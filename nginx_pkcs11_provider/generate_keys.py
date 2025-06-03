import os
import time
import hashlib
from datetime import datetime, timedelta, timezone

from pkcs11 import lib, KeyType, Mechanism, Attribute
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.ec import encode_ec_public_key, decode_ecdsa_signature, encode_named_curve_parameters
from asn1crypto.x509 import Certificate, TbsCertificate, Name, Time
from asn1crypto.algos import SignedDigestAlgorithm
from asn1crypto.core import Integer, OctetBitString, Sequence, VisibleString, UTF8String
from asn1crypto.keys import PublicKeyInfo, RSAPublicKey
from asn1crypto import pem
from nginx_pkcs11_provider.config import Config


def generate_tbs_certificate(subject_name, public_key_info, key_type):
    """Create an X.509 TBS (To-Be-Signed) certificate structure."""
    subject_pub_key_info = RSAPublicKey.load(public_key_info) if key_type == "RSA" else public_key_info
    tbs = TbsCertificate({
        "version": 2,  # v3 certificate
        "serial_number": int(time.time()),  # Unique serial number
        "signature": SignedDigestAlgorithm({"algorithm": "sha256_rsa" if key_type == "RSA" else "sha256_ecdsa"}),
        "issuer": Name.build({"common_name": "PKCS11 Test CA"}),
        "validity": {
            "not_before": Time({
                'utc_time': datetime.now(timezone.utc),
            }),
            "not_after": Time({
                'utc_time': datetime.now(timezone.utc) + timedelta(days=365),
            }),
        },
        "subject": Name.build({"common_name": subject_name}),
        "subject_public_key_info": subject_pub_key_info,
    })
    return tbs


def extract_public_key(pkcs11_pub_key):
    """Extract a public key from PKCS#11 and format it for X.509 certificates."""
    if pkcs11_pub_key.key_type == KeyType.RSA:
        pub_der = encode_rsa_public_key(pkcs11_pub_key)
    elif pkcs11_pub_key.key_type == KeyType.EC:
        pub_der = encode_ec_public_key(pkcs11_pub_key)
    else:
        raise ValueError("Unsupported key type for certificate generation")

    return PublicKeyInfo.load(pub_der)


def sign_with_pkcs11(session, private_key, tbs_data, key_type):
    """Sign the TBS certificate data using the PKCS#11 private key."""
    if key_type == "RSA":
        mechanism = Mechanism.SHA256_RSA_PKCS
        return private_key.sign(tbs_data, mechanism=mechanism)
    elif key_type == "EC":
        mechanism = Mechanism.ECDSA
        tbs_hash = hashlib.sha256(tbs_data).digest()
        return private_key.sign(tbs_hash, mechanism=mechanism)
    else:
        raise ValueError("Unsupported key type for signing")


def generate_signed_certificate(session, priv_key, pub_key, subject_name, key_type):
    """Generate a self-signed X.509 certificate using PKCS#11 signing."""
    # Create the TBS certificate
    public_key_info = extract_public_key(pub_key)
    tbs_cert = generate_tbs_certificate(subject_name, public_key_info, key_type)

    # Get the DER-encoded TBS certificate (to be signed)
    tbs_der = tbs_cert.dump()

    # Sign the TBS data with PKCS#11
    signature = sign_with_pkcs11(session, priv_key, tbs_der, key_type)

    # Set the correct signature algorithm
    if key_type == "RSA":
        signature_algorithm = "sha256_rsa"
    elif key_type == "EC":
        signature_algorithm = "sha256_ecdsa"
    else:
        raise ValueError("Unsupported key type")

    # Create the final certificate structure
    signed_cert = Certificate({
        "tbs_certificate": tbs_cert,
        "signature_algorithm": SignedDigestAlgorithm({"algorithm": signature_algorithm}),
        "signature_value": OctetBitString(signature),
    })

    return signed_cert.dump()


class Pkcs11PrivateKey(Sequence):
    _fields = [("desc", VisibleString), ("uri", UTF8String)]


def uri2pem(uri: str) -> bytes:
    """Convert a PKCS#11 URI to a PEM file."""
    data = Pkcs11PrivateKey(
        {
            "desc": VisibleString("PKCS#11 Provider URI v1.0"),
            "uri": UTF8String(uri),
        }
    )
    return pem.armor("PKCS#11 PROVIDER URI", data.dump())


def generate_key(config: Config, pkcs11, tmp_dir: str, key_type: str, token_type: str, token_name: str,
                 token_index: int, token_pin: str, token_server_key: str, token_server_cert: str):
    print(f"🔹 Generating {token_type} {key_type} key pair for {token_name}...")

    pkcs11_token = pkcs11.get_token(token_label=token_name)
    session = pkcs11_token.open(rw=True, user_pin=token_pin)

    # Generate RSA or EC key pair
    if key_type == "EC":
        parameters = session.create_domain_parameters(KeyType.EC, {
            Attribute.EC_PARAMS: encode_named_curve_parameters(config.get_curve_name())
        }, local=True)
        pub, priv = parameters.generate_keypair(id=token_index, store=True, label=token_server_key)
    else:
        pub, priv = session.generate_keypair(
            KeyType.RSA, 2048, id=token_index, store=True, label=token_server_key
        )

    print(f"✅ {key_type} key pair created for {token_name}")

    # Generate PEM key representation
    uri = f"pkcs11:token={token_name};object={token_server_key};type=private?pin-value={token_pin}"
    pem_data = uri2pem(uri)
    pem_file = config.get_key_path(token_server_key)
    with open(pem_file, "wb") as f:
        f.write(pem_data)
    print(f"✅ Private {key_type} key created: {pem_file}")

    # Generate a self-signed certificate
    cert_der = generate_signed_certificate(session, priv, pub, token_name, key_type)
    # Save the certificate as a PEM file
    cert_pem = pem.armor("CERTIFICATE", cert_der)
    cert_file = config.get_cert_path(token_server_cert)
    with open(cert_file, "wb") as f:
        f.write(cert_pem)
    print(f"✅ Self-signed certificate generated: {cert_file}")


def generate_keys(config: Config):
    """Generate RSA or EC keys for each SoftHSM token and store a self-signed certificate."""
    tokens = config.get_tokens()
    tmp_dir = config.get_tmp_dir()
    key_type = config.get_key_type()
    lib_path = config.get_pkcs11_library_path(True)

    pkcs11 = lib(lib_path)

    for token in tokens:
        generate_key(config, pkcs11, tmp_dir, key_type, "server", token.get_server_name(),
                     token.index, token.pin, token.main_server_key, token.main_server_cert)
        if config.is_nginx_client_cert_enabled() and config.is_nginx_client_cert_with_pkcs11_key():
            generate_key(config, pkcs11, tmp_dir, key_type, "client", token.get_client_name(),
                         token.index, token.pin, token.main_client_key, token.main_client_cert)
