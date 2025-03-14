import os
import time
import hashlib
from datetime import datetime, timedelta
from pkcs11 import lib, KeyType, Mechanism
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.ec import encode_ec_public_key, decode_ecdsa_signature
from asn1crypto.x509 import Certificate, TbsCertificate, SignedDigestAlgorithm
from asn1crypto.algos import DigestAlgorithm, SignedDigestAlgorithm
from asn1crypto.core import Integer, OctetBitString, Sequence
from asn1crypto.keys import PublicKeyInfo
from asn1crypto import pem
from nginx_pkcs11_provider.config import Config

def generate_tbs_certificate(subject_name, public_key_info):
    """Create an X.509 TBS (To-Be-Signed) certificate structure."""
    tbs = TbsCertificate({
        "version": 2,  # v3 certificate
        "serial_number": int(time.time()),  # Unique serial number
        "signature": SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        "issuer": {"common_name": "PKCS11 Test CA"},
        "validity": {
            "not_before": datetime.utcnow(),
            "not_after": datetime.utcnow() + timedelta(days=365),
        },
        "subject": {"common_name": subject_name},
        "subject_public_key_info": public_key_info,
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
    if key_type == KeyType.RSA:
        mechanism = Mechanism.SHA256_RSA_PKCS
        return private_key.sign(tbs_data, mechanism=mechanism)
    elif key_type == KeyType.EC:
        mechanism = Mechanism.ECDSA
        tbs_hash = hashlib.sha256(tbs_data).digest()
        raw_signature = private_key.sign(tbs_hash, mechanism=mechanism)
        return encode_ecdsa_signature(raw_signature)
    else:
        raise ValueError("Unsupported key type for signing")


def encode_ecdsa_signature(signature):
    """Convert raw PKCS#11 ECDSA signature to ASN.1 DER format."""
    r, s = decode_ecdsa_signature(signature)
    return Sequence([Integer(r), Integer(s)]).dump()


def generate_signed_certificate(session, priv_key, pub_key, subject_name, key_type):
    """Generate a self-signed X.509 certificate using PKCS#11 signing."""
    # Create the TBS certificate
    public_key_info = extract_public_key(pub_key)
    tbs_cert = generate_tbs_certificate(subject_name, public_key_info)

    # Get the DER-encoded TBS certificate (to be signed)
    tbs_der = tbs_cert.dump()

    # Sign the TBS data with PKCS#11
    signature = sign_with_pkcs11(session, priv_key, tbs_der, key_type)

    # Set the correct signature algorithm
    if key_type == KeyType.RSA:
        signature_algorithm = "sha256_rsa"
    elif key_type == KeyType.EC:
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

def generate_keys(config: Config):
    """Generate RSA or EC keys for each SoftHSM token and store a self-signed certificate."""
    tokens = config.get_tokens()
    tmp_dir = config.get_tmp_dir()
    key_type = config.get_key_type()
    lib_path = config.get_pkcs11_library_path()

    pkcs11 = lib(lib_path)

    for token in tokens:
        print(f"🔹 Generating {key_type} key pair for {token.name}...")

        pkcs11_token = pkcs11.get_token(token_label=token.name)
        session = pkcs11_token.open(rw=True, user_pin=token.pin)

        # Generate RSA or EC key pair
        if key_type == "EC":
            pub, priv = session.generate_keypair(
                KeyType.EC, 256, store=True, label=token.main_server_key,
                capabilities={"sign": True, "derive": True}
            )
        else:
            pub, priv = session.generate_keypair(
                KeyType.RSA, 2048, store=True, label=token.main_server_key,
                capabilities={"sign": True, "decrypt": True}
            )

        print(f"✅ {key_type} key pair created for {token.name}")

        # Generate a self-signed certificate
        cert_der = generate_signed_certificate(session, priv, pub, token.name, key_type)

        # Save the certificate as a PEM file
        cert_pem = pem.armor("CERTIFICATE", cert_der)
        cert_file = os.path.join(tmp_dir, f"{token.main_server_cert}.crt")
        with open(cert_file, "wb") as f:
            f.write(cert_pem)

        print(f"✅ Self-signed certificate generated: {cert_file}")
