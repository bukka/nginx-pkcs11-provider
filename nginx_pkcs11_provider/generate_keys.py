import os
from datetime import datetime, timedelta
from pkcs11 import lib, KeyType, Mechanism
from asn1crypto.core import Sequence, VisibleString, UTF8String
from asn1crypto import pem
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from nginx_pkcs11_provider.config import Config


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


def generate_self_signed_cert(session, priv_key, pub_key, subject_name):
    """Generate a self-signed certificate using PKCS#11 private key."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKCS11 Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    # TODO: change this to sign it correctly with pkcs11 key
    cert = cert.sign(private_key=priv_key, algorithm=hashes.SHA256())

    return cert.public_bytes(Encoding.PEM)


def generate_keys(config: Config):
    """Generate RSA or EC keys for each SoftHSM token and store a self-signed certificate."""
    tokens = config.get_tokens()
    tmp_dir = config.get_tmp_dir()
    key_type = config.get("key_type", "RSA").upper()
    lib_path = config.get_pkcs11_library_path()

    pkcs11 = lib(lib_path)
    os.makedirs(tmp_dir, exist_ok=True)

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

        # Generate PEM key representation
        uri = f"pkcs11:token={token.name};object={token.main_server_key};type=private?pin-value={token.pin}"
        pem_data = uri2pem(uri)

        pem_file = os.path.join(tmp_dir, f"{token.main_server_key}.pem")
        with open(pem_file, "wb") as f:
            f.write(pem_data)

        print(f"✅ PEM file generated: {pem_file}")

        # Generate a self-signed certificate
        cert_pem = generate_self_signed_cert(session, priv, pub, token.name)

        cert_file = os.path.join(tmp_dir, f"{token.main_server_cert}.crt")
        with open(cert_file, "wb") as f:
            f.write(cert_pem)

        print(f"✅ Self-signed certificate generated: {cert_file}")
