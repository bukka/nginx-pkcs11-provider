import os
from datetime import datetime, timedelta, timezone
from pkcs11 import lib, KeyType, Mechanism, Attribute
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.ec import encode_ec_public_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, load_der_private_key, load_der_public_key
from nginx_pkcs11_provider.config import Config


def extract_public_key(pkcs11_pub_key):
    """Extract a public key from PKCS#11 and convert it to `pyca/cryptography` format."""
    if pkcs11_pub_key.key_type == KeyType.RSA:
        pub_der = encode_rsa_public_key(pkcs11_pub_key)
    elif pkcs11_pub_key.key_type == KeyType.EC:
        pub_der = encode_ec_public_key(pkcs11_pub_key)
    else:
        raise ValueError("Unsupported key type for certificate generation")

    return load_der_public_key(pub_der)


def export_private_key(pkcs11_priv_key):
    """Export the private key from PKCS#11 to a format usable by `pyca/cryptography`."""
    priv_der = pkcs11_priv_key[Attribute.VALUE]
    return load_der_private_key(priv_der, password=None)


def generate_self_signed_cert(priv_key, pub_key, subject_name):
    """Generate a self-signed certificate using the exported private key."""
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
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(priv_key, hashes.SHA256())  # Now signing with an exported key
    )

    return cert.public_bytes(Encoding.PEM)


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

        # Generate RSA or EC key pair with EXPORTABLE attributes
        key_attrs = {
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False  # Allow exporting private key
        }

        if key_type == "EC":
            pub, priv = session.generate_keypair(
                KeyType.EC, 256, store=True, label=token.main_server_key,
                capabilities={"sign": True, "derive": True},
                attributes=key_attrs
            )
        else:
            pub, priv = session.generate_keypair(
                KeyType.RSA, 2048, store=True, label=token.main_server_key,
                capabilities={"sign": True, "decrypt": True},
                attributes=key_attrs
            )

        print(f"✅ {key_type} key pair created for {token.name}")

        # Extract public key from PKCS#11
        pyca_pub_key = extract_public_key(pub)

        # Export private key from PKCS#11
        pyca_priv_key = export_private_key(priv)

        # Generate a self-signed certificate
        cert_pem = generate_self_signed_cert(pyca_priv_key, pyca_pub_key, token.name)

        cert_file = os.path.join(tmp_dir, f"{token.main_server_cert}.crt")
        with open(cert_file, "wb") as f:
            f.write(cert_pem)

        print(f"✅ Self-signed certificate generated: {cert_file}")


if __name__ == "__main__":
    config = Config("config.yml")
    generate_keys(config)
