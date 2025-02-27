import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
from nginx_pkcs11_provider.config import Config

def generate_client_cert(config: Config):
    """Generate a normal file-based client certificate (self-signed)."""
    # Skip if the client cert is not used.
    if not config.is_nginx_client_cert_enabled():
        return

    tmp_dir = config.get_tmp_dir()
    os.makedirs(tmp_dir, exist_ok=True)

    key_type = config.get_key_type()

    if key_type == "EC":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKCS11 Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "client-cert"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    private_key_path = os.path.join(tmp_dir, "client-key.pem")
    cert_path = os.path.join(tmp_dir, "client-cert.pem")

    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"✅ Client certificate and key generated: {cert_path}, {private_key_path}")
