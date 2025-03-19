import os
import subprocess
from nginx_pkcs11_provider.config import Config

def run_client_test(config: Config):
    """Perform a client-authenticated HTTPS request."""
    cert_args = []
    if config.is_nginx_client_cert_enabled():
        client_cert = config.get_client_cert_path()
        client_key = config.get_client_private_key_path()
        if not os.path.exists(client_cert) or not os.path.exists(client_key):
            print("❌ Client certificate or key missing! Run `python run.py init` first.")
            return
        cert_args = ["--cert", client_cert, "--key", client_key]

    for token in config.get_tokens():
        server_url = f"https://localhost:{token.port}/"
        cmd = ["curl", "-k", *cert_args, server_url]
        print(f"🔍 Testing client request: " + " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print("📄 Response:")
        print(result.stdout)
