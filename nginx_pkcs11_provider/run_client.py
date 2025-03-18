import os
import subprocess
from nginx_pkcs11_provider.config import Config

def run_client_test(config: Config):
    """Perform a client-authenticated HTTPS request."""
    client_cert = config.get_client_cert_path()
    client_key = config.get_client_private_key_path()

    if not os.path.exists(client_cert) or not os.path.exists(client_key):
        print("❌ Client certificate or key missing! Run `python run.py init` first.")
        return

    server_url = "https://localhost:8443"

    print(f"🔍 Testing client authentication against {server_url}...")
    result = subprocess.run([
        "curl", "-k", "--cert", client_cert, "--key", client_key, server_url
    ], capture_output=True, text=True)

    print("📄 Response:")
    print(result.stdout)
