import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from nginx_pkcs11_provider.config import Config


def run_client_test(config: Config, repeat: int = 1, parallel: bool = True):
    """Perform a client-authenticated HTTPS request."""
    cert_args = []
    if config.is_nginx_client_cert_enabled() and not config.is_nginx_client_cert_with_pkcs11_key():
        client_cert = config.get_client_cert_path()
        client_key = config.get_client_private_key_path()
        if not os.path.exists(client_cert) or not os.path.exists(client_key):
            print("❌ Client certificate or key missing! Run `python run.py init` first.")
            return
        cert_args = ["--cert", client_cert, "--key", client_key]


    config.load_envs(True)
    config.use_openssl_be_config()
    envs = config.get_envs()
    executable = config.get_curl_executable()

    def do_request(token):
        if config.is_nginx_client_cert_enabled() and config.is_nginx_client_cert_with_pkcs11_key():
            curl_cert_args = [
                "--cert", config.get_cert_path(token.main_client_cert),
                "--key", config.get_key_path(token.main_client_key)
            ]
        else:
            curl_cert_args = cert_args
        server_url = f"https://localhost:{token.port}/"
        cmd = [executable, "-k", *curl_cert_args, server_url]
        print(f"🔍 Testing client request: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, env=envs)
        return token.name, result.stdout.strip()

    for i in range(repeat):
        print(f"\n🔁 Running client test iteration {i + 1}/{repeat}")

        if parallel:
            with ThreadPoolExecutor() as executor:
                futures = {executor.submit(do_request, token): token for token in config.get_tokens()}
                for future in as_completed(futures):
                    token_name, output = future.result()
                    print(f"📄 Response from token '{token_name}':\n{output}")
        else:
            for token in config.get_tokens():
                token_name, output = do_request(token)
                print(f"📄 Response from token '{token_name}':\n{output}")
