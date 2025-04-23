import subprocess
from nginx_pkcs11_provider.config import Config


def run_proxy(config: Config):
    """Runs pkcs11-proxy using the generated configuration."""
    env = config.load_envs(True)
    be_lib = config.get_pkcs11_library_path(True)
    print(f"🚀 Starting pkcs11-proxy: pkcs11-proxy {be_lib}")
    try:
        subprocess.run(["pkcs11-daemon", be_lib], env=env, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Nginx failed to start: {e}")