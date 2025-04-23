import subprocess
from nginx_pkcs11_provider.config import Config


def run_proxy(config: Config):
    """Runs pkcs11-proxy using the generated configuration."""
    env = config.load_envs(True)
    be_lib = config.get_pkcs11_library_path(True)
    executable = config.is_pkcs11_proxy_executable()
    print(f"🚀 Starting pkcs11-proxy daemon: {executable} {be_lib}")
    try:
        subprocess.run([executable, be_lib], env=env, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Nginx failed to start: {e}")