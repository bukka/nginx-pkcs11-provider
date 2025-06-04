import os
import subprocess
from nginx_pkcs11_provider.config import Config


def run_nginx(config: Config):
    """Runs Nginx using the generated configuration."""
    tmp_dir = config.get_tmp_dir()
    nginx_conf_path = os.path.join(tmp_dir, "nginx.conf")

    if not os.path.exists(nginx_conf_path):
        print("❌ Nginx configuration not found! Run `python run.py init` first.")
        return

    config.load_envs(True)
    config.set_openssl_provider_log('nginx')
    envs = config.get_envs()
    executable = config.get_nginx_executable()
    print(f"🚀 Starting Nginx: {executable} -c {nginx_conf_path}")
    try:
        subprocess.run([executable, "-c", nginx_conf_path], env=envs, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Nginx failed to start: {e}")
