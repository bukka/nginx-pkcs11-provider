import os
import subprocess
from nginx_pkcs11_provider.config import Config


def run_nginx(config: Config):
    """Runs Nginx using the generated configuration."""
    tmp_dir = config.get("nginx.tmp_dir")
    nginx_conf_path = os.path.join(tmp_dir, "nginx.conf")

    if not os.path.exists(nginx_conf_path):
        print("❌ Nginx configuration not found! Run `python run.py init` first.")
        return

    print(f"🚀 Starting Nginx with config: {nginx_conf_path}")

    try:
        subprocess.run(["nginx", "-c", nginx_conf_path, "-g", "daemon off;"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Nginx failed to start: {e}")
