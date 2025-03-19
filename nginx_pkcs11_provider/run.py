import argparse
import os
import shutil

from nginx_pkcs11_provider.config import Config
from nginx_pkcs11_provider.setup_pkcs11_proxy import setup_pkcs11_proxy
from nginx_pkcs11_provider.setup_softhsm import setup_softhsm
from nginx_pkcs11_provider.generate_openssl_conf import generate_openssl_conf
from nginx_pkcs11_provider.generate_keys import generate_keys
from nginx_pkcs11_provider.generate_nginx import generate_nginx_config
from nginx_pkcs11_provider.generate_client_cert import generate_client_cert
from nginx_pkcs11_provider.run_nginx import run_nginx
from nginx_pkcs11_provider.run_client import run_client_test

def init_tmp(config: Config):
    if config.is_fresh():
        shutil.rmtree(config.get_tmp_dir())
    os.makedirs(config.get_tmp_dir(), exist_ok=True)

def init(config: Config):
    """Initializes everything: SoftHSM tokens, OpenSSL config, keys, nginx config, and client certs."""
    print("🔹 Initializing PKCS#11 environment...")
    init_tmp(config)
    generate_openssl_conf(config)
    setup_softhsm(config)
    setup_pkcs11_proxy(config)
    generate_keys(config)
    generate_nginx_config(config)
    generate_client_cert(config)
    print("✅ Initialization complete! Use `python run.py run <target>` to start.")

def run(target: str, config: Config):
    """Runs the specified target."""
    if target == "nginx":
        print("🚀 Starting nginx with PKCS#11 integration...")
        run_nginx(config)
    elif target == "client":
        print("🚀 Running client test against PKCS#11 server...")
        run_client_test(config)
    else:
        print(f"❌ Unknown run target: {target}. Use 'nginx' or 'client'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PKCS#11-based Nginx provider test project")
    parser.add_argument("--config", type=str, default="config.yml", help="Path to configuration file")

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Initialize SoftHSM tokens, keys, nginx config, and client certs")
    parser_run = subparsers.add_parser("run", help="Run a specific component")
    parser_run.add_argument("target", choices=["nginx", "client"], help="Specify what to run")

    args = parser.parse_args()

    config = Config(args.config)

    if args.command == "init":
        init(config)
    elif args.command == "run":
        run(args.target, config)
    else:
        parser.print_help()