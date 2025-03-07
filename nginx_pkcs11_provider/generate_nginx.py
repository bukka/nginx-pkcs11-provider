import os
from nginx_pkcs11_provider.config import Config

NGINX_TEMPLATE = """worker_processes auto;
events {{
    worker_connections 1024;
}}

http {{
    include mime.types;
    {servers}
}}
"""

SERVER_TEMPLATE = """
server {{
    listen {port} ssl;
    ssl_engine pkcs11;
    ssl_certificate "{server_cert}";
    ssl_certificate_key "{server_key}";

    {client_cert_config}

    location / {{
        return 200 "PKCS11 test server {index} on port {port}\\n";
    }}
}}
"""

CLIENT_CERT_CONFIG = """
    ssl_client_certificate "{client_cert}";
    ssl_verify_client on;
"""


def generate_nginx_config(config: Config):
    """Generates the Nginx configuration file based on the config settings."""
    tmp_dir = config.get_tmp_dir()
    tokens = config.get_tokens()
    port_start = config.get("nginx.ports.start", 8443)
    enable_client_cert = config.is_nginx_client_cert_enabled()

    servers_config = "\n".join([
        SERVER_TEMPLATE.format(
            index=token.index,
            port=port_start + token.index - 1,
            server_cert=os.path.join(tmp_dir, f"{token.main_server_cert}.crt"),
            server_key=os.path.join(tmp_dir, f"{token.main_server_key}.pem"),
            client_cert_config=CLIENT_CERT_CONFIG.format(
                client_cert=os.path.join(tmp_dir, "client-cert.pem")
            ) if enable_client_cert else ""
        )
        for token in tokens
    ])

    nginx_config = NGINX_TEMPLATE.format(servers=servers_config)

    nginx_conf_path = os.path.join(tmp_dir, "nginx.conf")
    with open(nginx_conf_path, "w") as f:
        f.write(nginx_config)

    print(f"✅ Nginx config generated at {nginx_conf_path}")
