import os
from nginx_pkcs11_provider.config import Config, Token

NGINX_TEMPLATE = """# Nginx configuration file
pid {pid_file};
daemon off;

env SOFTHSM2_CONF;
env OPENSSL_CONF;
env PKCS11_PROXY_SOCKET;

events {{
    worker_connections 1024;
}}

http {{
    error_log /dev/stderr debug;
    access_log /dev/stdout;

    client_body_temp_path {client_body_temp_path};
    proxy_temp_path {proxy_temp_path};

    {servers}
}}
"""

SERVER_TEMPLATE = """
server {{
    listen {port} ssl;
    ssl_certificate "{server_cert}";
    ssl_certificate_key "{server_key}";
    ssl_protocols {ssl_protocol};
    ssl_ciphers {ssl_ciphers};
    ssl_ecdh_curve {ssl_ecdh_curves};
    ssl_prefer_server_ciphers {ssl_prefer_server_ciphers};

    {client_cert_config}

    location / {{
        return 200 "PKCS11 test server {index} on port {port}\\n";
    }}
}}
"""

CLIENT_CERT_CONFIG = """
    ssl_client_certificate "{client_cert}";
    ssl_verify_client optional;
"""


def generate_nginx_config(config: Config):
    """Generates the Nginx configuration file based on the config settings."""
    tmp_dir = config.get_tmp_dir()
    tokens = config.get_tokens()
    pid_file = os.path.join(tmp_dir, "nginx.pid")
    client_body_temp_path = os.path.join(tmp_dir, "client_body_temp")
    proxy_temp_path = os.path.join(tmp_dir, "proxy_temp_path")
    ssl_protocol = config.get_nginx_ssl_protocol()
    ssl_ciphers = config.get_nginx_ssl_ciphers()
    ssl_ecdh_curves = config.get_nginx_ssl_ecdh_curves()
    ssl_prefer_server_ciphers = config.get_nginx_ssl_prefer_server_ciphers()

    def get_client_cert_config(token: Token):
        if not config.is_nginx_client_cert_enabled():
            return ""
        if config.is_nginx_client_cert_with_pkcs11_key():
            if config.is_nginx_client_cert_same_as_server_cert():
                client_cert_name = token.main_server_cert
            else:
                client_cert_name = token.main_client_cert
            client_cert = config.get_cert_path(client_cert_name)
        else:
            client_cert = config.get_client_cert_path()
        return CLIENT_CERT_CONFIG.format(client_cert=client_cert)

    servers_config = "\n".join([
        SERVER_TEMPLATE.format(
            index=token.index,
            port=token.port,
            server_cert=config.get_cert_path(token.main_server_cert),
            server_key=config.get_key_path(token.main_server_key),
            ssl_protocol=ssl_protocol,
            ssl_ciphers=ssl_ciphers,
            ssl_ecdh_curves=ssl_ecdh_curves,
            ssl_prefer_server_ciphers=ssl_prefer_server_ciphers,
            client_cert_config=get_client_cert_config(token)
        )
        for token in tokens
    ])

    nginx_config = NGINX_TEMPLATE.format(
        pid_file=pid_file,
        servers=servers_config,
        client_body_temp_path=client_body_temp_path,
        proxy_temp_path=proxy_temp_path,
    )

    nginx_conf_path = os.path.join(tmp_dir, "nginx.conf")
    with open(nginx_conf_path, "w") as f:
        f.write(nginx_config)

    print(f"✅ Nginx config generated at {nginx_conf_path}")
