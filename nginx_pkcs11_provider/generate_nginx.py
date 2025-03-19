import os
from nginx_pkcs11_provider.config import Config

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
    ssl_engine pkcs11;
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
    port_start = config.get("nginx.ports.start", 8443)
    ssl_protocol = config.get("nginx.ssl.protocol", "TLSv1.2 TLSv1.3")
    ssl_ciphers = config.get("nginx.ssl.ciphers", "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256")
    ssl_ecdh_curves = config.get("nginx.ssl.ecdh_curver", "prime256v1:secp384r1:brainpoolP256r1:brainpoolP384r1:brainpoolP512r1")
    ssl_prefer_server_ciphers = config.get("nginx.ssl.prefer_server_ciphers", "on")
    enable_client_cert = config.is_nginx_client_cert_enabled()

    servers_config = "\n".join([
        SERVER_TEMPLATE.format(
            index=token.index,
            port=port_start + token.index - 1,
            server_cert=os.path.join(tmp_dir, f"{token.main_server_cert}.crt"),
            server_key=os.path.join(tmp_dir, f"{token.main_server_key}.pem"),
            ssl_protocol=ssl_protocol,
            ssl_ciphers=ssl_ciphers,
            ssl_ecdh_curves=ssl_ecdh_curves,
            ssl_prefer_server_ciphers=ssl_prefer_server_ciphers,
            client_cert_config=CLIENT_CERT_CONFIG.format(
                client_cert=config.get_client_cert_path()
            ) if enable_client_cert else ""
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
