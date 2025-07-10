import os
import math
from nginx_pkcs11_provider.config import Config, Token

NGINX_TEMPLATE = """# Nginx configuration file (Instance {instance_id})
pid {pid_file};
daemon off;
error_log /dev/stderr debug;

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
    fastcgi_temp_path {fastcgi_temp_path};
    uwsgi_temp_path {uwsgi_temp_path};
    scgi_temp_path {scgi_temp_path};

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
        return 200 "PKCS11 test server {index} on port {port} (Instance {instance_id})\\n";
    }}
}}
"""

CLIENT_CERT_CONFIG = """
    ssl_client_certificate "{client_cert}";
    ssl_verify_client optional;
"""


def split_tokens_evenly(tokens, num_instances):
    """Split tokens into chunks as evenly as possible across instances."""
    if num_instances <= 0:
        raise ValueError("Number of instances must be greater than 0")

    if num_instances > len(tokens):
        raise ValueError(f"Cannot create {num_instances} instances with only {len(tokens)} tokens. "
                         f"Reduce instances_count or add more tokens.")

    if num_instances == len(tokens):
        # One token per instance
        return [[token] for token in tokens]

    # Calculate base chunk size and remainder
    chunk_size = len(tokens) // num_instances
    remainder = len(tokens) % num_instances

    chunks = []
    start_idx = 0

    for i in range(num_instances):
        # Some chunks get an extra token if there's a remainder
        current_chunk_size = chunk_size + (1 if i < remainder else 0)
        end_idx = start_idx + current_chunk_size
        chunks.append(tokens[start_idx:end_idx])
        start_idx = end_idx

    return chunks


def generate_nginx_config(config: Config):
    """Generates the Nginx configuration files based on the config settings."""
    tmp_dir = config.get_tmp_dir()
    tokens = config.get_tokens()
    instances_count = config.get_nginx_instances_count()
    ssl_protocol = config.get_nginx_ssl_protocol()
    ssl_ciphers = config.get_nginx_ssl_ciphers()
    ssl_ecdh_curves = config.get_nginx_ssl_ecdh_curves()
    ssl_prefer_server_ciphers = config.get_nginx_ssl_prefer_server_ciphers()

    # Ensure temp directories exist
    temp_dirs = ['client_body_temp', 'proxy_temp_path', 'fastcgi_temp_path',
                 'uwsgi_temp', 'scgi_temp']
    for temp_dir in temp_dirs:
        os.makedirs(os.path.join(tmp_dir, temp_dir), exist_ok=True)

    def get_client_cert_config(token: Token, instance_id: int):
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

    # Split tokens across instances
    token_chunks = split_tokens_evenly(tokens, instances_count)

    generated_configs = []

    for instance_id, instance_tokens in enumerate(token_chunks, 1):
        # Skip empty instances
        if not instance_tokens:
            print(f"⚠️  Instance {instance_id} has no tokens, skipping...")
            continue

        # Create instance-specific paths
        pid_file = os.path.join(tmp_dir, f"nginx_{instance_id}.pid")
        client_body_temp_path = os.path.join(tmp_dir, f"client_body_temp_{instance_id}")
        proxy_temp_path = os.path.join(tmp_dir, f"proxy_temp_path_{instance_id}")
        fastcgi_temp_path = os.path.join(tmp_dir, f"fastcgi_temp_path_{instance_id}")
        uwsgi_temp_path = os.path.join(tmp_dir, f"uwsgi_temp_{instance_id}")
        scgi_temp_path = os.path.join(tmp_dir, f"scgi_temp_{instance_id}")

        # Create instance-specific temp directories
        for temp_path in [client_body_temp_path, proxy_temp_path, fastcgi_temp_path,
                          uwsgi_temp_path, scgi_temp_path]:
            os.makedirs(temp_path, exist_ok=True)

        # Generate server configs for this instance
        servers_config = "\n".join([
            SERVER_TEMPLATE.format(
                instance_id=instance_id,
                index=token.index,
                port=token.port,
                server_cert=config.get_cert_path(token.main_server_cert),
                server_key=config.get_key_path(token.main_server_key),
                ssl_protocol=ssl_protocol,
                ssl_ciphers=ssl_ciphers,
                ssl_ecdh_curves=ssl_ecdh_curves,
                ssl_prefer_server_ciphers=ssl_prefer_server_ciphers,
                client_cert_config=get_client_cert_config(token, instance_id)
            )
            for token in instance_tokens
        ])

        # Generate the complete nginx config for this instance
        nginx_config = NGINX_TEMPLATE.format(
            instance_id=instance_id,
            pid_file=pid_file,
            servers=servers_config,
            client_body_temp_path=client_body_temp_path,
            proxy_temp_path=proxy_temp_path,
            fastcgi_temp_path=fastcgi_temp_path,
            uwsgi_temp_path=uwsgi_temp_path,
            scgi_temp_path=scgi_temp_path,
        )

        # Write the config file
        nginx_conf_path = os.path.join(tmp_dir, f"nginx_{instance_id}.conf")
        with open(nginx_conf_path, "w") as f:
            f.write(nginx_config)

        generated_configs.append(nginx_conf_path)

        # Print summary for this instance
        token_ports = [str(token.port) for token in instance_tokens]
        print(f"✅ Nginx config {instance_id} generated at {nginx_conf_path}")
        print(f"   └─ {len(instance_tokens)} tokens on ports: {', '.join(token_ports)}")

    print(f"\n📊 Summary: Generated {len(generated_configs)} nginx configurations")
    return generated_configs
