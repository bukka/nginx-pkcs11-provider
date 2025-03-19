import os
import secrets

from nginx_pkcs11_provider.config import Config

def setup_pkcs11_proxy(config: Config):
    """Initialize pkcs11-proxy."""
    if not config.is_pkcs11_proxy_enabled():
        return

    if config.get('pkcs11.proxy.tls.enabled', False):
        schema = 'tls'
        tmp_dir = config.get_tmp_dir()
        psk_file = os.path.join(tmp_dir, "pkcs11_proxy_psk")
        # Create the PSK file if it does not exist
        if not os.path.isfile(psk_file):
            with open(psk_file, "w") as f:
                psk = secrets.token_hex(32)
                f.write(f"client:{psk}\n")
        config.set_env('PKCS11_PROXY_TLS_PSK_FILE', psk_file)
    else:
        schema = 'tcp'

    proxy_port = config.get('pkcs11.proxy.port')
    proxy_socket = f'{schema}://localhost:{proxy_port}'
    config.set_env('PKCS11_PROXY_SOCKET', proxy_socket)
    config.set_env('PKCS11_DAEMON_SOCKET', proxy_socket)
