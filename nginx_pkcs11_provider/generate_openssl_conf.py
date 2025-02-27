import os
from nginx_pkcs11_provider.config import Config

OPENSSL_TEMPLATE = """openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = {provider_path}
pkcs11-module-path = {module_path}
pkcs11-module-token-pin = {default_pin}
activate = 1
"""

def generate_openssl_conf(config: Config):
    """Generates the OpenSSL configuration file."""
    tmp_dir = config.get_tmp_dir()
    openssl_conf_path = os.path.join(tmp_dir, "openssl.cnf")

    provider_path = config.get_pkcs11_library_path()
    module_path = config.get_pkcs11_module_path()

    openssl_conf_content = OPENSSL_TEMPLATE.format(
        provider_path=provider_path,
        module_path=module_path,
        default_pin=config.get_default_pin(),
    )

    os.makedirs(tmp_dir, exist_ok=True)
    with open(openssl_conf_path, "w") as f:
        f.write(openssl_conf_content)

    print(f"✅ OpenSSL config generated at {openssl_conf_path}")
    config.set_env("OPENSSL_CONF", openssl_conf_path)
    config.set_env("LD_LIBRARY_PATH", os.path.join(config.get_openssl_dir(), "lib64"))
