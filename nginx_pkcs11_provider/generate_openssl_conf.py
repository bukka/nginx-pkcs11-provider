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
module = {module_path}
pkcs11-module-path = {library_path}
pkcs11-module-token-pin = {default_pin}
pkcs11-module-default-slot-id = {default_slot}
activate = 1
"""

def generate_openssl_conf(config: Config):
    """Generates the OpenSSL configuration file."""
    openssl_conf_path = os.path.join(config.get_tmp_dir(), "openssl.cnf")

    module_path = config.get_pkcs11_module_path()
    library_path = config.get_pkcs11_library_path()

    openssl_conf_content = OPENSSL_TEMPLATE.format(
        module_path=module_path,
        library_path=library_path,
        default_pin=config.get_default_pin(),
        default_slot=config.get_default_slot(),
    )

    with open(openssl_conf_path, "w") as f:
        f.write(openssl_conf_content)

    print(f"✅ OpenSSL config generated at {openssl_conf_path}")
    config.set_env("OPENSSL_CONF", openssl_conf_path)
    config.set_env("LD_LIBRARY_PATH", os.path.join(config.get_openssl_dir(), "lib64"))

    if config.get('pkcs11.provider.log', True):
        provider_log = os.path.join(config.get_tmp_dir(), 'pkcs11-provider.log')
        config.set_env('PKCS11_PROVIDER_DEBUG ', f'file:{provider_log},level:6')
