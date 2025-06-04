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


def make_openssl_conf(config: Config, backend: bool = False) -> str:
    openssl_conf_type = 'be' if backend else 'fe'
    openssl_conf_path = os.path.join(config.get_tmp_dir(), f"openssl-{openssl_conf_type}.cnf")

    module_path = config.get_pkcs11_module_path()
    library_path = config.get_pkcs11_library_path(backend)

    openssl_conf_content = OPENSSL_TEMPLATE.format(
        module_path=module_path,
        library_path=library_path,
        default_pin=config.get_default_pin(),
        default_slot=config.get_default_slot(),
    )

    with open(openssl_conf_path, "w") as f:
        f.write(openssl_conf_content)

    return openssl_conf_path


def generate_openssl_conf(config: Config):
    """Generates the OpenSSL configuration file."""
    [fe_path, be_path] = [make_openssl_conf(config, False), make_openssl_conf(config, True)]
    config.save_openssl_config_paths(fe_path, be_path)

    print(f"✅ OpenSSL frontend config generated at {fe_path} and backend config generated at {be_path}")
    config.use_openssl_fe_config()
    config.set_env("LD_LIBRARY_PATH", os.path.join(config.get_openssl_dir(), "lib64"))
    config.set_openssl_provider_log()
