import subprocess
import os
from nginx_pkcs11_provider.config import Config

SOFTHSM2_TEMPLATE = """# SoftHSM v2 configuration file

directories.tokendir = {token_dir}
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = {log_level}

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false
"""

def setup_softhsm(config: Config):
    """Initialize SoftHSM tokens with unique PINs."""
    tmp_dir = config.get_tmp_dir()
    token_dir = config.get("pkcs11.softhsm.token_dir", os.path.join(tmp_dir, "tokendir"))
    log_level = config.get("pkcs11.softhsm.log.level", "WARNING")
    so_pin = config.get("pkcs11.softhsm.so_pin", '1234')
    library_path = config.get_pkcs11_library_path(True)
    num_tokens = config.get_tokens_num()
    tokens = config.get_tokens()

    os.makedirs(token_dir, exist_ok=True)

    softhsm2_conf_content = SOFTHSM2_TEMPLATE.format(
        token_dir=token_dir,
        log_level=log_level,
    )
    softhsm2_conf_path = os.path.join(tmp_dir, "softhsm2.conf")
    with open(softhsm2_conf_path, "w") as f:
        f.write(softhsm2_conf_content)
    config.set_env("SOFTHSM2_CONF", softhsm2_conf_path)

    for token in tokens:
        slot_id = token.index - 1 # needs to start from 0

        subprocess.run([
            "softhsm2-util", "--init-token",
            "--module", library_path,
            "--slot", slot_id, "--label", token.name,
            "--pin", token.pin, "--so-pin", so_pin
        ], check=True)

    print(f"✅ SoftHSM initialized with {num_tokens} tokens.")
