import subprocess
import os
from nginx_pkcs11_provider.config import Config

SOFTHSM2_TEMPLATE = """# SoftHSM v2 configuration file

directories.tokendir = {token_dir}
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = WARNING

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false
"""

def setup_softhsm(config: Config):
    """Initialize SoftHSM tokens with unique PINs."""
    so_pin = config.get("softhsm.so_pin", '1234')
    token_dir = config.get("softhsm.token_dir")
    num_tokens = config.get_tokens_num()
    tokens = config.get_tokens()

    os.makedirs(token_dir, exist_ok=True)

    softhsm2_conf_content = SOFTHSM2_TEMPLATE.format(
        token_dir=token_dir,
    )
    softhsm2_conf_path = os.path.join(token_dir, "softhsm2.conf")
    with open(softhsm2_conf_path, "w") as f:
        f.write(softhsm2_conf_content)
    config.set_env("SOFTHSM2_CONF", softhsm2_conf_path)

    for token in tokens:
        slot_id = token.index - 1 # needs to start from 0

        subprocess.run([
            "softhsm2-util", "--init-token",
            "--slot", slot_id, "--label", token.name,
            "--pin", token.pin, "--so-pin", so_pin
        ], check=True)

    print(f"✅ SoftHSM initialized with {num_tokens} tokens.")
