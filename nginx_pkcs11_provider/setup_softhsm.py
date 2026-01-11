import re
import subprocess
import os
from nginx_pkcs11_provider.config import Config, Token

SOFTHSM2_TEMPLATE = """# SoftHSM v2 configuration file

directories.tokendir = {token_dir}
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = {log_level}
log.file = {log_file}

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false
"""


def setup_softhsm(config: Config):
    """Initialize SoftHSM tokens with unique PINs."""
    if not config.is_fresh():
        return

    tmp_dir = config.get_tmp_dir()
    token_dir = config.get("pkcs11.softhsm.token_dir", os.path.join(tmp_dir, "tokendir"))
    log_level = config.get("pkcs11.softhsm.log.level", "WARNING")
    log_file = os.path.join(tmp_dir, 'softhsmv2.log')
    so_pin = config.get("pkcs11.softhsm.so_pin", '1234')
    library_path = config.get_pkcs11_library_path(True)
    num_tokens = config.get_tokens_num()
    tokens = config.get_tokens()
    os.makedirs(token_dir, exist_ok=True)

    softhsm2_conf_content = SOFTHSM2_TEMPLATE.format(
        token_dir=token_dir,
        log_level=log_level,
        log_file=log_file,
    )
    softhsm2_conf_path = os.path.join(tmp_dir, "softhsm2.conf")
    with open(softhsm2_conf_path, "w") as f:
        f.write(softhsm2_conf_content)
    config.set_env("SOFTHSM2_CONF", softhsm2_conf_path)

    def create_token(token: Token, slot_id: int, name: str) -> str:
        cmd = [
            "softhsm2-util", "--init-token",
            "--module", library_path,
            "--slot", str(slot_id), "--label", name,
            "--pin", token.pin, "--so-pin", so_pin
        ]
        print(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Extract the reassigned slot number
        match = re.search(r"reassigned to slot (\d+)", result.stdout)
        if match:
            reassigned_slot = match.group(1)
            print(f"✅ Token '{name}' reassigned to slot {reassigned_slot}")
            return reassigned_slot
        else:
            raise Exception(f"⚠️ Could not determine reassigned slot for token '{token.name}'")

    idx = 0
    for token in tokens:
        token.server_slot = create_token(token, idx, token.get_server_name())
        idx += 1
        if config.has_nginx_client_cert_token():
            token.client_slot = create_token(token, idx, token.get_client_name())
            idx += 1

    print(f"✅ SoftHSM initialized with {num_tokens} tokens.")
