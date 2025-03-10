import yaml
import os
import random

class Token:
    """Represents a PKCS#11 token with a name and PIN."""
    def __init__(self, index: int, name: str, pin: str):
        self.index = index
        self.name = name
        self.pin = pin
        self.main_server_key = f"server-key-{index}"
        self.main_server_cert = f"server-cert-{index}"


class Config:
    def __init__(self, config_path=None):
        self.config_path = config_path or "config.yml"
        self.config = self._load_config()
        self._init_tokens()
        self.custom_envs = {}
        self.cache = {}

    def _load_config(self):
        """Load the YAML configuration file."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        with open(self.config_path, "r") as f:
            return yaml.safe_load(f)

    def _init_tokens(self):
        """Generate and store unique tokens with PINs."""
        tokens_file = os.path.join(self.get_tmp_dir(), "tokens.yaml")

        self.tokens = []

        if os.path.exists(tokens_file):
            with open(tokens_file, "r") as f:
                token_data = yaml.safe_load(f)
                self.tokens = [Token(index=t["index"], name=t["name"], pin=t["pin"]) for t in token_data]
        else:
            num_tokens = self.get_tokens_num()
            token_prefix = self.get_tokens_prefix()
            self.tokens = [
                Token(index=i, name=f"{token_prefix}{i}", pin=str(random.randint(1000, 9999)))
                for i in range(1, num_tokens + 1)
            ]

            os.makedirs(os.path.dirname(tokens_file), exist_ok=True)
            with open(tokens_file, "w") as f:
                yaml.dump([{"name": t.name, "pin": t.pin} for t in self.tokens], f)

    def get(self, key, default=None):
        """Helper function to retrieve a config value using dot notation."""
        if key in self.cache:
            return self.cache[key]
        keys = key.split(".")
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                value = default
                break
        if value is None:
            raise ValueError(f"Config value not found: {key}")
        self.cache[key] = value
        return value

    def get_key_type(self, default: str = "EC"):
        """Get key type"""
        return self.get("keys.type", default).upper()

    def get_tokens_num(self, default=1):
        """Returns the number of tokens to be generated."""
        return self.get("pkcs11.tokens.num", default)

    def get_tokens_prefix(self, default="Token"):
        """Returns the name prefix of tokens to be generated."""
        return self.get("pkcs11.tokens.prefix", default)

    def get_tokens(self):
        """Returns all generated tokens as objects."""
        return self.tokens

    def get_tmp_dir(self):
        """Returns the temporary directory for storing PEM files."""
        return self.get("tmp_dir")

    def get_default_pin(self):
        """Returns the first generated token's PIN as the default one."""
        if not self.tokens:
            raise ValueError("No tokens available")
        return self.tokens[0].pin

    def get_openssl_dir(self):
        """Returns the OpenSSL directory."""
        return self.get("openssl_dir")

    def get_pkcs11_module_path(self):
        """Determine the correct path for pkcs11.so."""
        custom_path = self.get("pkcs11.module")
        if custom_path:
            return custom_path

        openssl_dir = self.get_openssl_dir()
        if openssl_dir:
            module_path = os.path.join(openssl_dir, "ossl-modules", "pkcs11.so")
            if os.path.exists(module_path):
                return module_path
            else:
                raise ValueError(f"openssl module path {module_path} does not exist")
        raise ValueError("module path does not exist")

    def get_pkcs11_library_path(self, backend: bool = False):
        """Determine the correct path for the PKCS#11 library."""
        if not backend and  self.is_pkcs11_proxy_enabled():
            return self.get("pkcs11.proxy.lib")
        else:
            return self.get("pkcs11.softhsm.lib")

    def is_pkcs11_proxy_enabled(self):
        return self.get("pkcs11.proxy.enabled", False)

    def is_nginx_client_cert_enabled(self):
        return self.get("nginx.client_cert.enabled", False)

    def set_env(self, name: str, value: str):
        """Set an environment variable."""
        print(f"export {name}='{value}'")
        self.custom_envs[name] = value
        os.environ[name] = value
