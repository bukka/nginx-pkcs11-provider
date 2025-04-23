import json
import os
import random
import shutil
import yaml

class Token:
    """Represents a PKCS#11 token with a name and PIN."""

    index: int
    name: str
    pin: str
    port: int
    slot: str|None = None
    main_server_key: str
    main_server_cert: str

    def __init__(self, index: int, name: str, pin: str, port_start: int = 7000):
        self.index = index
        self.name = name
        self.pin = pin
        self.port = port_start + index - 1
        self.main_server_key = f"server-key-{index}"
        self.main_server_cert = f"server-cert-{index}"

class Config:
    cache: dict
    custom_envs: dict
    config_path: str
    config: dict
    tmp_dir: str|None = None

    def __init__(self, config_path=None, init_tmp: bool = False):
        self.custom_envs = {}
        self.cache = {}
        self.config_path = config_path or "config.yml"
        self.config = self._load_config()
        if init_tmp:
            self._init_tmp()
        self._init_tokens()

    def _init_tmp(self):
        if self.is_fresh():
            shutil.rmtree(self.get_tmp_dir())
        os.makedirs(self.get_tmp_dir(), exist_ok=True)

    def _load_config(self) -> dict:
        """Load the YAML configuration file."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        with open(self.config_path, "r") as f:
            return yaml.safe_load(f)

    def _init_tokens(self):
        """Generate and store unique tokens with PINs."""
        tokens_file = os.path.join(self.get_tmp_dir(), "tokens.yaml")

        self.tokens = []
        num_tokens = self.get_tokens_num()
        port_start = self.get_nginx_port_start()

        if os.path.exists(tokens_file):
            with open(tokens_file, "r") as f:
                token_data = yaml.safe_load(f)
            if len(token_data) == num_tokens:
                self.tokens = [
                    Token(
                        index=t["index"],
                        name=t["name"],
                        pin=t["pin"],
                        port_start=port_start,
                    )
                    for t in token_data
                ]
        if len(self.tokens) == 0:
            token_prefix = self.get_tokens_prefix()
            self.tokens = [
                Token(
                    index=i,
                    name=f"{token_prefix}{i}",
                    pin=str(random.randint(1000, 9999)),
                    port_start=port_start,
                )
                for i in range(1, num_tokens + 1)
            ]

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

    def get_curve_name(self, name: str = "secp256r1"):
        """Get key curve name (used just for EC type)"""
        return self.get("keys.curve_name", name)

    def get_tokens_num(self, default=1):
        """Returns the number of tokens to be generated."""
        return self.get("pkcs11.tokens.num", default)

    def get_tokens_prefix(self, default="Token"):
        """Returns the name prefix of tokens to be generated."""
        return self.get("pkcs11.tokens.prefix", default)

    def get_tokens(self) -> list[Token]:
        """Returns all generated tokens as objects."""
        return self.tokens

    def get_nginx_executable(self):
        """Return nginx port start."""
        return self.get("nginx.executable", "nginx")

    def get_nginx_port_start(self):
        """Return nginx port start."""
        return self.get("nginx.ports.start", 7000)

    def get_nginx_ssl_protocol(self):
        """Return the SSL protocol for Nginx."""
        return self.get("nginx.ssl.protocol", "TLSv1.2 TLSv1.3")

    def get_nginx_ssl_ciphers(self):
        """Return the SSL ciphers for Nginx."""
        return self.get(
            "nginx.ssl.ciphers",
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256"
        )

    def get_nginx_ssl_ecdh_curves(self):
        """Return the ECDH curves for Nginx."""
        return self.get(
            "nginx.ssl.ecdh_curves",
            "prime256v1:secp384r1:brainpoolP256r1:brainpoolP384r1:brainpoolP512r1"
        )

    def get_nginx_ssl_prefer_server_ciphers(self):
        """Return whether Nginx should prefer server ciphers."""
        return self.get("nginx.ssl.prefer_server_ciphers", "on")

    def get_tmp_dir(self):
        """Returns the temporary directory for storing PEM files."""
        if self.tmp_dir is None:
            tmp_dir = self.get("tmp_dir", 'tmp')
            self.tmp_dir = os.path.join(os.getcwd(), tmp_dir) if not os.path.isabs(tmp_dir) else tmp_dir
        return self.tmp_dir

    def get_client_cert_path(self):
        """Returns the path to the client certificate."""
        return os.path.join(self.get_tmp_dir(), "client-cert.pem")

    def get_client_private_key_path(self):
        """Returns the path to the client key."""
        return os.path.join(self.get_tmp_dir(), "client-key.pem")

    def get_default_pin(self) -> str:
        """Returns the first generated token's PIN as the default one."""
        if not self.tokens:
            raise ValueError("No tokens available")
        return self.tokens[0].pin

    def get_default_slot(self) -> str|None:
        """Returns the first generated token's slot as the default one."""
        if not self.tokens:
            raise ValueError("No tokens available")
        return self.tokens[0].slot

    def get_openssl_dir(self) -> str:
        """Returns the OpenSSL directory."""
        return self.get("openssl_dir")

    def get_pkcs11_module_path(self):
        """Determine the correct path for pkcs11.so."""
        custom_path = self.get("pkcs11.module", False)
        if custom_path:
            return custom_path

        openssl_dir = self.get_openssl_dir()
        if openssl_dir:
            module_path = os.path.join(openssl_dir, "lib64", "ossl-modules", "pkcs11.so")
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

    def is_pkcs11_proxy_executable(self):
        return self.get("pkcs11.proxy.executable", "pkcs11-daemon")

    def is_nginx_client_cert_enabled(self):
        return self.get("nginx.client_cert.enabled", False)

    def is_fresh(self):
        return self.get('fresh', True)

    def get_env_sh_file(self):
        return os.path.join(self.get_tmp_dir(), "env.sh")

    def get_env_json_file(self):
        return os.path.join(self.get_tmp_dir(), "env.json")

    def load_envs(self, print_envs: bool = False) -> dict[str, str]:
        """Load all environment variables from shell file."""
        env_file = self.get_env_json_file()
        if os.path.exists(env_file):
            with open(env_file, "r") as f:
                self.custom_envs = json.load(f)
                if print_envs:
                    for name, value in self.custom_envs.items():
                        print(f"export {name}={value}")
        return self.custom_envs

    def set_env(self, name: str, value: str):
        """Set an environment variable."""
        print(f"export {name}='{value}'")
        self.custom_envs[name] = value
        os.environ[name] = value

    def store_envs(self):
        """Dump all environment variables to a shell file that can be sourced."""
        with open(self.get_env_sh_file(), "w") as f:
            for name, value in self.custom_envs.items():
                f.write(f"export {name}='{value}'\n")
        with open(self.get_env_json_file(), "w") as f:
            json.dump(self.custom_envs, f)

    def store_tokens(self):
        """Store all tokens"""
        tokens_file = os.path.join(self.get_tmp_dir(), "tokens.yaml")
        with open(tokens_file, "w") as f:
            yaml.dump([{"index": t.index, "name": t.name, "slot": t.slot, "pin": t.pin} for t in self.tokens], f)

    def store(self):
        self.store_envs()
        self.store_tokens()
