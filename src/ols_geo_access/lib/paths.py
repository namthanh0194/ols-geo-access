from pathlib import Path


class PluginPaths:
    DATA_FILES = {
        "config": "config.json",
        "domains": "domains.json",
        "traffic_detection": "traffic_detection.json",
        "providers": "providers.json",
        "woo_exceptions": "woo_exceptions.json",
        "ip_allowlist": "ip_allowlist.json",
        "cloudflare_prefixes": "cloudflare_prefixes.json",
        "proxy_trust_state": "proxy_trust_state.json",
        "state": "state.json",
    }

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.data = self.root / "data"

    def data_file(self, name):
        if name not in self.DATA_FILES:
            raise ValueError("unknown data file")
        return self.data / self.DATA_FILES[name]
