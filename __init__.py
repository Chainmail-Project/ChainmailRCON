import json
import os
import random
import string

from Chainmail import Wrapper
from Chainmail.Plugin import ChainmailPlugin


class ChainmailRCON(ChainmailPlugin):
    def __init__(self, manifest: dict, wrapper: "Wrapper.Wrapper") -> None:
        super().__init__(manifest, wrapper)

        if not os.path.isfile(os.path.join(manifest["path"], "config.json")):
            with open(os.path.join(manifest["path"], "config.json"), "w") as f:
                self.config = {
                    "password": "".join(random.choice(string.ascii_letters + string.digits) for i in range(16)),
                    "use_whitelist": False,
                    "whitelisted_ips": []
                }
                json.dump(self.config, f, sort_keys=True, indent=4)
                self.logger.info(f"Generated new config. Use the password {self.config['password']} to authenticate.")
        else:
            with open(os.path.join(manifest["path"], "config.json")) as f:
                self.config = json.load(f)