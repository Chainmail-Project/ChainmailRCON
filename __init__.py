import builtins
import json
import os
import random
import re
import string

from Chainmail import Wrapper
from Chainmail.Plugin import ChainmailPlugin


class ChainmailRCON(ChainmailPlugin):

    def __init__(self, manifest: dict, wrapper: "Wrapper.Wrapper") -> None:
        super().__init__(manifest, wrapper)

        self.commands = []

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

        builtins.RCON = self

    def register_command(self, name: str, regex: str, description: str, handler: classmethod, requires_auth: bool = False) -> None:
        """
        Registers a new RCON command
        :param name: The name of the RCON command. Typically used for command lists
        :param regex: The regex used to process the command
        :param description: The description of the command
        :param handler: The handler for the command
        :param requires_auth: Whether the command requires the client to be authenticated
        """
        self.commands.append({
            "name": name,
            "regex": re.compile(regex),
            "description": description,
            "handler": handler,
            "requires_auth": requires_auth
        })
