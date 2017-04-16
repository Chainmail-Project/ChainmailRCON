import builtins
import json
import os
import random
import re
import string
import threading
from socketserver import StreamRequestHandler, ThreadingTCPServer
from typing import List, Match
from socket import SOL_SOCKET, SO_REUSEADDR, SHUT_RDWR

from Chainmail import Wrapper
from Chainmail.Plugin import ChainmailPlugin
from Chainmail.Events import ConsoleOutputEvent, Events


class RCONClientHandler(StreamRequestHandler):

    # noinspection PyAttributeOutsideInit
    def setup(self):
        super().setup()
        self.authed = False
        self.rcon = getattr(builtins, "RCON")  # type: ChainmailRCON
        self.rcon.logger.info(f"New client connected from {self.client_address[0]}")
        self.rcon.clients.append(self)


    def handle(self):
        try:
            if self.rcon.config["use_whitelist"] and self.client_address[0] not in self.rcon.config["whitelisted_ips"]:
                self.writeline("ERROR: Not on whitelist")
                return
            while self.rcon.enabled and self.rcon.wrapper.wrapper_running:
                line = self.rfile.readline().decode("utf-8").strip()
                if line != "":
                    self.rcon.process_command(line, self)
        except (BrokenPipeError, OSError, ConnectionResetError):
            self.finish()


    def finish(self):
        super().finish()
        try:
            self.rcon.clients.remove(self)
        except ValueError:
            pass
        self.rcon.logger.info(f"Client {self.client_address[0]} disconnected")

    def writeline(self, line: str):
        try:
            self.wfile.write(f"{line}\n".encode("utf-8"))
        except (BrokenPipeError, OSError, ConnectionResetError):
            self.finish()


class ChainmailRCON(ChainmailPlugin):

    def __init__(self, manifest: dict, wrapper: "Wrapper.Wrapper") -> None:
        super().__init__(manifest, wrapper)

        builtins.RCON = self

        self.commands = []
        self.clients = []  # type: List[RCONClientHandler]

        if not os.path.isfile(os.path.join(manifest["path"], "config.json")):
            with open(os.path.join(manifest["path"], "config.json"), "w") as f:
                self.config = {
                    "password": "".join(random.choice(string.ascii_letters + string.digits) for i in range(16)),
                    "use_whitelist": False,
                    "whitelisted_ips": [],
                    "port": 25566
                }
                json.dump(self.config, f, sort_keys=True, indent=4)
                self.logger.info(f"Generated new config. Use the password {self.config['password']} to authenticate.")
        else:
            with open(os.path.join(manifest["path"], "config.json")) as f:
                self.config = json.load(f)

        self.wrapper.EventManager.register_handler(Events.CONSOLE_OUTPUT, self.handle_console_output)

        self.register_command("/auth", "\\/auth ([\\w]+)", "Authenticates using a password to gain access to higher privilege commands.", self.command_auth)

        self.server = ThreadingTCPServer(("", self.config["port"]), RCONClientHandler)
        self.server.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

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

    def process_command(self, data: str, handler: RCONClientHandler):
        for command in self.commands:
            if command["regex"].match(data):
                if not command["requires_auth"] or handler.authed:
                    threading.Thread(target=command["handler"], args=(command["regex"].findall(data), handler)).start()
                    return
        if handler.authed:
            self.wrapper.write_line(data)

    def run_server(self):
        self.server.serve_forever()
        self.server.server_close()

    def enable(self) -> None:
        super().enable()
        threading.Thread(target=self.run_server).start()

    def disable(self) -> None:
        super().disable()
        self.server.shutdown()
        for client in self.clients[:]:
            client.connection.shutdown(SHUT_RDWR)

    def command_auth(self, matches: Match[str], handler: RCONClientHandler):
        if matches[0] == self.config["password"]:
            handler.authed = True
            handler.writeline("AUTH: Client authenticated successfully")
        else:
            handler.authed = False
            handler.writeline("AUTH: Invalid RCON password")

    def handle_console_output(self, event: ConsoleOutputEvent):
        for client in self.clients:
            client.writeline(event.output)
