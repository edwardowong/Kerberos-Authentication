"""
Assignment 3
Name: Edward Wong ewong385
Class: CS4458A
"""

import getpass
import json
import pickle
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

REALM_NAME = "@KERBEROS"

AS_TGS_SHARED_KEY = get_random_bytes(32)
TGS_FS_SHARED_KEY = get_random_bytes(32)


def derive_secret_key(username: str, password: str) -> bytes:
    """
    Derives the given user's secret key from the username and password.
    This one-way derivation function uses SHA256 as the hashing algorithm.
    The salt (combined username and realm name) is prepended to the given
    password so that two different encryption keys are generated for users
    with the same password.
    """
    salt = (username + REALM_NAME + password)
    key = SHA256.new(salt.encode()).digest()
    return key


def encrypt(key: bytes, data: Any) -> bytes:
    """Encrypts the given data using AES."""
    cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(16), mac_len=16)
    nonce = cipher.nonce
    encryption, tags = cipher.encrypt_and_digest(pickle.dumps(data))
    return pickle.dumps([nonce, encryption, tags])


def decrypt(key: bytes, data: bytes) -> Any:
    """Decrypts the given message using AES."""
    loaded_data = pickle.loads(data)
    cipher = AES.new(key, AES.MODE_EAX, nonce=loaded_data[0], mac_len=16)
    decryption = cipher.decrypt_and_verify(loaded_data[1], loaded_data[2])
    return pickle.loads(decryption)


class AuthenticationServer:
    """The authentication server in Kerberos."""

    def __init__(self) -> None:
        with open("users.json", "rb") as file:
            self.users = {k: bytes.fromhex(v) for k, v in json.load(file).items()}

    def request_authentication(self, username: str) -> Optional[Tuple[bytes, bytes]]:
        """Requests authentication for the given user from the authentication server."""
        try:
            client_key = self.users[username]               # checks if username is in database, and creates client secret key
        except KeyError:
            print("Username not found!")
            exit()
        else:
            client_tgs_key = get_random_bytes(32)
            tgt = Ticket(username, client_tgs_key)
            msg1 = encrypt(client_key, client_tgs_key)      # Message 1: client/TGS session key encrypted using client secret key
            msg2 = encrypt(AS_TGS_SHARED_KEY, tgt)          # Message 2: TGT encrypted using shared key between AS and TGS
            return msg1, msg2


class TicketGrantingServer:
    """The ticket-granting server in Kerberos."""

    def request_authorization(self, tgt_encrypted: bytes, authenticator_encrypted: bytes) -> Optional[Tuple[bytes, bytes]]:
        """Requests service authorization from the ticket-granting server by using the given TGT and authenticator."""

        client_fs_key = get_random_bytes(32)
        tgt = decrypt(AS_TGS_SHARED_KEY, tgt_encrypted)
        client_tgs_key = tgt.session_key
        auth = decrypt(client_tgs_key, authenticator_encrypted)

        if tgt.username != auth.username:
            print("TGS Error: TGT username and authenticator username are different!")
            exit()
        else:                                                   # if usernames match
            msg5 = encrypt(client_tgs_key, client_fs_key)       # Message 5: client/FS session key encrypted using client/TGS session key
            service_ticket = Ticket(tgt.username, client_fs_key)
            msg6 = encrypt(TGS_FS_SHARED_KEY, service_ticket)   # Message 6: service ticket encrypted using shared key between TGS and FS
            return msg5, msg6


class FileServer:
    """The file server in Kerberos."""

    def request_file(self, filename: str, ticket_encrypted: bytes, authenticator_encrypted: bytes) -> Optional[bytes]:
        """Requests the given file from the file server by using the given service ticket and authenticator as authorization."""
        ticket = decrypt(TGS_FS_SHARED_KEY, ticket_encrypted)
        client_fs_key = ticket.session_key
        auth = decrypt(client_fs_key, authenticator_encrypted)
        try:
            if ticket.username == auth.username:
                with open(filename, "rb") as file:
                    data = file.read()

                file_request = FileResponse(data, auth.timestamp)
                msg9 = encrypt(client_fs_key, file_request)       # Message 9: the file request response encrypted using the client/FS session key
                return msg9
            else:
                print("FS Error: Ticket username and authenticator username are different!")
                exit()
        except FileNotFoundError:
            print(filename + " not found!")
            exit()


class Client:
    """The client in Kerberos."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.secret_key = derive_secret_key(username, password)

    @classmethod
    def from_terminal(cls):
        """Creates a client object using user input from the terminal."""

        username = input("Username: ")
        password = getpass.getpass("Password: ")
        return cls(username, password)

    def get_file(self, filename: str):
        """Gets the given file from the file server."""

        AS = AuthenticationServer()
        TGS = TicketGrantingServer()
        FS = FileServer()

        msg1, msg2 = AS.request_authentication(self.username)
        auth = Authenticator(self.username)

        try:
            client_tgs_key = decrypt(self.secret_key, msg1)
        except:
            print("Failed to decrypt client/TGS session key")
            exit()

        try:
            auth_encrypted = encrypt(client_tgs_key, auth)                  # Message 4: authenticator encrypted using client/TGS session key
        except:
            print("Failed to encrypt authenticator using client/TGS session key")
            exit()

        try:
            msg5, msg6 = TGS.request_authorization(msg2, auth_encrypted)    # Message 3: client forwards message 2 (TGT) from AS to TGS
        except:
            print("Failed to forward TGT from AS to TGS")
            exit()

        try:
            client_fs_key = decrypt(client_tgs_key, msg5)
        except:
            print("Failed to decrypt client/FS session key")
            exit()

        try:
            auth_encrypted = encrypt(client_fs_key, auth)                   # Message 8: authenticator encrypted using client/FS session key
        except:
            print("Failed to encrypt authenticator using client/FS session key")
            exit()

        try:
            file_request_encrypted = FS.request_file(filename, msg6, auth_encrypted)  # Message 7: client forwards message 6 (service ticket) from TGS to FS
        except:
            print("Failed to forward service ticket from TGS to FS")
            exit()

        try:
            file_request_decrypted = decrypt(client_fs_key, file_request_encrypted)
            if file_request_decrypted.timestamp == auth.timestamp:
                print("Retrieved " + filename + " from FS:")
                print(file_request_decrypted.data.decode())
            else:
                print("Client Error: File request timestamp and authenticator timestamp do not match!")
        except:
            print("Failed to decrypt file request!")
            exit()


@dataclass(frozen=True)
class Ticket:
    """A ticket that acts as both a ticket-granting ticket (TGT) and a service ticket."""

    username: str
    session_key: bytes
    validity: float = field(init=False, default_factory=lambda: time.time() + 3600)


@dataclass(frozen=True)
class Authenticator:
    """An authenticator used by the client to confirm their identity with the various servers."""

    username: str
    timestamp: float = field(init=False, default_factory=time.time)


@dataclass(frozen=True)
class FileResponse:
    """A response to a file request that contains the file's data and a timestamp to confirm the file server's identity."""

    data: str
    timestamp: float


if __name__ == "__main__":
    client = Client.from_terminal()
    client.get_file("test.txt")
