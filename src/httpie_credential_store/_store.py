"""Credentials are managed here."""

import io
import json
import os
import re
import stat
import sys

import httpie.config


class CredentialStore(object):
    """Credential store, manages your credentials."""

    def __init__(self, credentials):
        self._credentials = credentials

    def lookup(self, url, credential_id=None):
        for credential in self._credentials:
            if re.search(credential["url"], url):
                if credential_id and credential.get("id") != credential_id:
                    continue
                return credential["auth"]

        message = f"No credentials found for a given URL: '{url}'"
        if credential_id:
            message += f" (id='{credential_id}')"
        raise LookupError(message)


def get_credential_store(name, directory=httpie.config.DEFAULT_CONFIG_DIR):
    """Returns a credential store that can be used to lookup credentials."""

    credentials = []
    credential_file = os.path.join(directory, name)

    if not os.path.exists(credential_file):
        raise FileNotFoundError(
            f"Credentials file '{credential_file}' is not found; "
            f"please create one and try again."
        )

    mode = stat.S_IMODE(os.stat(credential_file).st_mode)

    # Since credentials file may contain unencrypted secrets, I decided to
    # follow the same practice SSH does and do not work if the file can be
    # read by anyone but current user. However, I haven't figured how to
    # set correct permissions on Windows (I don't use this platform), let's
    # ignore this platform for a while.
    if sys.platform != "win32":
        if mode & 0o077 > 0o000:
            raise PermissionError(
                f"Permissions '{mode:04o}' for '{credential_file}' are too "
                f"open; please ensure your credentials file is NOT accessible "
                f"by others."
            )

        if mode & 0o400 != 0o400:
            raise PermissionError(
                f"Permissions '{mode:04o}' for '{credential_file}' are too "
                f"close; please ensure your credentials file CAN be read by "
                f"you."
            )

    with io.open(credential_file, encoding="UTF-8") as f:
        credentials = json.load(f)

    return CredentialStore(credentials)
