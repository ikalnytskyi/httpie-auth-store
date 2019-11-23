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

    def lookup(self, url, key_id=None):
        for key in self._credentials:
            if re.search(key["url"], url):
                if key_id and key.get("id") != key_id:
                    continue
                return key["auth"]

        message = "No credentials found for a given URL: '%s'" % url
        if key_id:
            message += " (id='%s')" % key_id
        raise LookupError(message)


def get_credential_store(name, directory=httpie.config.DEFAULT_CONFIG_DIR):
    """Returns a credential store that can be used to lookup credentials."""

    credentials = []
    confpath = os.path.join(directory, name)

    if not os.path.exists(confpath):
        raise FileNotFoundError(
            "Credentials file '%s' is not found; please create one and try again."
            % confpath
        )

    mode = stat.S_IMODE(os.stat(confpath).st_mode)

    # Since credentials file may contain unencrypted secrets, I decided to
    # follow the same practice SSH does and do not work if the file can be
    # read by anyone but current user. However, I haven't figured how to
    # set correct permissions on Windows (I don't use this platform), let's
    # ignore this platform for a while.
    if sys.platform != "win32":
        if mode & 0o077 > 0o000:
            raise PermissionError(
                "Permissions '%04o' for '%s' are too open; please ensure your "
                "credentials file is NOT accessible by others."
                % (mode, confpath)
            )

        if mode & 0o400 != 0o400:
            raise PermissionError(
                "Permissions '%04o' for '%s' are too close; please ensure your "
                "credentials file CAN be read by you." % (mode, confpath)
            )

    with io.open(confpath, encoding="UTF-8") as f:
        credentials = json.load(f)

    return CredentialStore(credentials)
