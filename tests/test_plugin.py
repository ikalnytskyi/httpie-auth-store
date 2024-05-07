"""httpie-credential-store test suite."""

import io
import json
import os
import re
import sys

from urllib.request import parse_http_list, parse_keqv_list

import pytest
import responses


_is_windows = sys.platform == "win32"


class _DigestAuthHeader:
    """Assert that a given Authorization header has expected digest parameters."""

    def __init__(self, parameters):
        self._parameters = parameters

    def __eq__(self, authorization_header_value):
        auth_type, auth_value = authorization_header_value.split(maxsplit=1)
        assert auth_type.lower() == "digest"
        assert parse_keqv_list(parse_http_list(auth_value)) == self._parameters
        return True


class _RegExp:
    """Assert that a given string meets some expectations."""

    def __init__(self, pattern, flags=0):
        self._regex = re.compile(pattern, flags)

    def __eq__(self, actual):
        return bool(self._regex.match(actual))

    def __repr__(self):
        return self._regex.pattern


@pytest.fixture(autouse=True)
def httpie_config_dir(_httpie_config_dir):
    """Return a path to HTTPie configuration directory."""

    yield _httpie_config_dir

    # Since we cannot use new directory for HTTPie configuration for every test
    # (see reasons in `_httpie_config_dir` fixture), we must at least ensure
    # that there's no side effect between tests by emptying the directory.
    for path in _httpie_config_dir.iterdir():
        path.unlink()


@pytest.fixture()
def credentials_file(httpie_config_dir):
    """Return a path to credentials file."""

    return os.path.join(httpie_config_dir, "credentials.json")


@pytest.fixture()
def set_credentials(credentials_file):
    """Render given credentials to credentials.json."""

    def render(credentials, mode=0o600):
        with open(credentials_file, "w", encoding="UTF-8") as f:
            f.write(json.dumps(credentials, indent=4))
        os.chmod(credentials_file, mode)

    return render


@pytest.fixture()
def httpie_stderr():
    """Return captured standard error stream of HTTPie."""

    return io.StringIO()


@pytest.fixture()
def httpie_run(httpie_stderr):
    """Run HTTPie from within this process."""

    def main(args):
        # Imports of HTTPie internals must be local because otherwise they
        # won't take into account patched HTTPIE_CONFIG_DIR environment
        # variable.
        import httpie.context
        import httpie.core

        args = ["http", "--ignore-stdin", *args]
        env = httpie.context.Environment(stderr=httpie_stderr)
        return httpie.core.main(args, env=env)

    return main


@pytest.fixture(params=["credential-store", "creds"])
def creds_auth_type(request):
    """All possible aliases."""

    return request.param


@responses.activate
def test_basic_auth_plugin(httpie_run):
    """The plugin neither breaks nor overwrites existing auth plugins."""

    httpie_run(["-A", "basic", "-a", "user:p@ss", "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == b"Basic dXNlcjpwQHNz"


@responses.activate
def test_creds_auth_deactivated_by_default(httpie_run):
    """The plugin is deactivated by default."""

    httpie_run(["http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert "Authorization" not in request.headers


@responses.activate
def test_creds_auth_basic(httpie_run, set_credentials, creds_auth_type):
    """The plugin works for HTTP basic auth."""

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "basic",
                    "username": "user",
                    "password": "p@ss",
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == "Basic dXNlcjpwQHNz"


@responses.activate
def test_creds_auth_basic_keychain(httpie_run, set_credentials, creds_auth_type, tmp_path):
    """The plugin retrieves secrets from keychain for HTTP basic auth."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("p@ss", encoding="UTF-8")

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "basic",
                    "username": "user",
                    "password": {
                        "keychain": "shell",
                        "command": f"cat {secrettxt}",
                    },
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == "Basic dXNlcjpwQHNz"


@responses.activate
def test_creds_auth_digest(httpie_run, set_credentials, creds_auth_type):
    """The plugin works for HTTP digest auth."""

    responses.add(
        responses.GET,
        "http://example.com",
        status=401,
        headers={
            "WWW-Authenticate": (
                "Digest realm=auth.example.com"
                ',qop="auth,auth-int"'
                ",nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093"
                ",opaque=5ccc069c403ebaf9f0171e9517f40e41"
            )
        },
    )

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "digest",
                    "username": "user",
                    "password": "p@ss",
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 2
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert "Authorization" not in request.headers

    request = responses.calls[1].request
    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == _DigestAuthHeader(
        {
            "username": "user",
            "realm": "auth.example.com",
            "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            "uri": "/",
            "opaque": "5ccc069c403ebaf9f0171e9517f40e41",
            "qop": "auth",
            "nc": "00000001",
            # Both 'response' and 'cnonce' are time-based, thus there's no
            # reliable way to check their values without mocking time module.
            # Since we do not test here produced "digest", but ensure a proper
            # auth method is used, checking these values using regular
            # expression should be enough.
            "response": _RegExp(r"^[0-9a-fA-F]{32}$"),
            "cnonce": _RegExp(r"^[0-9a-fA-F]{16}$"),
        }
    )


@responses.activate
def test_creds_auth_token(httpie_run, set_credentials, creds_auth_type):
    """The plugin works for HTTP token auth."""

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "token",
                    "token": "token-can-be-anything",
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_creds_auth_token_scheme(httpie_run, set_credentials, creds_auth_type):
    """The plugin works for HTTP token auth with custom scheme."""

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "token",
                    "token": "token-can-be-anything",
                    "scheme": "JWT",
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == "JWT token-can-be-anything"


@responses.activate
def test_creds_auth_token_keychain(httpie_run, set_credentials, creds_auth_type, tmp_path):
    """The plugin retrieves secrets from keychain for HTTP token auth."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("token-can-be-anything", encoding="UTF-8")

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "token",
                    "token": {
                        "keychain": "shell",
                        "command": f"cat {secrettxt}",
                    },
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_creds_auth_header(httpie_run, set_credentials, creds_auth_type):
    """The plugin works for HTTP header auth."""

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "header",
                    "name": "X-Auth",
                    "value": "value-can-be-anything",
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["X-Auth"] == "value-can-be-anything"


@responses.activate
def test_creds_auth_header_keychain(httpie_run, set_credentials, creds_auth_type, tmp_path):
    """The plugin retrieves secrets from keychain for HTTP header auth."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("value-can-be-anything", encoding="UTF-8")

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "header",
                    "name": "X-Auth",
                    "value": {
                        "keychain": "shell",
                        "command": f"cat {secrettxt}",
                    },
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["X-Auth"] == "value-can-be-anything"


@responses.activate
def test_creds_auth_multiple_token_header(httpie_run, set_credentials, creds_auth_type):
    """The plugin works for multiple auths."""

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "multiple",
                    "providers": [
                        {
                            "provider": "token",
                            "token": "token-can-be-anything",
                            "scheme": "JWT",
                        },
                        {
                            "provider": "header",
                            "name": "X-Auth",
                            "value": "value-can-be-anything",
                        },
                    ],
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == "JWT token-can-be-anything"
    assert request.headers["X-Auth"] == "value-can-be-anything"


@responses.activate
def test_creds_auth_multiple_header_header(httpie_run, set_credentials, creds_auth_type):
    """The plugin supports usage of the same auth provider twice."""

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "multiple",
                    "providers": [
                        {
                            "provider": "header",
                            "name": "X-Secret",
                            "value": "secret-can-be-anything",
                        },
                        {
                            "provider": "header",
                            "name": "X-Auth",
                            "value": "auth-can-be-anything",
                        },
                    ],
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["X-Secret"] == "secret-can-be-anything"
    assert request.headers["X-Auth"] == "auth-can-be-anything"


@responses.activate
def test_creds_auth_multiple_token_header_keychain(
    httpie_run, set_credentials, creds_auth_type, tmp_path
):
    """The plugin retrieves secrets from keychains for combination of auths."""

    tokentxt, secrettxt = tmp_path.joinpath("token.txt"), tmp_path.joinpath("secret.txt")
    tokentxt.write_text("token-can-be-anything", encoding="UTF-8")
    secrettxt.write_text("secret-can-be-anything", encoding="UTF-8")

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "multiple",
                    "providers": [
                        {
                            "provider": "token",
                            "token": {
                                "keychain": "shell",
                                "command": f"cat {tokentxt}",
                            },
                            "scheme": "JWT",
                        },
                        {
                            "provider": "header",
                            "name": "X-Auth",
                            "value": {
                                "keychain": "shell",
                                "command": f"cat {secrettxt}",
                            },
                        },
                    ],
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == "JWT token-can-be-anything"
    assert request.headers["X-Auth"] == "secret-can-be-anything"


@responses.activate
@pytest.mark.parametrize(
    ("auth", "error_pattern"),
    [
        pytest.param(
            {"provider": "basic"},
            r"http: error: TypeError: (HTTPBasicAuth\.)?__init__\(\) missing 2 required "
            r"keyword-only arguments: 'username' and 'password'",
            id="basic-both",
        ),
        pytest.param(
            {"provider": "basic", "username": "user"},
            r"http: error: TypeError: (HTTPBasicAuth\.)?__init__\(\) missing 1 required "
            r"keyword-only argument: 'password'",
            id="basic-passowrd",
        ),
        pytest.param(
            {"provider": "basic", "password": "p@ss"},
            r"http: error: TypeError: (HTTPBasicAuth\.)?__init__\(\) missing 1 required "
            r"keyword-only argument: 'username'",
            id="basic-username",
        ),
        pytest.param(
            {"provider": "digest"},
            r"http: error: TypeError: (HTTPDigestAuth\.)?__init__\(\) missing 2 required "
            r"keyword-only arguments: 'username' and 'password'",
            id="digest-both",
        ),
        pytest.param(
            {"provider": "digest", "username": "user"},
            r"http: error: TypeError: (HTTPDigestAuth\.)?__init__\(\) missing 1 required "
            r"keyword-only argument: 'password'",
            id="digest-password",
        ),
        pytest.param(
            {"provider": "digest", "password": "p@ss"},
            r"http: error: TypeError: (HTTPDigestAuth\.)?__init__\(\) missing 1 required "
            r"keyword-only argument: 'username'",
            id="digest-username",
        ),
        pytest.param(
            {"provider": "token"},
            r"http: error: TypeError: (HTTPTokenAuth\.)?__init__\(\) missing 1 required "
            r"keyword-only argument: 'token'",
            id="token",
        ),
        pytest.param(
            {"provider": "header"},
            r"http: error: TypeError: (HTTPHeaderAuth\.)?__init__\(\) missing 2 required "
            r"keyword-only arguments: 'name' and 'value'",
            id="header-both",
        ),
        pytest.param(
            {"provider": "header", "name": "X-Auth"},
            r"http: error: TypeError: (HTTPHeaderAuth\.)?__init__\(\) missing 1 required "
            r"keyword-only argument: 'value'",
            id="header-value",
        ),
        pytest.param(
            {"provider": "header", "value": "value-can-be-anything"},
            r"http: error: TypeError: (HTTPHeaderAuth\.)?__init__\(\) missing 1 required "
            r"keyword-only argument: 'name'",
            id="header-name",
        ),
        pytest.param(
            {"provider": "multiple"},
            r"http: error: TypeError: (HTTPMultipleAuth\.)?__init__\(\) missing 1 required "
            r"keyword-only argument: 'providers'",
            id="multiple",
        ),
    ],
)
def test_creds_auth_missing(
    httpie_run, set_credentials, httpie_stderr, auth, error_pattern, creds_auth_type
):
    """The plugin raises error on wrong parameters."""

    set_credentials([{"url": "http://example.com", "auth": auth}])
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 0
    assert re.fullmatch(error_pattern, httpie_stderr.getvalue().strip())


@responses.activate
@pytest.mark.parametrize(
    ("regexp", "url", "normalized_url"),
    [
        pytest.param(
            r"http://example.com/",
            "http://example.com/",
            "http://example.com/",
            id="http",
        ),
        pytest.param(
            r"http://example.com",
            "http://example.com/",
            "http://example.com/",
            id="http-no-trailing-/",
        ),
        pytest.param(
            r"https://example.com",
            "https://example.com/",
            "https://example.com/",
            id="https",
        ),
        pytest.param(
            r"^http://example.com/$",
            "http://example.com/",
            "http://example.com/",
            id="^regexp$",
        ),
        pytest.param(
            r"example.com",
            "http://example.com/",
            "http://example.com/",
            id="no-protocol",
        ),
        pytest.param(r"example", "http://example.com/", "http://example.com/", id="part"),
        pytest.param(
            r"example.com",
            "http://example.com/foo/bar",
            "http://example.com/foo/bar",
            id="long-request-url",
        ),
        pytest.param(
            r"http://example.com/foo/bar",
            "http://example.com/foo/bar",
            "http://example.com/foo/bar",
            id="long-request-url-pattern",
        ),
        pytest.param(
            r"http://example(.com|.org)/foo/bar",
            "http://example.com/foo/bar",
            "http://example.com/foo/bar",
            id="long-request-url-pattern-regexp",
        ),
    ],
)
def test_creds_lookup_regexp(
    httpie_run, set_credentials, regexp, url, normalized_url, creds_auth_type
):
    """The plugin uses pattern matching to find credentials."""

    set_credentials(
        [
            {
                "url": regexp,
                "auth": {
                    "provider": "token",
                    "token": "token-can-be-anything",
                },
            }
        ]
    )
    httpie_run(["-A", creds_auth_type, url])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == normalized_url
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_creds_lookup_1st_matched_wins(httpie_run, set_credentials, creds_auth_type):
    """The plugin uses auth of first matched credential entry."""

    set_credentials(
        [
            {
                "url": "yoda.ua",
                "auth": {
                    "provider": "token",
                    "token": "token-can-be-anything",
                },
            },
            {
                "url": "yoda.ua/v2",
                "auth": {
                    "provider": "basic",
                    "username": "user",
                    "password": "p@ss",
                },
            },
        ]
    )
    httpie_run(["-A", creds_auth_type, "https://yoda.ua/v2/the-force"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/v2/the-force"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_creds_lookup_many_credentials(httpie_run, set_credentials, creds_auth_type):
    """The plugin works with many URLs and credentials."""

    responses.add(responses.GET, "https://yoda.ua/about/", status=200)
    responses.add(responses.GET, "http://skywalker.com", status=200)

    set_credentials(
        [
            {
                "url": "yoda.ua",
                "auth": {
                    "provider": "token",
                    "token": "token-can-be-anything",
                },
            },
            {
                "url": "http://skywalker.com",
                "auth": {
                    "provider": "basic",
                    "username": "user",
                    "password": "p@ss",
                },
            },
        ]
    )
    httpie_run(["-A", creds_auth_type, "https://yoda.ua/about/"])
    httpie_run(["-A", creds_auth_type, "http://skywalker.com"])
    assert len(responses.calls) == 2

    request = responses.calls[0].request
    assert request.url == "https://yoda.ua/about/"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"

    request = responses.calls[1].request
    assert request.url == "http://skywalker.com/"
    assert request.headers["Authorization"] == "Basic dXNlcjpwQHNz"


@responses.activate
@pytest.mark.parametrize(
    ("regexp", "url"),
    [
        pytest.param(r"http://example.com/", "https://example.com/", id="http-https"),
        pytest.param(r"https://example.com", "http://example.com/", id="https-http"),
        pytest.param(r"^example.com", "https://example.com/", id="^regexp"),
        pytest.param(r"example.com", "http://example.org/", id="org-com"),
        pytest.param(
            r"http://example.com/foo/baz",
            "http://example.com/foo/bar",
            id="long-request-url-pattern",
        ),
    ],
)
def test_creds_lookup_error(httpie_run, set_credentials, regexp, url, httpie_stderr):
    """The plugin raises error if no credentials found."""

    set_credentials(
        [
            {
                "url": regexp,
                "auth": {
                    "provider": "token",
                    "token": "token-can-be-anything",
                },
            }
        ]
    )
    httpie_run(["-A", "credential-store", url])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        f"http: error: LookupError: No credentials found for a given URL: '{url}'"
    )


@responses.activate
def test_creds_lookup_by_id(httpie_run, set_credentials):
    """The plugin uses a given credential ID as a hint for 2+ matches."""

    set_credentials(
        [
            {
                "url": "yoda.ua",
                "auth": {"provider": "token", "token": "i-am-yoda"},
            },
            {
                "id": "luke",
                "url": "yoda.ua",
                "auth": {"provider": "token", "token": "i-am-skywalker"},
            },
        ]
    )
    httpie_run(["-A", "credential-store", "https://yoda.ua/about/"])
    httpie_run(["-A", "credential-store", "-a", "luke", "https://yoda.ua/about/"])
    assert len(responses.calls) == 2

    request = responses.calls[0].request
    assert request.url == "https://yoda.ua/about/"
    assert request.headers["Authorization"] == "Bearer i-am-yoda"

    request = responses.calls[1].request
    assert request.url == "https://yoda.ua/about/"
    assert request.headers["Authorization"] == "Bearer i-am-skywalker"


@responses.activate
def test_creds_lookup_by_id_error(httpie_run, set_credentials, httpie_stderr, creds_auth_type):
    """The plugin raises error if no credentials found."""

    set_credentials(
        [
            {
                "id": "yoda",
                "url": "yoda.ua",
                "auth": {"provider": "token", "token": "i-am-yoda"},
            },
            {
                "id": "luke",
                "url": "yoda.ua",
                "auth": {"provider": "token", "token": "i-am-skywalker"},
            },
        ]
    )

    httpie_run(["-A", creds_auth_type, "-a", "vader", "https://yoda.ua/about/"])
    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        "http: error: LookupError: No credentials found for a given URL: "
        "'https://yoda.ua/about/' (id='vader')"
    )


@responses.activate
@pytest.mark.skipif(_is_windows, reason="no support for permissions on windows")
@pytest.mark.parametrize(
    "mode",
    [
        pytest.param(0o700, id="0700"),
        pytest.param(0o600, id="0600"),
        pytest.param(0o500, id="0500"),
        pytest.param(0o400, id="0400"),
    ],
)
def test_creds_permissions_safe(httpie_run, set_credentials, mode, creds_auth_type):
    """The plugin doesn't complain if credentials file has safe permissions."""

    set_credentials(
        [
            {
                "url": "http://example.com",
                "auth": {
                    "provider": "basic",
                    "username": "user",
                    "password": "p@ss",
                },
            }
        ],
        mode=mode,
    )
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "http://example.com/"
    assert request.headers["Authorization"] == "Basic dXNlcjpwQHNz"


@responses.activate
@pytest.mark.skipif(_is_windows, reason="no support for permissions on windows")
@pytest.mark.parametrize(
    "mode",
    [
        pytest.param(0o607, id="0607"),
        pytest.param(0o606, id="0606"),
        pytest.param(0o605, id="0605"),
        pytest.param(0o604, id="0604"),
        pytest.param(0o603, id="0603"),
        pytest.param(0o602, id="0602"),
        pytest.param(0o601, id="0601"),
        pytest.param(0o670, id="0670"),
        pytest.param(0o660, id="0660"),
        pytest.param(0o650, id="0650"),
        pytest.param(0o640, id="0640"),
        pytest.param(0o630, id="0630"),
        pytest.param(0o620, id="0620"),
        pytest.param(0o610, id="0610"),
    ],
)
def test_creds_permissions_unsafe(
    httpie_run,
    set_credentials,
    mode,
    httpie_stderr,
    credentials_file,
    creds_auth_type,
):
    """The plugin complains if credentials file has unsafe permissions."""

    set_credentials([{"url": "http://example.com", "auth": {}}], mode=mode)
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert httpie_stderr.getvalue().strip() == (
        f"http: error: PermissionError: Permissions '{mode:04o}' for "
        f"'{credentials_file}' are too open; please ensure your credentials "
        f"file is NOT accessible by others."
    )


@responses.activate
@pytest.mark.skipif(_is_windows, reason="no support for permissions on windows")
@pytest.mark.parametrize(
    "mode",
    [
        pytest.param(0o300, id="0300"),
        pytest.param(0o200, id="0200"),
        pytest.param(0o100, id="0100"),
    ],
)
def test_creds_permissions_not_enough(
    httpie_run,
    set_credentials,
    mode,
    httpie_stderr,
    credentials_file,
    creds_auth_type,
):
    """The plugin complains if credentials file has unsafe permissions."""

    set_credentials([{"url": "http://example.com", "auth": {}}], mode=mode)
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert httpie_stderr.getvalue().strip() == (
        f"http: error: PermissionError: Permissions '{mode:04o}' for "
        f"'{credentials_file}' are too close; please ensure your credentials "
        f"file CAN be read by you."
    )


@responses.activate
def test_creds_auth_no_database(httpie_run, credentials_file, httpie_stderr, creds_auth_type):
    """The plugin raises error if credentials file does not exist."""

    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        f"http: error: FileNotFoundError: Credentials file '{credentials_file}' "
        f"is not found; please create one and try again."
    )


@responses.activate
@pytest.mark.parametrize(
    ("auth", "error"),
    [
        pytest.param(
            {"provider": "header", "name": "X-Auth", "value": "p@ss\n"},
            r"http: error: ValueError: HTTP header authentication provider "
            r"received invalid header value: 'p@ss\n'. Please remove illegal "
            r"characters and try again.",
            id="header-value",
        ),
        pytest.param(
            {"provider": "token", "token": "t0ken\n"},
            r"http: error: ValueError: HTTP token authentication provider "
            r"received token that contains illegal characters: 't0ken\n'. "
            r"Please remove these characters and try again.",
            id="token-token",
        ),
        pytest.param(
            {"provider": "token", "token": "t0ken", "scheme": "J\nWT"},
            r"http: error: ValueError: HTTP token authentication provider "
            r"received scheme that contains illegal characters: 'J\nWT'. "
            r"Please remove these characters and try again.",
            id="token-scheme",
        ),
    ],
)
def test_creds_auth_header_value_illegal_characters(
    httpie_run, set_credentials, httpie_stderr, creds_auth_type, auth, error
):
    set_credentials([{"url": "http://example.com", "auth": auth}])
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == error


@responses.activate
@pytest.mark.parametrize(
    ("auth", "error"),
    [
        pytest.param(
            {"provider": "header", "name": "X-Auth\n", "value": "p@ss"},
            r"http: error: ValueError: HTTP header authentication provider "
            r"received invalid header name: 'X-Auth\n'. Please remove illegal "
            r"characters and try again.",
            id="header-name-newline",
        ),
        pytest.param(
            {"provider": "header", "name": "X:Auth", "value": "p@ss"},
            r"http: error: ValueError: HTTP header authentication provider "
            r"received invalid header name: 'X:Auth'. Please remove illegal "
            r"characters and try again.",
            id="header-name-colon",
        ),
    ],
)
def test_creds_auth_header_name_illegal_characters(
    httpie_run, set_credentials, httpie_stderr, creds_auth_type, auth, error
):
    set_credentials([{"url": "http://example.com", "auth": auth}])
    httpie_run(["-A", creds_auth_type, "http://example.com"])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == error
