import io
import json
import pathlib
import re
import sys
import typing as t

from urllib.request import parse_http_list, parse_keqv_list

import httpie.context
import httpie.core
import pytest
import responses

from httpie_auth_store._auth import StoreAuth


_is_windows = sys.platform == "win32"


HttpieRunT = t.Callable[[t.List[t.Union[str, bytes]]], int]
StoreSetT = t.Callable[..., None]


class _DigestAuthHeader:
    """Assert that a given Authorization header has expected digest parameters."""

    def __init__(self, parameters: t.Mapping[str, t.Any]) -> None:
        self._parameters = parameters

    def __eq__(self, authorization_header_value: object) -> bool:
        assert isinstance(authorization_header_value, str)
        auth_type, auth_value = authorization_header_value.split(maxsplit=1)
        assert auth_type.lower() == "digest"
        assert parse_keqv_list(parse_http_list(auth_value)) == self._parameters
        return True


class _RegExp:
    """Assert that a given string meets some expectations."""

    def __init__(self, pattern: str, flags: int = 0) -> None:
        self._regex = re.compile(pattern, flags)

    def __eq__(self, actual: object) -> bool:
        assert isinstance(actual, str)
        return bool(self._regex.match(actual))

    def __repr__(self) -> str:
        return self._regex.pattern


@pytest.fixture(autouse=True)
def httpie_config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> pathlib.Path:
    """Return a path to HTTPie configuration directory."""

    config_dir = tmp_path.joinpath(".httpie")
    config_dir.mkdir()
    monkeypatch.setattr("httpie.config.DEFAULT_CONFIG_DIR", config_dir)
    return config_dir


@pytest.fixture()
def auth_store_path(httpie_config_dir: pathlib.Path) -> pathlib.Path:
    """Return a path to the auth store file."""

    return httpie_config_dir / StoreAuth.AUTH_STORE_FILENAME


@pytest.fixture()
def store_set(auth_store_path: pathlib.Path) -> StoreSetT:
    """Render given auth store to auth_store.json."""

    def render(
        *,
        bindings: t.List[t.Mapping[str, t.Any]],
        secrets: t.Optional[t.Mapping[str, t.Any]] = None,
        mode: int = 0o600,
    ) -> None:
        auth_store_path.write_text(
            json.dumps(
                {
                    "bindings": bindings,
                    "secrets": secrets or {},
                },
                indent=4,
            )
        )
        auth_store_path.chmod(mode)

    return render


@pytest.fixture()
def httpie_stderr() -> io.StringIO:
    """Return captured standard error stream of HTTPie."""

    return io.StringIO()


@pytest.fixture()
def httpie_run(httpie_stderr: io.StringIO, httpie_config_dir: pathlib.Path) -> HttpieRunT:
    """Run HTTPie from within this process."""

    def main(args: t.List[t.Union[str, bytes]]) -> int:
        args = ["http", "--ignore-stdin", *args]
        env = httpie.context.Environment(stderr=httpie_stderr, config_dir=httpie_config_dir)
        return httpie.core.main(args, env=env)

    return main


@responses.activate
def test_basic_auth_plugin(httpie_run: HttpieRunT) -> None:
    """The plugin neither breaks nor overwrites existing auth plugins."""

    httpie_run(["-A", "basic", "-a", "user:p@ss", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == b"Basic dXNlcjpwQHNz"


@responses.activate
def test_store_auth_deactivated_by_default(httpie_run: HttpieRunT) -> None:
    """The plugin is deactivated by default."""

    httpie_run(["https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert "Authorization" not in request.headers


@responses.activate
def test_store_auth_basic(httpie_run: HttpieRunT, store_set: StoreSetT) -> None:
    """The plugin works for HTTP basic auth."""

    store_set(
        bindings=[
            {
                "auth_type": "basic",
                "auth": "user:p@ss",
                "resources": ["https://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == b"Basic dXNlcjpwQHNz"


@responses.activate
@pytest.mark.parametrize("auth", ["user", "user:"])
def test_store_auth_basic_no_password(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    auth: str,
) -> None:
    """The plugin works for HTTP basic auth even w/o password."""

    store_set(
        bindings=[
            {
                "auth_type": "basic",
                "auth": auth,
                "resources": ["https://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == b"Basic dXNlcjo="


@responses.activate
def test_store_auth_basic_no_username(httpie_run: HttpieRunT, store_set: StoreSetT) -> None:
    """The plugin works for HTTP basic auth even w/o username."""

    store_set(
        bindings=[
            {
                "auth_type": "basic",
                "auth": ":p@ss",
                "resources": ["https://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == b"Basic OnBAc3M="


@responses.activate
def test_store_auth_basic_secret_provider(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    tmp_path: pathlib.Path,
) -> None:
    """The plugin retrieves secrets from secret provider for HTTP basic auth."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("p@ss", encoding="UTF-8")

    store_set(
        bindings=[
            {
                "auth_type": "basic",
                "auth": "user:$PASSWORD",
                "resources": ["https://yoda.ua"],
            }
        ],
        secrets={
            "PASSWORD": {
                "provider": "sh",
                "script": f"cat {secrettxt}",
            }
        },
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == b"Basic dXNlcjpwQHNz"


@responses.activate
def test_store_auth_digest(httpie_run: HttpieRunT, store_set: StoreSetT) -> None:
    """The plugin works for HTTP digest auth."""

    responses.add(
        responses.GET,
        "https://yoda.ua",
        status=401,
        headers={
            "WWW-Authenticate": (
                "Digest realm=auth.yoda.ua"
                ',qop="auth,auth-int"'
                ",nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093"
                ",opaque=5ccc069c403ebaf9f0171e9517f40e41"
            )
        },
    )

    store_set(
        bindings=[
            {
                "auth_type": "digest",
                "auth": "user:p@ss",
                "resources": ["https://yoda.ua"],
            }
        ],
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 2
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert "Authorization" not in request.headers

    request = responses.calls[1].request
    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == _DigestAuthHeader(
        {
            "username": "user",
            "realm": "auth.yoda.ua",
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
@pytest.mark.parametrize("auth", ["user", "user:"])
def test_store_auth_digest_no_password(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    auth: str,
) -> None:
    """The plugin works for HTTP digest auth even w/o password."""

    responses.add(
        responses.GET,
        "https://yoda.ua",
        status=401,
        headers={
            "WWW-Authenticate": (
                "Digest realm=auth.yoda.ua"
                ',qop="auth,auth-int"'
                ",nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093"
                ",opaque=5ccc069c403ebaf9f0171e9517f40e41"
            )
        },
    )

    store_set(
        bindings=[
            {
                "auth_type": "digest",
                "auth": auth,
                "resources": ["https://yoda.ua"],
            }
        ],
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 2
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert "Authorization" not in request.headers

    request = responses.calls[1].request
    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == _DigestAuthHeader(
        {
            "username": "user",
            "realm": "auth.yoda.ua",
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
def test_store_auth_digest_secret_provider(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    tmp_path: pathlib.Path,
) -> None:
    """The plugin retrieves secrets from secret provider for HTTP digest auth."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("p@ss", encoding="UTF-8")

    responses.add(
        responses.GET,
        "https://yoda.ua",
        status=401,
        headers={
            "WWW-Authenticate": (
                "Digest realm=auth.yoda.ua"
                ',qop="auth,auth-int"'
                ",nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093"
                ",opaque=5ccc069c403ebaf9f0171e9517f40e41"
            )
        },
    )

    store_set(
        bindings=[
            {
                "auth_type": "digest",
                "auth": "user:$PASSWORD",
                "resources": ["https://yoda.ua"],
            }
        ],
        secrets={
            "PASSWORD": {
                "provider": "sh",
                "script": f"cat {secrettxt}",
            }
        },
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 2
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert "Authorization" not in request.headers

    request = responses.calls[1].request
    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == _DigestAuthHeader(
        {
            "username": "user",
            "realm": "auth.yoda.ua",
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
def test_store_auth_bearer(httpie_run: HttpieRunT, store_set: StoreSetT) -> None:
    """The plugin works for HTTP bearer auth."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": ["https://yoda.ua"],
            }
        ],
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_store_auth_bearer_secret_provider(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    tmp_path: pathlib.Path,
) -> None:
    """The plugin retrieves secrets from secret provider for HTTP bearer auth."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("token-can-be-anything", encoding="UTF-8")

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "$TOKEN",
                "resources": ["https://yoda.ua"],
            }
        ],
        secrets={
            "TOKEN": {
                "provider": "sh",
                "script": f"cat {secrettxt}",
            },
        },
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_store_auth_header(httpie_run: HttpieRunT, store_set: StoreSetT) -> None:
    """The plugin works for HTTP header auth."""

    store_set(
        bindings=[
            {
                "auth_type": "header",
                "auth": "X-Auth:value-can-be:anything",
                "resources": ["https://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["X-Auth"] == "value-can-be:anything"


@responses.activate
def test_store_auth_header_secret_provider(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    tmp_path: pathlib.Path,
) -> None:
    """The plugin retrieves secrets from secret provider for HTTP header auth."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("value-can-be:anything", encoding="UTF-8")

    store_set(
        bindings=[
            {
                "auth_type": "header",
                "auth": "X-Auth:$SECRET",
                "resources": ["https://yoda.ua"],
            }
        ],
        secrets={
            "SECRET": {
                "provider": "sh",
                "script": f"cat {secrettxt}",
            },
        },
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["X-Auth"] == "value-can-be:anything"


@responses.activate
def test_store_auth_3rd_party_plugin(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
) -> None:
    """The plugin works for third-party auth plugin."""

    store_set(
        bindings=[
            {
                "auth_type": "hmac",
                "auth": "secret:rice",
                "resources": ["https://yoda.ua"],
            }
        ],
    )

    # The 'Date' request header is supplied to make sure that produced HMAC
    # is always the same.
    httpie_run(["-A", "store", "https://yoda.ua", "Date: Wed, 08 May 2024 00:00:00 GMT"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == "HMAC dGPPAQGIQ4KYgxuZm45G8pUspKI2wx/XjwMBpoMi3Gk="


@responses.activate
def test_store_auth_3rd_party_plugin_secret_provider(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    tmp_path: pathlib.Path,
) -> None:
    """The plugin retrieves secrets from secret provider for third-party auth plugin."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("rice", encoding="UTF-8")

    store_set(
        bindings=[
            {
                "auth_type": "hmac",
                "auth": "secret:$HMAC_SECRET",
                "resources": ["https://yoda.ua"],
            }
        ],
        secrets={
            "HMAC_SECRET": {
                "provider": "sh",
                "script": f"cat {secrettxt}",
            }
        },
    )

    # The 'Date' request header is supplied to make sure that produced HMAC
    # is always the same.
    httpie_run(["-A", "store", "https://yoda.ua", "Date: Wed, 08 May 2024 00:00:00 GMT"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == "HMAC dGPPAQGIQ4KYgxuZm45G8pUspKI2wx/XjwMBpoMi3Gk="


@responses.activate
def test_store_auth_composite_bearer_header(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
) -> None:
    """The plugin works for composite auth."""

    store_set(
        bindings=[
            {
                "auth_type": "composite",
                "auth": [
                    {
                        "auth_type": "bearer",
                        "auth": "token-can-be-anything",
                    },
                    {
                        "auth_type": "header",
                        "auth": "X-Auth:secret-can-be-anything",
                    },
                ],
                "resources": ["https://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"
    assert request.headers["X-Auth"] == "secret-can-be-anything"


@responses.activate
def test_store_auth_composite_header_header(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
) -> None:
    """The plugin supports usage of the same auth provider twice."""

    store_set(
        bindings=[
            {
                "auth_type": "composite",
                "auth": [
                    {
                        "auth_type": "header",
                        "auth": "X-Secret:secret-can-be-anything",
                    },
                    {
                        "auth_type": "header",
                        "auth": "X-Auth:secret-can-be-anything",
                    },
                ],
                "resources": ["https://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["X-Secret"] == "secret-can-be-anything"
    assert request.headers["X-Auth"] == "secret-can-be-anything"


@responses.activate
def test_store_auth_composite_bearer_header_secret_provider(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    tmp_path: pathlib.Path,
) -> None:
    """The plugin retrieves secrets from secret providers for composite auth."""

    tokentxt, secrettxt = tmp_path.joinpath("token.txt"), tmp_path.joinpath("secret.txt")
    tokentxt.write_text("token-can-be-anything", encoding="UTF-8")
    secrettxt.write_text("secret-can-be-anything", encoding="UTF-8")

    store_set(
        bindings=[
            {
                "auth_type": "composite",
                "auth": [
                    {
                        "auth_type": "bearer",
                        "auth": "$TOKEN",
                    },
                    {
                        "auth_type": "header",
                        "auth": "X-Auth:$SECRET",
                    },
                ],
                "resources": ["https://yoda.ua"],
            }
        ],
        secrets={
            "TOKEN": {
                "provider": "sh",
                "script": f"cat {tokentxt}",
            },
            "SECRET": {
                "provider": "sh",
                "script": f"cat {secrettxt}",
            },
        },
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"
    assert request.headers["X-Auth"] == "secret-can-be-anything"


@responses.activate
@pytest.mark.parametrize("auth_type", ["basic", "digest", "bearer", "header", "composite"])
def test_store_auth_required(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    httpie_stderr: io.StringIO,
    auth_type: str,
) -> None:
    """The plugin raises error if auth is missing but required."""

    store_set(
        bindings=[
            {
                "auth_type": auth_type,
                "resources": ["https://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    error_message = (
        f"http: error: ValueError: Broken '{auth_type}' authentication entry: missing 'auth'."
    )

    if _is_windows:
        # The error messages on Windows doesn't contain class names before
        # method names, thus we have to cut them out.
        error_message = re.sub(r"ValueError: \w+\.", "ValueError: ", error_message)

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == error_message


@responses.activate
@pytest.mark.parametrize(
    "resource",
    [
        "https://yoda.ua",
        "https://yoda.ua/",
        "https://yoda.ua/v1",
        "https://yoda.ua/v1/",
    ],
)
def test_store_lookup_subresource(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    resource: str,
) -> None:
    """The plugin uses subresource checking to find authentication binding."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": [resource],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua/v1/subresource"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/v1/subresource"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_store_lookup_scheme_case_insensitive(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
) -> None:
    """The plugin uses case insensitive scheme comparison."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": ["HttPs://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua/v1/subresource"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/v1/subresource"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_store_lookup_hostname_case_insensitive(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
) -> None:
    """The plugin uses case insensitive hostname comparison."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": ["https://yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua/v1/subresource"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/v1/subresource"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_store_lookup_path_case_sensitive(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    httpie_stderr: io.StringIO,
) -> None:
    """The plugin uses case sensitive path comparison."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": ["https://yoda.ua/v1/"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua/V1/subresource"])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        "http: error: LookupError: No binding found for 'https://yoda.ua/V1/subresource'."
    )


@responses.activate
def test_store_lookup_1st_matched_wins(httpie_run: HttpieRunT, store_set: StoreSetT) -> None:
    """The plugin uses auth of first matched binding."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": ["https://yoda.ua"],
            },
            {
                "auth_type": "basic",
                "auth": "user:p@ss",
                "resources": ["https://yoda.ua/v2"],
            },
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua/v2/the-force"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/v2/the-force"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"


@responses.activate
def test_store_lookup_many_bindings(httpie_run: HttpieRunT, store_set: StoreSetT) -> None:
    """The plugin works with many URLs and bindings."""

    responses.add(responses.GET, "https://yoda.ua/about/", status=200)
    responses.add(responses.GET, "https://skywalker.com", status=200)

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": ["https://yoda.ua"],
            },
            {
                "auth_type": "basic",
                "auth": "user:p@ss",
                "resources": ["https://skywalker.com"],
            },
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua/about/"])
    httpie_run(["-A", "store", "https://skywalker.com"])
    assert len(responses.calls) == 2

    request = responses.calls[0].request
    assert request.url == "https://yoda.ua/about/"
    assert request.headers["Authorization"] == "Bearer token-can-be-anything"

    request = responses.calls[1].request
    assert request.url == "https://skywalker.com/"
    assert request.headers["Authorization"] == b"Basic dXNlcjpwQHNz"


@responses.activate
@pytest.mark.parametrize(
    ("resource", "url"),
    [
        pytest.param("http://yoda.ua/", "https://yoda.ua/", id="scheme"),
        pytest.param("https://yoda.ua/", "https://another.com/", id="hostname"),
        pytest.param("https://yoda.ua/v1/", "https://yoda.ua/v2/foo", id="path"),
    ],
)
def test_store_lookup_not_found(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    resource: str,
    url: str,
    httpie_stderr: io.StringIO,
) -> None:
    """The plugin raises error if no auth bindings found."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": [resource],
            }
        ]
    )
    httpie_run(["-A", "store", url])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        f"http: error: LookupError: No binding found for '{url}'."
    )


@responses.activate
def test_store_lookup_missing_resource_scheme(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    httpie_stderr: io.StringIO,
) -> None:
    """The plugin raises error if an auth binding missing scheme."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": ["yoda.ua"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        "http: error: ValueError: Broken binding: missing schema in 'yoda.ua'."
    )


@responses.activate
def test_store_lookup_missing_resource_hostname(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    httpie_stderr: io.StringIO,
) -> None:
    """The plugin raises error if an auth binding missing hostname."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "token-can-be-anything",
                "resources": ["https:///"],
            }
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        "http: error: ValueError: Broken binding: missing hostname in 'https:///'."
    )


@responses.activate
def test_store_lookup_by_id(httpie_run: HttpieRunT, store_set: StoreSetT) -> None:
    """The plugin uses a given credential ID as a hint for 2+ matches."""

    store_set(
        bindings=[
            {
                "id": "yoda",
                "auth_type": "bearer",
                "auth": "i-am-yoda",
                "resources": ["https://yoda.ua"],
            },
            {
                "id": "luke",
                "auth_type": "bearer",
                "auth": "i-am-skywalker",
                "resources": ["https://yoda.ua"],
            },
        ]
    )
    httpie_run(["-A", "store", "https://yoda.ua/about/"])
    httpie_run(["-A", "store", "-a", "luke", "https://yoda.ua/about/"])
    assert len(responses.calls) == 2

    request = responses.calls[0].request
    assert request.url == "https://yoda.ua/about/"
    assert request.headers["Authorization"] == "Bearer i-am-yoda"

    request = responses.calls[1].request
    assert request.url == "https://yoda.ua/about/"
    assert request.headers["Authorization"] == "Bearer i-am-skywalker"


@responses.activate
def test_store_lookup_by_id_error(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    httpie_stderr: io.StringIO,
) -> None:
    """The plugin raises error if no auth binding found."""

    store_set(
        bindings=[
            {
                "id": "yoda",
                "auth_type": "bearer",
                "auth": "i-am-yoda",
                "resources": ["https://yoda.ua"],
            },
            {
                "id": "luke",
                "auth_type": "bearer",
                "auth": "i-am-skywalker",
                "resources": ["https://yoda.ua"],
            },
        ]
    )

    httpie_run(["-A", "store", "-a", "vader", "https://yoda.ua/about/"])
    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        "http: error: LookupError: No binding found for 'https://yoda.ua/about/'."
    )


@responses.activate
def test_store_lookup_missing_secret(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    httpie_stderr: io.StringIO,
) -> None:
    """The plugin uses case sensitive path comparison."""

    store_set(
        bindings=[
            {
                "auth_type": "bearer",
                "auth": "$TOKEN",
                "resources": ["https://yoda.ua/"],
            }
        ],
    )
    httpie_run(["-A", "store", "https://yoda.ua/"])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        "http: error: ValueError: Broken authentication entry: missing secret: TOKEN."
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
def test_store_permissions_safe(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    mode: int,
) -> None:
    """The plugin doesn't complain if auth store has safe permissions."""

    store_set(
        bindings=[
            {
                "auth_type": "basic",
                "auth": "user:p@ss",
                "resources": ["https://yoda.ua"],
            }
        ],
        mode=mode,
    )
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.url == "https://yoda.ua/"
    assert request.headers["Authorization"] == b"Basic dXNlcjpwQHNz"


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
def test_store_permissions_unsafe(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    mode: int,
    httpie_stderr: io.StringIO,
    auth_store_path: pathlib.Path,
) -> None:
    """The plugin complains if auth store has unsafe permissions."""

    store_set(bindings=[], mode=mode)
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert httpie_stderr.getvalue().strip() == (
        f"http: error: PermissionError: Permissions {mode:04o} for "
        f"'{auth_store_path}' are too open. Authentication store MUST NOT "
        f"be accessible by others."
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
def test_store_permissions_not_enough(
    httpie_run: HttpieRunT,
    store_set: StoreSetT,
    mode: int,
    httpie_stderr: io.StringIO,
    auth_store_path: pathlib.Path,
) -> None:
    """The plugin complains if auth store has unsafe permissions."""

    store_set(bindings=[], mode=mode)
    httpie_run(["-A", "store", "https://yoda.ua"])

    assert httpie_stderr.getvalue().strip() == (
        f"http: error: PermissionError: Permissions {mode:04o} for "
        f"'{auth_store_path}' are too close. Authentication store MUST be "
        f"readabe by you."
    )


@responses.activate
def test_store_auth_no_database(
    httpie_run: HttpieRunT,
    auth_store_path: pathlib.Path,
    httpie_stderr: io.StringIO,
) -> None:
    """The plugin raises error if auth store does not exist."""

    httpie_run(["-A", "store", "https://yoda.ua"])

    assert len(responses.calls) == 0
    assert httpie_stderr.getvalue().strip() == (
        f"http: error: FileNotFoundError: Authentication store is not found: '{auth_store_path}'."
    )
