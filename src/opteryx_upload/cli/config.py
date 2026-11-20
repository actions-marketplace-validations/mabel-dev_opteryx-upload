"""Where the CLI gets its credentials, its URL, and its exit codes.

Exit codes are part of the interface. A pipeline that has to grep stderr to find
out whether an upload was refused because the data was wrong or because the
token was is a pipeline that will eventually retry the wrong one, so each
category the caller might act on differently gets its own number.
"""

from __future__ import annotations

import os
from typing import Optional

from ..auth import DEFAULT_AUTH_URL
from ..auth import DEFAULT_OIDC_AUDIENCE
from ..auth import GitHubOIDCAuthenticator
from ..auth import PATAuthenticator
from ..client import DEFAULT_BASE_URL
from ..client import ContractClient
from ..client import TokenLike
from ..exceptions import AuthenticationError
from ..exceptions import AuthorizationError
from ..exceptions import ContractError
from ..exceptions import ContractStale
from ..exceptions import InternalError
from ..exceptions import NotAuthorized
from ..exceptions import UploadClientError

# ---- exit codes -----------------------------------------------------------

OK = 0
#: The command was wrong: bad arguments, a file that is not there, no token.
USAGE = 2
#: The service refused the upload on its merits - a type that will not cast, two
#: files that disagree, a column nobody declared. Retrying will not help.
REFUSED = 3
#: The target moved after the contract was agreed. Retrying WILL help, which is
#: why it is not `REFUSED`: re-negotiating against the new definition is the fix.
STALE = 4
#: Not signed in, or signed in as somebody who may not write here.
DENIED = 5
#: The service could not be reached, or answered with something unusable.
UNAVAILABLE = 6
#: Ctrl-C. Conventional, and it matters here because an interrupted upload
#: leaves an abandonable contract rather than a half-published dataset.
INTERRUPTED = 130


def exit_code_for(error: BaseException) -> int:
    """Map an exception to the number the shell sees."""
    if isinstance(error, InternalError):
        # The service broke, which is not the upload being refused. Retrying a
        # refusal never helps and retrying this often does, so they must not
        # share a number.
        return UNAVAILABLE
    if isinstance(error, ContractStale):
        return STALE
    if isinstance(error, (NotAuthorized, AuthenticationError, AuthorizationError)):
        return DENIED
    if isinstance(error, ContractError):
        return REFUSED
    if isinstance(error, UploadClientError):
        return UNAVAILABLE
    return USAGE


# ---- environment ----------------------------------------------------------

ENV_URL = "OPTERYX_UPLOAD_URL"
ENV_TOKEN = "OPTERYX_TOKEN"
ENV_CLIENT_ID = "OPTERYX_CLIENT_ID"
ENV_CLIENT_SECRET = "OPTERYX_CLIENT_SECRET"
ENV_AUTH_URL = "OPTERYX_AUTH_URL"
ENV_OIDC_AUDIENCE = "OPTERYX_OIDC_AUDIENCE"


class ConfigError(Exception):
    """Something the caller can fix by changing the command or the environment."""


def base_url(explicit: Optional[str] = None) -> str:
    return (explicit or os.environ.get(ENV_URL) or DEFAULT_BASE_URL).rstrip("/")


def build_client(
    *,
    url: Optional[str] = None,
    token: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    oidc: bool = False,
    timeout: float = 300.0,
) -> ContractClient:
    """A client, or a `ConfigError` naming the variable that would fix it.

    An access token - a username and a token - wins over an ambient
    `OPTERYX_TOKEN`. A bearer assertion expires in minutes and an upload can
    take longer than that, so a static one is refused part way through with rows
    already staged; an access token is re-exchanged as it ages, and the client
    resolves it per request.

    `--token` still wins when passed explicitly - a CI job that already holds a
    valid assertion should not have it ignored. Only the ambient variable loses.

    Neither is read from a file: a token on disk is a token in a backup, and the
    shells and CI systems that run this all have a way to hold a secret that is
    not a file in the repository.

    In GitHub Actions with `id-token: write` there is a fourth option and it is
    the best one, because there is no secret to hold at all: the job asks GitHub
    for a signed token saying which workflow it is. That is used automatically
    when nothing else was configured, and `oidc=True` demands it - a workflow
    that meant to authenticate as itself and silently fell back to an ambient
    variable would be a surprise worth an error.
    """
    explicit_token = token
    token = token or os.environ.get(ENV_TOKEN)
    client_id = client_id or os.environ.get(ENV_CLIENT_ID)
    client_secret = client_secret or os.environ.get(ENV_CLIENT_SECRET)
    audience = os.environ.get(ENV_OIDC_AUDIENCE) or DEFAULT_OIDC_AUDIENCE
    auth_url = os.environ.get(ENV_AUTH_URL) or DEFAULT_AUTH_URL

    if oidc:
        if not GitHubOIDCAuthenticator.is_available():
            raise ConfigError(
                "--oidc needs GitHub Actions to mint a token, and this job cannot: "
                "ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are "
                "not set. Add `permissions: id-token: write` to the job."
            )
        credential: TokenLike = GitHubOIDCAuthenticator(audience=audience, auth_url=auth_url)
    elif client_id and client_secret and not explicit_token:
        credential = PATAuthenticator(
            client_id=client_id,
            client_secret=client_secret,
            auth_url=auth_url,
        )
    elif token:
        credential = token
    elif client_id or client_secret:
        missing = ENV_CLIENT_SECRET if client_id else ENV_CLIENT_ID
        raise ConfigError(f"an access token needs a username too; {missing} is not set")
    elif GitHubOIDCAuthenticator.is_available():
        # Nothing was configured and we are in a job that can prove who it is.
        credential = GitHubOIDCAuthenticator(audience=audience, auth_url=auth_url)
    else:
        raise ConfigError(
            f"no credentials: set {ENV_CLIENT_ID} and {ENV_CLIENT_SECRET}, or {ENV_TOKEN}, "
            "or run in GitHub Actions with `permissions: id-token: write`"
        )

    return ContractClient(token=credential, base_url=base_url(url), timeout=timeout)
