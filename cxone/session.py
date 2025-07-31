"""
session.py
==========

Contains :class:`CxOneSession` responsible for handling
authentication against the Checkmarx One (CxOne) platform.

The session exchanges a Personal Access Token (PAT) / refresh token
for a short-lived access token and transparently renews the token
whenever it has expired.

Every public method and attribute is documented – search for
``def`` and ``property`` in this file for details.
"""

from __future__ import annotations

import datetime as _dt
import logging as _logging
import threading as _threading
from typing import Any, Dict, Optional

import requests

_logger = _logging.getLogger(__name__)
_logger.addHandler(_logging.NullHandler())


class CxOneSession:
    """Handle authentication and token refresh logic for CxOne.
    The class is thread-safe – a lock protects token renewal.
    """

    _TOKEN_PATH = "protocol/openid-connect/token"

    def __init__(
        self,
        token_base_url: str,
        tenant: str,
        refresh_token: str,
        client_id: str = "ast-app",
        verify_ssl: bool = True,
        timeout: int = 15,
    ) -> None:
        """Create a new authenticated session.

        Parameters
        ----------
        token_base_url:
            Base URL where the realm lives, e.g. ``https://cxone-preprod/auth/realms``.
            **Do not** include the tenant segment.
        tenant:
            CxOne tenant / realm, e.g. ``cxone-preprod``.
        refresh_token:
            Personal access / refresh token generated on the CxOne portal.
        client_id:
            OAuth client ID to use. The default value ``ast-app`` is the value used
            by the PowerShell scripts we are migrating from.
        verify_ssl:
            Whether to verify SSL certificates. Set to ``False`` for on-prem PoCs.
        timeout:
            Request timeout in seconds.
        """
        self._token_base_url = token_base_url.rstrip("/")
        self._tenant = tenant
        self._refresh_token = refresh_token
        self._client_id = client_id
        self._verify_ssl = verify_ssl
        self._timeout = timeout

        # Mutable fields that change after login
        self._token_type: Optional[str] = None
        self._access_token: Optional[str] = None
        self._expires_at: _dt.datetime | None = None

        # Lock protects token refresh in multi-threaded contexts
        self._lock = _threading.Lock()

        # Perform initial login so that the instance is ready to use
        self._login()

    # ---------------------------------------------------------------------#
    # Public API                                                           #
    # ---------------------------------------------------------------------#

    def auth_header(self) -> Dict[str, str]:
        """Return a valid HTTP ``Authorization`` header.

        The header is refreshed automatically if the current token
        is close to expiry.
        """
        self._ensure_valid_token()
        return {"Authorization": f"{self._token_type} {self._access_token}"}

    # ---------------------------------------------------------------------#
    # Internal helpers                                                     #
    # ---------------------------------------------------------------------#

    def _ensure_valid_token(self) -> None:
        """Refresh the token if expiry is < 30 seconds away."""
        if self._expires_at is None or self._access_token is None:
            # Should not happen – treat as not logged in
            _logger.debug("Token not present – performing login.")
            self._login()
            return

        # Renew if we are *about* to expire
        if _dt.datetime.utcnow() >= self._expires_at - _dt.timedelta(seconds=30):
            _logger.debug("Token is expired / about to expire – refreshing.")
            with self._lock:
                # Another thread might have refreshed meanwhile
                if _dt.datetime.utcnow() < self._expires_at - _dt.timedelta(seconds=30):
                    return
                self._login()

    def _login(self) -> None:
        """Exchange the refresh token for an access token."""
        token_url = self._build_token_url()
        payload = {
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "refresh_token": self._refresh_token,
        }

        _logger.debug("Requesting token from %s", token_url)
        resp = requests.post(
            token_url,
            data=payload,
            timeout=self._timeout,
            verify=self._verify_ssl,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()

        data: Dict[str, Any] = resp.json()

        self._token_type = data["token_type"]
        self._access_token = data["access_token"]
        # `expires_in` is seconds from *now*
        expires_in = int(data.get("expires_in", 300))
        self._expires_at = _dt.datetime.utcnow() + _dt.timedelta(seconds=expires_in)

        _logger.info(
            "Authenticated successfully as tenant '%s'. "
            "Token valid for %s seconds.",
            self._tenant,
            expires_in,
        )

    def _build_token_url(self) -> str:
        """Construct the absolute token endpoint URL.

        Returns
        -------
        str
            e.g. ``https://cxone-preprod/auth/realms/cxone-preprod/protocol/openid-connect/token``.
        """
        return f"{self._token_base_url}/{self._tenant}/{self._TOKEN_PATH}"
