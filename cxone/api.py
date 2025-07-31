"""
api.py
======

Light-weight wrapper around the CxOne REST API required for
report generation tasks.

Only a subset of endpoints is implemented – just enough to:
    * list projects
    * obtain latest scans
    * retrieve SAST results

If you need additional endpoints add a new method and update the
TODO.md file accordingly.
"""

from __future__ import annotations

import logging as _logging
from typing import Any, Dict, List

import requests

from .session import CxOneSession

_logger = _logging.getLogger(__name__)
_logger.addHandler(_logging.NullHandler())


class CxOneAPI:
    """Provide convenience methods for the CxOne REST API."""

    def __init__(
        self,
        session: CxOneSession,
        api_base_url: str,
        *,
        verify_ssl: bool = True,
        timeout: int = 15,
    ) -> None:
        """Create a new API helper.

        Parameters
        ----------
        session:
            An authenticated :class:`CxOneSession`.
        api_base_url:
            Base URL for the REST API including the ``/api/`` suffix, e.g. ``https://cxone-preprod/api/``.
        verify_ssl:
            Whether to verify SSL certificates.
        timeout:
            Request timeout in seconds.
        """
        self._session = session
        self._api_base_url = api_base_url.rstrip("/")
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        # Cache to avoid redundant API calls when resolving group names
        self._group_cache: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Public high-level helpers                                          #
    # ------------------------------------------------------------------ #

    def list_projects(self, offset: int = 0, limit: int = 1000) -> List[Dict[str, Any]]:
        """Return a list with all projects visible to the current tenant."""
        url = f"{self._api_base_url}/projects/?offset={offset}&limit={limit}"
        _logger.debug("GET %s", url)
        return self._get_json(url).get("projects", [])

    def get_latest_scans(
        self, project_id: str, *, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Return the latest *limit* scans for the specified project ID."""
        url = (
            f"{self._api_base_url}/projects/last-scan"
            f"?offset=0&limit={limit}&project-ids={project_id}"
        )
        _logger.debug("GET %s", url)
        return self._get_json(url).get("scans", [])

    def get_sast_results(self, scan_id: str) -> Dict[str, Any]:
        """Return SAST results for the provided scan identifier."""
        url = f"{self._api_base_url}/sast-results/?scan-id={scan_id}"
        _logger.debug("GET %s", url)
        return self._get_json(url)

    def get_group(self, group_id: str) -> Dict[str, Any]:
        """Return group details (name, full path, etc.) for the provided ID.

        Results are cached per instance to minimise network usage because the same
        group is often referenced by many projects.
        """
        if group_id in self._group_cache:
            return self._group_cache[group_id]

        url = f"{self._api_base_url}/groups/{group_id}"
        _logger.debug("GET %s", url)
        data = self._get_json(url)
        self._group_cache[group_id] = data
        return data

    # ------------------------------------------------------------------ #
    # Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    def _get_json(self, url: str) -> Dict[str, Any]:
        headers = {"Accept": "application/json", **self._session.auth_header()}
        resp = requests.get(
            url,
            headers=headers,
            timeout=self._timeout,
            verify=self._verify_ssl,
        )
        resp.raise_for_status()
        return resp.json()
