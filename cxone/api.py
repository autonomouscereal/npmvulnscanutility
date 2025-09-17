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
        self._have_group_index = False

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

    def get_project(self, project_id: str) -> Dict[str, Any]:
        """Fetch full project details (includes rich group data)."""
        url = f"{self._api_base_url}/projects/{project_id}"
        _logger.debug("GET %s", url)
        return self._get_json(url)

    def list_groups(self, *, limit: int = 1000) -> List[Dict[str, Any]]:
        """Retrieve all groups for the tenant (paginated) and cache them.

        Endpoint: ``GET /access-management/groups`` supports pagination via
        ``offset`` / ``limit``; we loop until the returned slice is < limit.
        """
        groups: List[Dict[str, Any]] = []
        offset = 0
        while True:
            url = f"{self._api_base_url}/access-management/groups?offset={offset}&limit={limit}"
            _logger.debug("GET %s", url)
            data = self._get_json(url)
            if not isinstance(data, list):
                break
            groups.extend(data)
            if len(data) < limit:
                break
            offset += limit

        # Cache results for quick lookup
        for g in groups:
            gid = g.get("id")
            if gid:
                self._group_cache[gid] = g
        self._have_group_index = True
        return groups

    def get_group(self, group_id: str) -> Dict[str, Any]:
        """Return group details (name, full path, etc.) for the provided ID.

        Uses local cache; falls back to API call if not present.
        """
        if group_id in self._group_cache:
            return self._group_cache[group_id]

        # If we have already indexed all groups and ID not found, just return stub
        if self._have_group_index:
            return {"id": group_id}

        # Use search by ids query parameter (supports comma-separated list)
        url = f"{self._api_base_url}/access-management/groups?ids={group_id}"
        _logger.debug("GET %s", url)
        data = self._get_json(url)
        # The endpoint returns an *array*
        if isinstance(data, list) and data:
            data = data[0]
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

    # ------------------------------------------------------------------ #
    # Repos manager / SCM import                                         #
    # ------------------------------------------------------------------ #

    def import_scm_projects(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Import and optionally scan SCM projects in bulk.

        This wraps the `POST /repos-manager/scm-projects` endpoint which accepts
        up to N projects per request. The caller is responsible for batching.

        Parameters
        ----------
        payload:
            The full JSON payload as described by the API (contains
            `scm`, `organization`, `defaultProjectSettings`,
            `scanProjectsAfterImport`, and `projects`).
        """
        url = f"{self._api_base_url}/repos-manager/scm-projects"
        headers = {
            "Accept": "application/json; version=1.0",
            "Content-Type": "application/json; version=1.0",
            **self._session.auth_header(),
        }
        _logger.debug("POST %s (projects=%s)", url, len(payload.get("projects", [])))
        resp = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=self._timeout,
            verify=self._verify_ssl,
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"status": resp.status_code, "text": resp.text}