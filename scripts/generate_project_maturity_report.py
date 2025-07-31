#!/usr/bin/env python3
"""
Generate a CSV report with CxOne projects and their maturity level.

The script produces ``project_maturity_report.csv`` with the following columns:

1. Group (hierarchy path)
2. Project name
3. Maturity level (2, 3 or 4 – see README for definitions)

A basic heuristic is used:

* Level 2 – default when at least one scan exists.
* Level 3 – at least one finding has a non-zero comment count.
* Level 4 – vulnerability count went down between the latest and the previous scan.

The thresholds/heuristics can be refined in the future – see ``TODO.md`` for ideas.
"""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from typing import Dict, List

import requests
from dotenv import load_dotenv

# Make cxone package importable when script is executed from root dir
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT_DIR))

from cxone import CxOneAPI, CxOneSession  # noqa: E402  pylint: disable=wrong-import-position

CSV_HEADERS = ["group", "project_name", "maturity_level"]
CSV_FILENAME = "project_maturity_report.csv"


def determine_maturity_level(
    api: CxOneAPI, project_id: str, latest_scans: List[Dict[str, str]]
) -> int:
    """Determine the maturity level for a single project.

    Parameters
    ----------
    api:
        An authenticated API helper.
    project_id:
        ID of the project being analysed.
    latest_scans:
        Output of :py:meth:`CxOneAPI.get_latest_scans`.

    Returns
    -------
    int
        2, 3 or 4 as per maturity definitions.
    """
    if not latest_scans:
        # No scans at all - treat as Level 1 (out of scope) but keep 2 for now
        return 2

    # ------------------------------------------------------------ Level 3
    scan_id = latest_scans[0]["id"]
    results = api.get_sast_results(scan_id)

    findings = results.get("queries", [])
    any_comment = False
    finding_count_latest = 0
    for q in findings:
        for r in q.get("results", []):
            finding_count_latest += 1
            if r.get("commentsCount", 0) > 0:
                any_comment = True

    if any_comment:
        # Could still qualify for level 4 – evaluate further
        level = 3
    else:
        level = 2

    # ------------------------------------------------------------ Level 4
    # Need at least two scans
    if len(latest_scans) >= 2:
        prev_scan_id = latest_scans[1]["id"]
        prev_results = api.get_sast_results(prev_scan_id)

        prev_findings = prev_results.get("queries", [])
        finding_count_prev = sum(
            len(q.get("results", [])) for q in prev_findings
        )

        if finding_count_prev > 0 and finding_count_latest < finding_count_prev:
            level = 4

    return level


def main() -> None:
    """Entry-point for CLI execution."""
    # Load .env from project root irrespective of the current working directory
    from dotenv import find_dotenv
    load_dotenv(find_dotenv())

    # Mandatory environment variables: see README.md
    token_base_url = os.getenv("CXONE_TOKEN_BASE_URL")
    tenant = os.getenv("CXONE_TENANT")
    refresh_token = os.getenv("CXONE_REFRESH_TOKEN")
    api_base_url = os.getenv("CXONE_API_BASE_URL")
    client_id = os.getenv("CXONE_CLIENT_ID", "ast-app")

    if not all([token_base_url, tenant, refresh_token, api_base_url]):
        print(
            "ERROR: Some required environment variables are missing. "
            "See README.md for details.",
            file=sys.stderr,
        )
        sys.exit(1)

    verify_ssl = os.getenv("CXONE_VERIFY_SSL", "true").lower() not in {"0", "false", "no"}

    session = CxOneSession(
        token_base_url=token_base_url,
        tenant=tenant,
        refresh_token=refresh_token,
        client_id=client_id,
        verify_ssl=verify_ssl,
    )
    api = CxOneAPI(session=session, api_base_url=api_base_url, verify_ssl=verify_ssl)

    projects = api.list_projects()
    print(f"Discovered {len(projects)} projects")

    with open(CSV_FILENAME, mode="w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=CSV_HEADERS)
        writer.writeheader()

        for project in projects:
            project_id = project["id"]
            scans = api.get_latest_scans(project_id)
            level = determine_maturity_level(api, project_id, scans)

            # -------------------- Resolve group names --------------------
            group_ids = project.get("groups") or []
            group_names: List[str] = []
            for gid in group_ids:
                try:
                    group_info = api.get_group(gid)
                    group_names.append(
                        group_info.get("fullName")
                        or group_info.get("fullPath")
                        or group_info.get("name")
                        or gid
                    )
                except Exception:  # pylint: disable=broad-except
                    group_names.append(gid)

            group_str = " | ".join(group_names) if group_names else (
                project.get("groupName") or project.get("groupPath") or ""
            )

            writer.writerow(
                {
                    "group": group_str,
                    "project_name": project["name"],
                    "maturity_level": level,
                }
            )

    print(f"Report written to {CSV_FILENAME}")


if __name__ == "__main__":
    main()
