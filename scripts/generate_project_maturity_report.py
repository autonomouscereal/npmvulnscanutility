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


def _extract_findings(result_json: Dict[str, any]) -> List[Dict[str, any]]:
    """Return list of finding dictionaries irrespective of schema version."""
    if "queries" in result_json:
        # legacy schema
        findings: List[Dict[str, any]] = []
        for q in result_json["queries"]:
            findings.extend(q.get("results", []))
        return findings
    if "findings" in result_json:
        return result_json["findings"]  # modern key
    # Fallback: try nested structure
    if "results" in result_json and isinstance(result_json["results"], list):
        return result_json["results"]
    return []


def _findings_have_comments(findings: List[Dict[str, any]]) -> bool:
    """Return True if at least one finding has comments."""
    for f in findings:
        if f.get("commentsCount", 0) > 0 or f.get("comments"):
            return True
    return False


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

    # ------------------------------ Level 3 & count findings
    scan_id = latest_scans[0]["id"]
    results_latest = api.get_sast_results(scan_id)
    findings_latest = _extract_findings(results_latest)
    finding_count_latest = len(findings_latest)

    level = 2  # default once we know at least one scan exists
    if _findings_have_comments(findings_latest):
        level = 3

    # ------------------------------ Level 4 comparison
    if len(latest_scans) >= 2:
        prev_scan_id = latest_scans[1]["id"]
        prev_results = api.get_sast_results(prev_scan_id)
        findings_prev = _extract_findings(prev_results)
        if findings_prev and len(findings_latest) < len(findings_prev):
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

    # Preload all groups to build mapping id -> object (name/path)
    api.list_groups()

    with open(CSV_FILENAME, mode="w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=CSV_HEADERS)
        writer.writeheader()

        for project in projects:
            project_id = project["id"]
            scans = api.get_latest_scans(project_id)
            level = determine_maturity_level(api, project_id, scans)

            # -------------------- Resolve group names --------------------
            group_str = ""
            try:
                project_full = api.get_project(project_id)
                grp_objs = project_full.get("groups", [])
                if grp_objs and isinstance(grp_objs[0], dict):
                    group_str = " | ".join(
                        g.get("fullName") or g.get("fullPath") or g.get("name") or g.get("id")
                        for g in grp_objs
                    )
                elif grp_objs:
                    # grp_objs is list of IDs – resolve
                    group_names: List[str] = []
                    for gid in grp_objs:
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
                    group_str = " | ".join(group_names)
            except Exception:  # pylint: disable=broad-except
                pass
            if not group_str:
                group_str = project.get("groupName") or project.get("groupPath") or ""

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
