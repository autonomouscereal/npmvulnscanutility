# scan_org_npm_supply_chain.py


import os
import json
import re
import base64
import csv
import time
import logging
import threading
import queue
import concurrent.futures as futures
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, Set, List
import requests
import certifi  # used as fallback
from dotenv import load_dotenv
from cxone.session import CxOneSession
from cxone.api import CxOneAPI
from tqdm import tqdm
from tls_helper import auto_fetch_and_trust_cert
import markdown as md

load_dotenv()

# Config from env
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_API_BASE = os.getenv("GITHUB_API_BASE", "https://api.github.com")
GITHUB_ORG = os.getenv("GITHUB_ORG")
BAD_PACKAGES_FILE = os.getenv("BAD_PACKAGES_FILE", "bad_packages.json")
def _safe_output_dir_from_env() -> str:
    # Prefer explicit env; if empty or a drive root ('/' or 'C:\\'), fall back to current dir
    raw = os.getenv("OUTPUT_DIR")
    if not raw or not raw.strip():
        return "."
    candidate = raw.strip()
    ap = os.path.abspath(candidate)
    # Root paths have dirname == path; avoid writing to drive root by default
    if os.path.dirname(ap) == ap:
        return "."
    return candidate

OUTPUT_DIR = _safe_output_dir_from_env()
LOG_FILE_ENV = os.getenv("LOG_FILE")
LOG_FILE = LOG_FILE_ENV if (LOG_FILE_ENV and LOG_FILE_ENV.strip()) else os.path.join(OUTPUT_DIR, "scan.log")
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"

# GitHub Enterprise base (used to build repo URLs for CxOne import)
# Example concat: f"{GITHUB_SCM_BASE_URL}/{owner}/{repo}" -> https://git.{org}.{govagency}.gov/owner/repo
GITHUB_SCM_BASE_URL = os.getenv("GITHUB_SCM_BASE_URL")

# Optional mapping of login -> email: <login>@CONTACT_EMAIL_DOMAIN
CONTACT_EMAIL_DOMAIN = os.getenv("CONTACT_EMAIL_DOMAIN")
ENABLE_REPO_DETAILS = os.getenv("ENABLE_REPO_DETAILS", "1") == "1"
ENABLE_PER_REPO_MD = os.getenv("ENABLE_PER_REPO_MD", "1") == "1"
TOP_CONTRIBUTORS = int(os.getenv("TOP_CONTRIBUTORS", "5"))
SCAN_MAX_WORKERS = int(os.getenv("SCAN_MAX_WORKERS", "8"))
IMPORT_SEVERITIES = [s.strip().upper() for s in os.getenv("IMPORT_SEVERITIES", "P1,P2").split(",") if s.strip()]
ENABLE_SARIF = os.getenv("ENABLE_SARIF", "1") == "1"
ENABLE_HTML = os.getenv("ENABLE_HTML", "1") == "1"
ENABLE_CHECKPOINTS = os.getenv("ENABLE_CHECKPOINTS", "1") == "1"

if not GITHUB_TOKEN or not GITHUB_ORG:
    raise SystemExit("GITHUB_TOKEN and GITHUB_ORG are required in .env")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Logging config: console + rotating file
logger = logging.getLogger("npm_scanner")
logger.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(fmt)
logger.addHandler(ch)

fh = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
fh.setLevel(logging.DEBUG)
fh.setFormatter(fmt)
logger.addHandler(fh)

# ===== TLS auto-fetch & trust integration =====
GITHUB_SSL_NO_VERIFY = os.getenv("GITHUB_SSL_NO_VERIFY", "0") == "1"
GITHUB_SSL_CA_BUNDLE = os.getenv("GITHUB_SSL_CA_BUNDLE")
AUTO_FETCH_SERVER_CERT = os.getenv("AUTO_FETCH_SERVER_CERT", "1") == "1"
AUTO_TRUST_FETCHED_CERT = os.getenv("AUTO_TRUST_FETCHED_CERT", "1") == "1"

verify_setting = None

if GITHUB_SSL_NO_VERIFY:
    logger.warning("GITHUB_SSL_NO_VERIFY=1 => SSL verification DISABLED (insecure).")
    verify_setting = False
else:
    if GITHUB_SSL_CA_BUNDLE and os.path.isfile(GITHUB_SSL_CA_BUNDLE):
        logger.info("Using explicit CA bundle from GITHUB_SSL_CA_BUNDLE: %s", GITHUB_SSL_CA_BUNDLE)
        verify_setting = GITHUB_SSL_CA_BUNDLE
    else:
        if AUTO_FETCH_SERVER_CERT:
            try:
                fetched = auto_fetch_and_trust_cert(GITHUB_API_BASE, OUTPUT_DIR, auto_trust=AUTO_TRUST_FETCHED_CERT)
                if fetched:
                    logger.info("Auto-fetched certificate and using it for TLS verification: %s", fetched)
                    verify_setting = fetched
                else:
                    logger.info("Auto-fetch ran but AUTO_TRUST_FETCHED_CERT is False; falling back.")
            except Exception as e:
                logger.warning("Auto-fetch cert failed: %s", e)

        if verify_setting is None:
            try:
                verify_setting = certifi.where()
                logger.info("Falling back to certifi CA bundle: %s", verify_setting)
            except Exception:
                logger.warning("certifi not available; will set verify=False (INSECURE)")
                verify_setting = False

# Create requests session and apply verify
session = requests.Session()
session.verify = verify_setting
session.headers.update({
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "gov-org-npm-scanner/1.0"
})
logger.debug("requests.Session created; session.verify=%s", session.verify)
# Suppress SSL warnings globally if verification is disabled
try:
    if session.verify is False:
        import urllib3  # type: ignore
        urllib3.disable_warnings(getattr(urllib3.exceptions, "InsecureRequestWarning"))
        # Some environments vendor urllib3 under requests.packages
        try:
            requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
                requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
            )
        except Exception:
            pass
        logger.warning("SSL verification disabled for GitHub; InsecureRequestWarning suppressed.")
except Exception:
    pass
# ============================================================

 

#--------------------------------
# Load bad packages list (list of {"name": "...", "versions": ["1.2.3", ...]})
# Load primary bad packages list
with open(BAD_PACKAGES_FILE, "r", encoding="utf-8") as f:
    bad_packages_raw = json.load(f)

# Merge optional feeds (same schema) but primary JSON remains the source of truth
extra_feeds = []
if os.getenv("BAD_FEED_URLS"):
    for feed in [x.strip() for x in os.getenv("BAD_FEED_URLS", "").split(",") if x.strip()]:
        try:
            if re.match(r"^https?://", feed, re.IGNORECASE):
                r = requests.get(feed, timeout=20, verify=session.verify)  # type: ignore[name-defined]
                r.raise_for_status()
                extra_feeds.extend(r.json())
            else:
                with open(feed, "r", encoding="utf-8") as ef:
                    extra_feeds.extend(json.load(ef))
            logger.info("Loaded optional feed: %s (items=%s)", feed, len(extra_feeds))
        except Exception as _ex:
            logger.warning("Failed loading optional feed %s: %s", feed, _ex)

merged_bad = {item["name"]: set(item.get("versions", [])) for item in bad_packages_raw}
for item in extra_feeds:
    try:
        merged_bad.setdefault(item["name"], set()).update(item.get("versions", []))
    except Exception:
        continue

bad_map: Dict[str, Set[str]] = merged_bad

logger.info(f"Loaded {len(bad_map)} watched packages from {BAD_PACKAGES_FILE}")

# Helper: GitHub pagination GET
def gh_get(url, params=None):
    params = params or {}
    logger.debug("HTTP GET %s params=%s", url, params)
    resp = session.get(url, params=params, timeout=30)
    if resp.status_code == 403 and 'rate limit' in resp.text.lower():
        reset = int(resp.headers.get("X-RateLimit-Reset", time.time()+60))
        wait = max(reset - int(time.time()), 10)
        logger.warning(f"Rate limited. Sleeping {wait}s")
        time.sleep(wait)
        resp = session.get(url, params=params, timeout=30)
        logger.debug("Retry HTTP GET %s -> %s", url, resp.status_code)
    # Adaptive backoff if remaining is critically low
    try:
        rem = int(resp.headers.get("X-RateLimit-Remaining", "10"))
        if rem <= 1:
            reset = int(resp.headers.get("X-RateLimit-Reset", time.time()+15))
            wait = max(reset - int(time.time()), 5)
            logger.warning("Near rate limit. Sleeping %ss", wait)
            time.sleep(wait)
    except Exception:
        pass
    logger.debug("HTTP %s -> %s", url, resp.status_code)
    resp.raise_for_status()
    return resp

# Get all repos for org
def list_org_repos(org) -> List[Dict]:
    logger.info(f"Enumerating repositories for org: {org}")
    repos = []
    url = f"{GITHUB_API_BASE}/orgs/{org}/repos"
    params = {"per_page": 100, "type": "all"}
    while url:
        r = gh_get(url, params=params)
        page = r.json()
        repos.extend(page)
        url = r.links.get("next", {}).get("url")
        logger.debug(f"Fetched {len(page)} repos page; total so far {len(repos)}")
    logger.info(f"Found {len(repos)} repositories in org {org}")
    return repos

# Detect versions in package-lock.json or package.json content
def parse_package_json(text: str) -> Dict[str, str]:
    try:
        pj = json.loads(text)
    except Exception:
        return {}
    deps = {}
    for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if sec in pj and isinstance(pj[sec], dict):
            deps.update(pj[sec])
    return deps

def find_versions_in_package_lock(text: str, pkg_name: str) -> Set[str]:
    versions = set()
    try:
        lk = json.loads(text)
    except Exception:
        return versions
    # npm v1/v2 difference handling
    # v1: dependencies nested; v2+: packages map
    if isinstance(lk, dict):
        if "packages" in lk:
            for key, info in lk.get("packages", {}).items():
                name = key.split("/")[-1]
                if name == pkg_name and isinstance(info, dict) and info.get("version"):
                    versions.add(info["version"])
        if "dependencies" in lk:
            def recurse(node):
                for name, vinfo in (node or {}).items():
                    if name == pkg_name and isinstance(vinfo, dict) and vinfo.get("version"):
                        versions.add(vinfo["version"])
                    if isinstance(vinfo, dict) and "dependencies" in vinfo:
                        recurse(vinfo["dependencies"])
            recurse(lk["dependencies"])
    return versions

# Find versions in yarn.lock/pnpm locks (basic heuristic)
def find_versions_in_text_lock(text: str, pkg_name: str) -> Set[str]:
    versions = set()
    # look for e.g. "package-name@^1.2.3:" then version: "version \"1.2.3\""
    # or lines like package-name@1.2.3:
    # We'll do a simple regex for version patterns near name
    for m in re.finditer(rf'(^|\n)(?:["\']?{re.escape(pkg_name)}["\']?(?:@[^:\s,]+)*):\s*', text):
        block_start = m.end()
        block = text[block_start:block_start+300]
        v = re.search(r'version\s*[:=]\s*["\']?([0-9A-Za-z\.\-\+]+)["\']?', block)
        if v:
            versions.add(v.group(1))
    # fallback: directly search for e.g. package-name@1.2.3
    for m in re.finditer(rf'{re.escape(pkg_name)}@([0-9]+\.[0-9A-Za-z\.\-\+]+)', text):
        versions.add(m.group(1))
    return versions


def _parse_codeowners(owner: str, repo_name: str) -> List[str]:
    """Return potential contacts from CODEOWNERS file as GitHub logins."""
    candidates = [
        ".github/CODEOWNERS",
        "CODEOWNERS",
    ]
    logins: List[str] = []
    for p in candidates:
        try:
            content_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/contents/{p}"
            resp = session.get(content_url, timeout=30)
            if resp.status_code != 200:
                continue
            data = resp.json()
            if isinstance(data, dict) and data.get("content"):
                file_content = base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
                for line in file_content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Extract @handles from the owners part of lines
                    for m in re.finditer(r"@([A-Za-z0-9_\\-]+)", line):
                        logins.append(m.group(1))
        except Exception:
            continue
    return sorted(list(set(logins)))


def _emails_from_logins(logins: List[str]) -> List[str]:
    if not CONTACT_EMAIL_DOMAIN:
        return []
    return [f"{login}@{CONTACT_EMAIL_DOMAIN}" for login in logins]


def _get_repo_contributors(owner: str, repo_name: str, *, top_n: int = 5) -> List[str]:
    try:
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/contributors"
        r = gh_get(url, params={"per_page": 100})
        arr = r.json() or []
        return [c.get("login") for c in arr[:top_n] if c.get("login")]
    except Exception:
        return []


def _get_repo_details(owner: str, repo_name: str) -> Dict[str, any]:
    if not ENABLE_REPO_DETAILS:
        return {}


def _get_branch_protections(owner: str, repo_name: str) -> Dict[str, any]:
    """Return protected branches and aggregated required status checks.

    Structure:
      {
        "protected_branches": ["main", "release"],
        "required_checks": ["build", "test"],
        "per_branch": {
            "main": {"checks": [..], "strict": bool},
            ...
        }
      }
    """
    result = {"protected_branches": [], "required_checks": [], "per_branch": {}}
    try:
        r = gh_get(f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/branches", params={"per_page": 100})
        branches = r.json() or []
        ctx_union: set[str] = set()
        for b in branches:
            if not isinstance(b, dict):
                continue
            name = b.get("name")
            if not name:
                continue
            if b.get("protected"):
                result["protected_branches"].append(name)
                # Try to fetch protection details
                try:
                    pr = gh_get(f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/branches/{name}/protection")
                    pdata = pr.json() or {}
                    rsc = pdata.get("required_status_checks") or {}
                    contexts = rsc.get("contexts") or []
                    strict = bool(rsc.get("strict"))
                    result["per_branch"][name] = {"checks": contexts, "strict": strict}
                    for c in contexts:
                        ctx_union.add(c)
                except Exception:
                    # Not all installations expose protection details without extra scopes
                    result["per_branch"][name] = {"checks": [], "strict": False}
        result["required_checks"] = sorted(list(ctx_union))
    except Exception:
        pass
    return result
    try:
        repo_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}"
        r = gh_get(repo_url)
        meta = r.json() or {}
        langs = []
        topics = []
        license_name = None
        try:
            lr = gh_get(f"{repo_url}/languages")
            langs = list((lr.json() or {}).keys())
        except Exception:
            pass
        try:
            tr = gh_get(f"{repo_url}/topics", params={"per_page": 100})
            topics = tr.json().get("names", []) if isinstance(tr.json(), dict) else []
        except Exception:
            pass
        try:
            lic = meta.get("license") or {}
            license_name = lic.get("spdx_id") or lic.get("name")
        except Exception:
            pass
        return {
            "stars": meta.get("stargazers_count"),
            "forks": meta.get("forks_count"),
            "watchers": meta.get("subscribers_count"),
            "protected_branches": None,  # Optional: fetch branch protection per branch if needed
            "languages": langs,
            "topics": topics,
            "license": license_name,
        }
    except Exception:
        return {}

# Given repo, inspect the default branch tree to find candidate files
def scan_repo(owner: str, repo_name: str):
    repo_full = f"{owner}/{repo_name}"
    logger.info(f"Scanning repo {repo_full}")
    try:
        repo_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}"
        repo_meta = gh_get(repo_url).json()
    except Exception as e:
        logger.exception(f"Failed to fetch repo metadata for {repo_full}: {e}")
        # Return minimal context so caller doesn't crash
        return [], {"repo": repo_full, "error": "meta_fetch_failed"}

    default_branch = repo_meta.get("default_branch", "main")
    pushed_at = repo_meta.get("pushed_at")
    last_activity = None
    try:
        if pushed_at:
            last_activity = datetime.fromisoformat(pushed_at.replace("Z", "+00:00")).isoformat()
    except Exception:
        last_activity = pushed_at
    sha = None
    # Get the tree recursively (may be large)
    try:
        ref_resp = gh_get(f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/git/refs/heads/{default_branch}").json()
        sha = ref_resp.get("object", {}).get("sha")
        if not sha:
            logger.warning(f"No sha for default branch {default_branch} in {repo_full}")
            # Return minimal context to avoid tuple unpack issues
            return [], {"repo": repo_full, "default_branch": default_branch, "last_activity": last_activity}
        # Checkpoint logic (skip unchanged repos)
        checkpoints_path = os.path.join(OUTPUT_DIR, "checkpoints.json")
        if ENABLE_CHECKPOINTS and os.path.isfile(checkpoints_path):
            try:
                with open(checkpoints_path, "r", encoding="utf-8") as cf:
                    old_map = json.load(cf) or {}
                if old_map.get(repo_full) == sha:
                    contacts = _parse_codeowners(owner, repo_name)
                    top_contribs = _get_repo_contributors(owner, repo_name, top_n=TOP_CONTRIBUTORS)
                    contact_emails = _emails_from_logins(list(set(contacts + top_contribs)))
                    details = _get_repo_details(owner, repo_name)
                    repo_context = {
                        "repo": repo_full,
                        "default_branch": default_branch,
                        "last_activity": last_activity,
                        "contacts": contacts,
                        "contact_emails": contact_emails,
                        **details,
                        "skipped": True,
                        "checkpoint_sha": sha or "",
                    }
                    return [], repo_context
            except Exception:
                pass
        tree_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/git/trees/{sha}?recursive=1"
        tree_resp = gh_get(tree_url, params={"per_page": 100})
        tree = tree_resp.json().get("tree", [])
    except requests.HTTPError as e:
        logger.warning(f"Tree API failed for {repo_full}: {e} - falling back to searching common paths")
        tree = []

    candidate_paths = []
    if tree:
        for entry in tree:
            path = entry.get("path", "")
            if path.endswith(("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
                candidate_paths.append(path)
            # also check workflows and .github for suspicious workflows/backdoors
            if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
                candidate_paths.append(path)
    else:
        # fallback: check common file locations
        candidate_paths = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", ".github/workflows"]

    logger.debug(f"{repo_full}: candidates to fetch = {len(candidate_paths)}")
    findings = []
    suspicious_scripts = []
    npmrc_hits = []

    for p in candidate_paths:
        try:
            content_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/contents/{p}"
            resp = session.get(content_url)
            if resp.status_code != 200:
                continue
            data = resp.json()
            file_content = ""
            if isinstance(data, dict) and data.get("content"):
                file_content = base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
            elif isinstance(data, list):
                # when path is a directory listing
                continue
            else:
                # fallback: raw download
                file_content = data.get("content", "")
            # parse according to filename
            fname = p.split("/")[-1].lower()
            if fname == "package.json":
                deps = parse_package_json(file_content)
                # scripts scan
                try:
                    pj = json.loads(file_content)
                    scripts = pj.get("scripts", {}) if isinstance(pj, dict) else {}
                    if isinstance(scripts, dict):
                        for name, cmd in scripts.items():
                            if isinstance(cmd, str) and re.search(r"curl\\s+.*(\\||;).*bash|wget\\s+.*(\\||;).*sh|powershell\\s+-command|Invoke-Expression|node\\s+-e|bash\\s+-c", cmd, re.IGNORECASE):
                                suspicious_scripts.append(f"{name}:{cmd}")
                except Exception:
                    pass
                for pkg_name in deps.keys():
                    if pkg_name in bad_map:
                        declared_version = deps[pkg_name]
                        status = "Unknown"
                        # try to locate line number in package.json for this dep
                        line_no = None
                        try:
                            for idx, ln in enumerate(file_content.splitlines(), start=1):
                                if re.search(rf'"{re.escape(pkg_name)}"\s*:', ln):
                                    line_no = idx
                                    break
                        except Exception:
                            pass
                        findings.append({
                            "repo": repo_full,
                            "file": p,
                            "package": pkg_name,
                            "declared_version": declared_version,
                            "versions_found": [],
                            "status": status,
                            "line": line_no
                        })
            elif fname == "package-lock.json":
                for pkg_name in bad_map.keys():
                    versions = find_versions_in_package_lock(file_content, pkg_name)
                    if versions:
                        status = "Compromised" if any(v in bad_map[pkg_name] for v in versions) else "Safe"
                        findings.append({
                            "repo": repo_full,
                            "file": p,
                            "package": pkg_name,
                            "declared_version": None,
                            "versions_found": sorted(list(versions)),
                            "status": status,
                            "line": None
                        })
            elif fname in ("yarn.lock", "pnpm-lock.yaml"):
                for pkg_name in bad_map.keys():
                    versions = find_versions_in_text_lock(file_content, pkg_name)
                    if versions:
                        status = "Compromised" if any(v in bad_map[pkg_name] for v in versions) else "Safe"
                        findings.append({
                            "repo": repo_full,
                            "file": p,
                            "package": pkg_name,
                            "declared_version": None,
                            "versions_found": sorted(list(versions)),
                            "status": status,
                            "line": None
                        })
            elif p.startswith(".github/workflows"):
                # quick heuristic: look for suspicious job steps e.g., run: curl ... | bash or token exfil
                if re.search(r"curl .*pipe.*bash|wget .*pipe.*sh|GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID", file_content, re.IGNORECASE):
                    findings.append({
                        "repo": repo_full,
                        "file": p,
                        "package": None,
                        "declared_version": None,
                        "versions_found": [],
                        "status": "Suspicious_Workflow",
                        "line": None
                    })
            elif fname == ".npmrc":
                for ln in file_content.splitlines():
                    line = ln.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "_auth" in line or "always-auth" in line or "unsafe-perm" in line:
                        npmrc_hits.append(line)
                    if line.startswith("registry=") and not re.search(r"npmjs\.org|npmjs\.com", line):
                        npmrc_hits.append(line)
        except Exception as ex:
            logger.exception(f"Error fetching/processing {p} in {repo_full}: {ex}")
            continue

    # If package.json findings had declared versions but we also saw versions in lockfiles, merge info
    # (simplified merging)
    merged = {}
    for f in findings:
        key = (f['repo'], f.get('package'), f['file'])
        merged.setdefault(key, {"repo": f['repo'], "package": f.get('package'), "files": set(), "decls": set(), "versions": set(), "statuses": set()})
        merged[key]["files"].add(f['file'])
        if f.get("declared_version"):
            merged[key]["decls"].add(f["declared_version"])
        for v in f.get("versions_found", []):
            merged[key]["versions"].add(v)
        merged[key]["statuses"].add(f.get("status", "Unknown"))

    results = []
    for (_, pkg, _), info in merged.items():
        versions = sorted(list(info["versions"]))
        declared = sorted(list(info["decls"]))
        statuses = sorted(list(info["statuses"]))
        final_status = "Compromised" if "Compromised" in statuses else ("Suspicious_Workflow" if "Suspicious_Workflow" in statuses else ("Safe" if "Safe" in statuses else "Unknown"))
        results.append({
            "Repository": info["repo"],
            "Package": pkg,
            "Files": ";".join(sorted(info["files"])),
            "DeclaredVersions": ";".join(declared) if declared else "",
            "InstalledVersions": ";".join(versions) if versions else "",
            "Status": final_status
        })
    logger.info(f"{repo_full}: found {len(results)} relevant entries")
    # Repo-level context and contacts
    contacts = _parse_codeowners(owner, repo_name)
    top_contribs = _get_repo_contributors(owner, repo_name, top_n=TOP_CONTRIBUTORS)
    contact_emails = _emails_from_logins(list(set(contacts + top_contribs)))
    details = _get_repo_details(owner, repo_name)
    protections = _get_branch_protections(owner, repo_name) if ENABLE_REPO_DETAILS else {}
    repo_context = {
        "repo": repo_full,
        "default_branch": default_branch,
        "last_activity": last_activity,
        "contacts": contacts,
        "contact_emails": contact_emails,
        **details,
        "suspicious_scripts": suspicious_scripts,
        "npmrc_hits": npmrc_hits,
        "checkpoint_sha": sha or "",
        **protections,
    }
    return results, repo_context

# Main
def main():
    # ---- CxOne setup (env-driven). The API base must include /api/ suffix
    # Example built token URL: f"{CXONE_TOKEN_BASE_URL}/{CXONE_TENANT}/protocol/openid-connect/token"
    CXONE_TOKEN_BASE_URL = os.getenv("CXONE_TOKEN_BASE_URL")
    CXONE_TENANT = os.getenv("CXONE_TENANT")
    CXONE_REFRESH_TOKEN = os.getenv("CXONE_REFRESH_TOKEN")
    CXONE_CLIENT_ID = os.getenv("CXONE_CLIENT_ID", "ast-app")
    CXONE_API_BASE_URL = os.getenv("CXONE_API_BASE_URL")
    CXONE_VERIFY_SSL = os.getenv("CXONE_VERIFY_SSL", "true").lower() == "true"
    CXONE_SCM_GITHUB_TOKEN = os.getenv("CXONE_SCM_GITHUB_TOKEN")
    CXONE_ORG_IDENTITY = os.getenv("CXONE_ORG_IDENTITY")
    CXONE_SCAN_AFTER_IMPORT = os.getenv("CXONE_SCAN_AFTER_IMPORT", "true").lower() == "true"
    CXONE_IMPORT_BATCH_SIZE = int(os.getenv("CXONE_IMPORT_BATCH_SIZE", "10"))
    CXONE_ENABLE_APISEC = os.getenv("CXONE_ENABLE_APISEC", "true").lower() == "true"
    CXONE_ENABLE_KICS = os.getenv("CXONE_ENABLE_KICS", "true").lower() == "true"

    if not all([CXONE_TOKEN_BASE_URL, CXONE_TENANT, CXONE_REFRESH_TOKEN, CXONE_API_BASE_URL, CXONE_SCM_GITHUB_TOKEN, CXONE_ORG_IDENTITY, GITHUB_SCM_BASE_URL]):
        logger.warning("CxOne import disabled due to missing env. Will still scan and report.")
        enable_import = False
        api = None
    else:
        enable_import = True
        cx_sess = CxOneSession(
            token_base_url=CXONE_TOKEN_BASE_URL,
            tenant=CXONE_TENANT,
            refresh_token=CXONE_REFRESH_TOKEN,
            client_id=CXONE_CLIENT_ID,
            verify_ssl=CXONE_VERIFY_SSL,
            timeout=30,
        )
        api = CxOneAPI(session=cx_sess, api_base_url=CXONE_API_BASE_URL, verify_ssl=CXONE_VERIFY_SSL, timeout=60)

    # Queue for importer. One worker (runner) to send batches of up to N while scan runs
    import_queue: "queue.Queue[dict]" = queue.Queue()
    import_failures: List[dict] = []
    importer_stop = object()

    def importer_worker():
        batch: List[dict] = []
        while True:
            item = import_queue.get()
            if item is importer_stop:
                # flush any remaining
                if batch and enable_import and api:
                    try:
                        payload = item["payload_builder"](batch)
                        repo_list = ", ".join(p.get("scm_url", "") for p in batch)
                        logger.info("Submitting final batch to CxOne (size=%s): %s", len(batch), repo_list)
                        if not DRY_RUN:
                            api.import_scm_projects(payload)
                    except Exception as ex:
                        logger.exception("Final batch import failed: %s", ex)
                        import_failures.extend(batch)
                break
            batch.append(item)
            if len(batch) >= CXONE_IMPORT_BATCH_SIZE:
                if enable_import and api:
                    try:
                        payload = item["payload_builder"](batch)
                        # Inline comment: example scm base + owner/repo result
                        repo_list = ", ".join(p.get("scm_url", "") for p in batch)
                        logger.info("Submitting batch to CxOne (size=%s): %s", len(batch), repo_list)
                        if not DRY_RUN:
                            api.import_scm_projects(payload)
                        batch.clear()
                    except Exception as ex:
                        logger.exception("Batch import failed: %s", ex)
                        import_failures.extend(batch)
                        batch.clear()

    if enable_import:
        logger.info(
            "CxOne import enabled: orgIdentity=%s, batch_size=%s, scan_after_import=%s",
            CXONE_ORG_IDENTITY,
            CXONE_IMPORT_BATCH_SIZE,
            CXONE_SCAN_AFTER_IMPORT,
        )
        t = threading.Thread(target=importer_worker, name="cxone_importer", daemon=True)
        t.start()

    repos = list_org_repos(GITHUB_ORG)
    all_findings = []
    per_repo_ctx: Dict[str, dict] = {}
    repo_count = len(repos)
    logger.info(f"Beginning scan of {repo_count} repositories under {GITHUB_ORG}")
    for idx, repo in enumerate(repos, 1):
        owner = repo["owner"]["login"]
        name = repo["name"]
        logger.info(f"[{idx}/{repo_count}] Scanning {owner}/{name}")
        logger.debug("Repo meta URL: %s", f"{GITHUB_API_BASE}/repos/{owner}/{name}")
        try:
            res, repo_ctx = scan_repo(owner, name)
            logger.debug("Scan complete: %s findings=%s skipped=%s", f"{owner}/{name}", len(res or []), repo_ctx.get("skipped", False))
            if res:
                all_findings.extend(res)
            per_repo_ctx[f"{owner}/{name}"] = repo_ctx
            # Determine repo-level status from npm-related findings only (exclude workflow-only repos)
            npm_related = [r for r in res if r.get("Package")]
            if npm_related:
                logger.debug("Repo %s npm-related entries=%s", f"{owner}/{name}", len(npm_related))
                # If any not Safe, enqueue for import
                worst = "Safe"
                ordering = {"Compromised": 3, "Unknown": 2, "Suspicious_Workflow": 1, "Safe": 0}
                for r in npm_related:
                    st = r["Status"] or "Unknown"
                    if ordering.get(st, 0) > ordering.get(worst, 0):
                        worst = st
                if worst != "Safe" and enable_import:
                    # Build per-project CxOne payload entry
                    scm_url = f"{GITHUB_SCM_BASE_URL}/{owner}/{name}"
                    branch = repo_ctx.get("default_branch") or "main"
                    if not branch:
                        import_failures.append({"repo": f"{owner}/{name}", "reason": "No default branch"})
                        logger.warning("Skipped CxOne import for %s: no default branch", f"{owner}/{name}")
                    else:
                        def _payload_builder(projects: List[dict]):
                            scanners = [
                                {"type": "sast", "incrementalScan": True},
                                {"type": "sca", "enableAutoPullRequests": True},
                            ]
                            if CXONE_ENABLE_APISEC:
                                scanners.append({"type": "apisec"})
                            if CXONE_ENABLE_KICS:
                                scanners.append({"type": "kics"})
                            base = {
                                "scm": {"type": "github", "token": CXONE_SCM_GITHUB_TOKEN},
                                "organization": {"orgIdentity": CXONE_ORG_IDENTITY},
                                "defaultProjectSettings": {
                                    "decoratePullRequests": True,
                                    "webhookEnabled": True,
                                    "scanners": scanners,
                                    # tags here are generic; severity added per-project below
                                    "tags": {"source": "npm_ingest"},
                                    # groups intentionally omitted per requirements
                                },
                                "scanProjectsAfterImport": CXONE_SCAN_AFTER_IMPORT,
                                "projects": [],
                            }
                            for p in projects:
                                proj = {
                                    "scmRepositoryUrl": p["scm_url"],
                                    "branchToScanUponCreation": p["branch"],
                                    "customSettings": {
                                        "decoratePullRequests": True,
                                        "webhookEnabled": True,
                                        "scanners": scanners,
                                        # Per-project tags include severity label
                                        "tags": {"source": "npm_ingest", "severity": p["severity"]},
                                    },
                                }
                                base["projects"].append(proj)
                            return base

                        severity = "P1" if worst == "Compromised" else "P2"
                        logger.info("Queueing for CxOne import: %s branch=%s severity=%s", scm_url, branch, severity)
                        import_queue.put({
                            "scm_url": scm_url,  # Example: https://git.org.gov/owner/repo
                            "branch": branch,    # Example: main
                            "severity": severity,
                            "payload_builder": _payload_builder,
                        })
        except Exception as e:
            logger.exception(f"Failed scanning repo {owner}/{name}: {e}")
        # small sleep to be nicer to API
        time.sleep(0.25)

    # Stop importer and wait
    if enable_import:
        import_queue.put(importer_stop)
        t.join(timeout=300)

    # Write CSV + JSON
    csv_path = os.path.join(OUTPUT_DIR, "compromised_packages_report.csv")
    json_path = os.path.join(OUTPUT_DIR, "compromised_packages_report.json")
    md_path = os.path.join(OUTPUT_DIR, "master_report.md")
    contacts_csv = os.path.join(OUTPUT_DIR, "contacts_owners.csv")
    if DRY_RUN:
        logger.info("DRY_RUN enabled — not writing output files")
    else:
        if all_findings:
            with open(csv_path, "w", newline="", encoding="utf-8") as cf:
                fieldnames = ["Repository", "Package", "Files", "DeclaredVersions", "InstalledVersions", "Status"]
                writer = csv.DictWriter(cf, fieldnames=fieldnames)
                writer.writeheader()
                for r in all_findings:
                    writer.writerow(r)
            with open(json_path, "w", encoding="utf-8") as jf:
                json.dump(all_findings, jf, indent=2)
            logger.info(f"Wrote {len(all_findings)} findings to {csv_path} and {json_path}")
        else:
            logger.info("No findings — no output files written.")

        # Master Markdown
        try:
            totals = {"Compromised": 0, "Unknown": 0, "Suspicious_Workflow": 0, "Safe": 0}
            for r in all_findings:
                totals[r.get("Status", "Unknown")] = totals.get(r.get("Status", "Unknown"), 0) + 1
            lines = []
            lines.append("# NPM Supply-Chain Scan Report\n")
            lines.append("## Summary\n")
            lines.append("| Status | Count |\n|---|---:|")
            for k in ["Compromised", "Unknown", "Suspicious_Workflow", "Safe"]:
                lines.append(f"| {k} | {totals.get(k, 0)} |")
            lines.append("\n## Legend\n")
            lines.append("- **Compromised**: lockfile shows a version in the malicious set.")
            lines.append("- **Unknown**: package present; version not determinable or declared only.")
            lines.append("- **Suspicious_Workflow**: risky CI workflow patterns detected (not imported unless npm package also impacted).")
            lines.append("- **Safe**: versions do not match any known malicious versions.\n")
            lines.append("## Priority Mapping\n")
            lines.append("- **P1**: Compromised (import + scan immediately)")
            lines.append("- **P2**: Unknown (import + scan)\n")
            lines.append("## Limitations & Notes\n")
            lines.append("- CxOne vendor intelligence may lag during active supply-chain events; our detection relies on lockfile/package evidence and heuristics. Results in CxOne may appear clean while this report flags risk.")
            lines.append("- GitHub API rate limits are handled with adaptive backoff; very large orgs may take multiple hours.")
            lines.append("- Branch protection details may require additional API scopes. Missing data is shown blank.")
            lines.append("- Resume: unchanged repos are skipped via checkpoints; delete checkpoints.json to force full rescan.\n")
            lines.append("## Affected Repositories (unique)\n")
            affected = sorted(list({r["Repository"] for r in all_findings if r.get("Status") != "Safe"}))
            lines.append("| Repository | Default Branch | Last Activity | Contacts | Emails | Languages | Topics | Stars | Forks | Watchers | Protected Branches | Required Checks |\n|---|---|---|---|---|---|---|---:|---:|---:|---|---|")
            for repo_full in affected:
                ctx = per_repo_ctx.get(repo_full, {})
                lines.append(
                    f"| {repo_full} | {ctx.get('default_branch','')} | {ctx.get('last_activity','')} | "
                    f"{', '.join(ctx.get('contacts',[]) or [])} | {', '.join(ctx.get('contact_emails',[]) or [])} | "
                    f"{', '.join(ctx.get('languages',[]) or [])} | {', '.join(ctx.get('topics',[]) or [])} | "
                    f"{ctx.get('stars','') or ''} | {ctx.get('forks','') or ''} | {ctx.get('watchers','') or ''} | "
                    f"{', '.join(ctx.get('protected_branches',[]) or [])} | {', '.join(ctx.get('required_checks',[]) or [])} |"
                )
            lines.append("\n")
            if import_failures:
                lines.append("## Import Failures / Skipped\n")
                lines.append("| Repo | Reason |\n|---|---|")
                for f in import_failures:
                    lines.append(f"| {f.get('repo','')} | {f.get('reason','import_failed')} |")
                lines.append("\n")
            with open(md_path, "w", encoding="utf-8") as mf:
                mf.write("\n".join(lines))
            logger.info("Wrote master Markdown report: %s", md_path)
        except Exception as ex:
            logger.warning("Failed to write Markdown report: %s", ex)

        # Contacts CSV
        try:
            rows = []
            for repo_full, ctx in per_repo_ctx.items():
                rows.append({
                    "Repository": repo_full,
                    "DefaultBranch": ctx.get("default_branch"),
                    "LastActivity": ctx.get("last_activity"),
                    "Contacts": ",".join(ctx.get("contacts", []) or []),
                    "Emails": ",".join(ctx.get("contact_emails", []) or []),
                })
            with open(contacts_csv, "w", newline="", encoding="utf-8") as cf:
                writer = csv.DictWriter(cf, fieldnames=["Repository", "DefaultBranch", "LastActivity", "Contacts", "Emails"])
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)
            logger.info("Wrote contacts CSV: %s", contacts_csv)
        except Exception as ex:
            logger.warning("Failed writing contacts CSV: %s", ex)

        # Per-repo Markdown (optional)
        try:
            if ENABLE_PER_REPO_MD:
                base_dir = os.path.join(OUTPUT_DIR, "repos")
                os.makedirs(base_dir, exist_ok=True)
                # Index findings per repo
                by_repo: Dict[str, List[dict]] = {}
                for r in all_findings:
                    by_repo.setdefault(r["Repository"], []).append(r)
                for repo_full, items in by_repo.items():
                    owner, repo_name = repo_full.split("/", 1)
                    path = os.path.join(base_dir, owner)
                    os.makedirs(path, exist_ok=True)
                    md_file = os.path.join(path, f"{repo_name}.md")
                    ctx = per_repo_ctx.get(repo_full, {})
                    md = []
                    md.append(f"# {repo_full}\n")
                    md.append("## Repo Details\n")
                    md.append("- Default branch: " + (ctx.get("default_branch") or ""))
                    md.append("- Last activity: " + (ctx.get("last_activity") or ""))
                    if ctx.get("languages"):
                        md.append("- Languages: " + ", ".join(ctx.get("languages", [])))
                    if ctx.get("topics"):
                        md.append("- Topics: " + ", ".join(ctx.get("topics", [])))
                    if ctx.get("license"):
                        md.append("- License: " + str(ctx.get("license")))
                    md.append("")
                    md.append("## Contacts\n")
                    md.append("- CODEOWNERS: " + ", ".join(ctx.get("contacts", []) or []))
                    if ctx.get("contact_emails"):
                        md.append("- Emails: " + ", ".join(ctx.get("contact_emails", [])))
                    md.append("")
                    md.append("## Findings\n")
                    md.append("| Package | Files | Declared | Installed | Status |\n|---|---|---|---|---|")
                    for it in items:
                        md.append(
                            f"| {it.get('Package','')} | {it.get('Files','')} | {it.get('DeclaredVersions','')} | "
                            f"{it.get('InstalledVersions','')} | {it.get('Status','')} |"
                        )
                    with open(md_file, "w", encoding="utf-8") as pf:
                        pf.write("\n".join(md))
                logger.info("Wrote per-repo Markdown to %s", base_dir)
        except Exception as ex:
            logger.warning("Failed writing per-repo Markdown: %s", ex)

        # SARIF output (optional)
        try:
            if ENABLE_SARIF:
                sarif_path = os.path.join(OUTPUT_DIR, "findings.sarif")
                rules = []
                results_sarif = []
                rule_ids = set()
                for r in all_findings:
                    rule_id = f"npm/{(r.get('Package') or 'unknown')}"
                    if rule_id not in rule_ids:
                        rules.append({
                            "id": rule_id,
                            "name": r.get("Package") or "unknown",
                            "shortDescription": {"text": "Potential malicious npm package"},
                            "help": {"text": "Investigate dependency and lock versions."},
                            "defaultConfiguration": {"level": "error" if r.get("Status") == "Compromised" else "warning"},
                        })
                        rule_ids.add(rule_id)
                    results_sarif.append({
                        "ruleId": rule_id,
                        "level": "error" if r.get("Status") == "Compromised" else "warning",
                        "message": {"text": f"{r.get('Repository')} uses {r.get('Package')} status={r.get('Status')}"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": (r.get("Files", "").split(';')[0] or '')},
                            }
                        }],
                    })
                sarif = {
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [{
                        "tool": {"driver": {"name": "npm-supply-chain-scanner", "rules": rules}},
                        "results": results_sarif,
                    }],
                }
                with open(sarif_path, "w", encoding="utf-8") as sf:
                    json.dump(sarif, sf, indent=2)
                logger.info("Wrote SARIF: %s", sarif_path)
        except Exception as ex:
            logger.warning("Failed writing SARIF: %s", ex)

        # HTML output (optional): render Markdown to HTML for better readability
        try:
            if ENABLE_HTML:
                html_path = os.path.join(OUTPUT_DIR, "master_report.html")
                try:
                    with open(md_path, "r", encoding="utf-8") as mf:
                        md_text = mf.read()
                except Exception:
                    md_text = ""
                html_body = md.markdown(md_text, extensions=["tables", "fenced_code"]) if md_text else ""
                html = [
                    "<!doctype html>",
                    "<html><head><meta charset=\"utf-8\"><title>NPM Supply-Chain Report</title>",
                    "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px} table{border-collapse:collapse} td,th{border:1px solid #ddd;padding:6px} pre,code{white-space:pre-wrap}</style>",
                    "</head><body>",
                    html_body,
                    "</body></html>",
                ]
                with open(html_path, "w", encoding="utf-8") as hf:
                    hf.write("\n".join(html))
                logger.info("Wrote HTML report: %s", html_path)
        except Exception as ex:
            logger.warning("Failed writing HTML report: %s", ex)

    # Update checkpoints after successful run
    try:
        if ENABLE_CHECKPOINTS:
            cps = {}
            for repo_full, ctx in per_repo_ctx.items():
                if ctx.get("checkpoint_sha"):
                    cps[repo_full] = ctx.get("checkpoint_sha")
            if cps:
                with open(os.path.join(OUTPUT_DIR, "checkpoints.json"), "w", encoding="utf-8") as cpf:
                    json.dump(cps, cpf, indent=2)
                logger.info("Wrote checkpoints for %s repos", len(cps))
    except Exception as ex:
        logger.warning("Failed writing checkpoints: %s", ex)

if __name__ == "__main__":
    main()
