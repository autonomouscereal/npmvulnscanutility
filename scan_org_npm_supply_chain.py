# scan_org_npm_supply_chain.py
import os
import json
import re
import base64
import csv
import time
import logging
from logging.handlers import RotatingFileHandler
from typing import Dict, Set, List
import requests
from dotenv import load_dotenv

load_dotenv()

# Config from env
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_API_BASE = os.getenv("GITHUB_API_BASE", "https://api.github.com")
GITHUB_ORG = os.getenv("GITHUB_ORG")
BAD_PACKAGES_FILE = os.getenv("BAD_PACKAGES_FILE", "bad_packages.json")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./scan_results")
LOG_FILE = os.getenv("LOG_FILE", os.path.join(OUTPUT_DIR, "scan.log"))
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"

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

session = requests.Session()
session.headers.update({
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "gov-org-npm-scanner/1.0"
})

#--------------------------------
# Load bad packages list (list of {"name": "...", "versions": ["1.2.3", ...]})
with open(BAD_PACKAGES_FILE, "r", encoding="utf-8") as f:
    bad_packages_raw = json.load(f)
bad_map: Dict[str, Set[str]] = {item["name"]: set(item.get("versions", [])) for item in bad_packages_raw}

logger.info(f"Loaded {len(bad_map)} watched packages from {BAD_PACKAGES_FILE}")

# Helper: GitHub pagination GET
def gh_get(url, params=None):
    params = params or {}
    resp = session.get(url, params=params, timeout=30)
    if resp.status_code == 403 and 'rate limit' in resp.text.lower():
        reset = int(resp.headers.get("X-RateLimit-Reset", time.time()+60))
        wait = max(reset - int(time.time()), 10)
        logger.warning(f"Rate limited. Sleeping {wait}s")
        time.sleep(wait)
        resp = session.get(url, params=params, timeout=30)
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

# Given repo, inspect the default branch tree to find candidate files
def scan_repo(owner: str, repo_name: str):
    repo_full = f"{owner}/{repo_name}"
    logger.info(f"Scanning repo {repo_full}")
    try:
        repo_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}"
        repo_meta = gh_get(repo_url).json()
    except Exception as e:
        logger.exception(f"Failed to fetch repo metadata for {repo_full}: {e}")
        return []

    default_branch = repo_meta.get("default_branch", "main")
    # Get the tree recursively (may be large)
    try:
        ref_resp = gh_get(f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/git/refs/heads/{default_branch}").json()
        sha = ref_resp.get("object", {}).get("sha")
        if not sha:
            logger.warning(f"No sha for default branch {default_branch} in {repo_full}")
            return []
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
                for pkg_name in deps.keys():
                    if pkg_name in bad_map:
                        declared_version = deps[pkg_name]
                        status = "Unknown"
                        # try to find actual installed version from lockfiles below
                        findings.append({
                            "repo": repo_full,
                            "file": p,
                            "package": pkg_name,
                            "declared_version": declared_version,
                            "versions_found": [],
                            "status": status
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
                            "status": status
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
                            "status": status
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
                        "status": "Suspicious_Workflow"
                    })
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
    return results

# Main
def main():
    repos = list_org_repos(GITHUB_ORG)
    all_findings = []
    repo_count = len(repos)
    logger.info(f"Beginning scan of {repo_count} repositories under {GITHUB_ORG}")
    for idx, repo in enumerate(repos, 1):
        owner = repo["owner"]["login"]
        name = repo["name"]
        logger.info(f"[{idx}/{repo_count}] Scanning {owner}/{name}")
        try:
            res = scan_repo(owner, name)
            if res:
                all_findings.extend(res)
        except Exception as e:
            logger.exception(f"Failed scanning repo {owner}/{name}: {e}")
        # small sleep to be nicer to API
        time.sleep(0.25)

    # Write CSV + JSON
    csv_path = os.path.join(OUTPUT_DIR, "compromised_packages_report.csv")
    json_path = os.path.join(OUTPUT_DIR, "compromised_packages_report.json")
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

if __name__ == "__main__":
    main()
