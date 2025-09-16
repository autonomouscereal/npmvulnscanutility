# tls_helper.py
import os
import re
import ssl
import hashlib
import subprocess
from urllib.parse import urlparse
from pathlib import Path
import logging

logger = logging.getLogger("npm_scanner.tls_helper")

def _parse_host_port(api_base: str):
    u = urlparse(api_base)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port

def _openssl_fetch_chain(host: str, port: int, timeout: int = 20) -> str:
    """Return concatenated PEM blocks (string) using openssl s_client."""
    cmd = ["openssl", "s_client", "-showcerts", "-servername", host, "-connect", f"{host}:{port}"]
    logger.debug("Attempting openssl certificate fetch: %s", " ".join(cmd))
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True)
    out = proc.stdout.decode("utf-8", errors="ignore")
    pem_blocks = re.findall(r"(-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)", out, flags=re.S)
    if not pem_blocks:
        raise RuntimeError("openssl returned no PEM blocks")
    return "\n".join(pem_blocks)

def _ssl_fetch_leaf(host: str, port: int) -> str:
    """Return PEM for server leaf cert via ssl.get_server_certificate."""
    logger.debug("Attempting ssl.get_server_certificate for %s:%s", host, port)
    return ssl.get_server_certificate((host, port))

def _sha256_fingerprint(pem_text: str) -> str:
    # strip PEM armor, decode base64, calc sha256
    import base64
    m = re.search(r"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", pem_text, flags=re.S)
    if not m:
        # fallback: hash entire PEM text
        h = hashlib.sha256(pem_text.encode("utf-8")).hexdigest()
        return h
    b64 = m.group(1).strip().replace("\n", "")
    der = base64.b64decode(b64)
    return hashlib.sha256(der).hexdigest()

def auto_fetch_and_trust_cert(api_base: str, output_dir: str, auto_trust: bool = True, prefer_openssl: bool = True) -> str:
    """
    Attempts to fetch server cert(s) for api_base and write to output_dir/certs/<host>.pem.
    If auto_trust is True, returns the path to the PEM file (suitable for requests.verify).
    On failure raises RuntimeError.
    """
    host, port = _parse_host_port(api_base)
    cert_dir = Path(output_dir) / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    target = cert_dir / f"{host}.pem"

    # If already present, reuse it
    if target.exists():
        logger.info("Using existing cert file: %s", target)
        return str(target) if auto_trust else ""

    last_errs = []
    # Try openssl first (captures full chain)
    if prefer_openssl:
        try:
            pem = _openssl_fetch_chain(host, port)
            target.write_text(pem, encoding="utf-8")
            fp = _sha256_fingerprint(pem)
            logger.info("Fetched cert chain via openssl -> %s (sha256:%s)", target, fp)
            return str(target) if auto_trust else ""
        except Exception as e:
            last_errs.append(f"openssl: {e}")
            logger.debug("openssl fetch failed", exc_info=True)

    # Fallback to ssl module (leaf only)
    try:
        pem = _ssl_fetch_leaf(host, port)
        target.write_text(pem, encoding="utf-8")
        fp = _sha256_fingerprint(pem)
        logger.info("Fetched leaf cert via ssl module -> %s (sha256:%s)", target, fp)
        return str(target) if auto_trust else ""
    except Exception as e:
        last_errs.append(f"ssl: {e}")
        logger.debug("ssl.get_server_certificate failed", exc_info=True)

    raise RuntimeError("Auto-fetch cert failed: " + " | ".join(last_errs))
