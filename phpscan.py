#!/usr/bin/env python3
"""
phpscan - Internal network PHP web-server inventory scanner.

Sweeps a set of hosts/ports you are authorized to scan, fingerprints each
responding web server, detects PHP and (where disclosed) its version, checks
that version against PHP.net's support lifecycle, and writes HTML, CSV and
JSON reports.

Standard library only. Python 3.8+.

AUTHORIZED USE ONLY. Scan only networks and hosts you own or have explicit
written permission to assess. Port/HTTP scanning without authorization may be
illegal in your jurisdiction and against your organization's policy.
"""

import argparse
import concurrent.futures
import csv
import datetime
import html
import http.client
import http.server
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

__version__ = "1.1.0"

KEV_URL_DEFAULT = ("https://www.cisa.gov/sites/default/files/feeds/"
                   "known_exploited_vulnerabilities.json")

# ---------------------------------------------------------------------------
# PHP support lifecycle data.
# Source: https://www.php.net/supported-versions.php (confirmed 2026-10).
# Dates are the END of each support phase (YYYY-MM-DD).
#   active_until    - active support (bug + security fixes) ends
#   security_until  - security-only support ends; after this the branch is EOL
# ---------------------------------------------------------------------------
PHP_LIFECYCLE = {
    "8.5": {"active_until": "2027-12-31", "security_until": "2029-12-31"},
    "8.4": {"active_until": "2026-12-31", "security_until": "2028-12-31"},
    "8.3": {"active_until": "2025-12-31", "security_until": "2027-12-31"},
    "8.2": {"active_until": "2024-12-31", "security_until": "2026-12-31"},
    "8.1": {"active_until": "2023-11-25", "security_until": "2025-12-31"},
    "8.0": {"active_until": "2022-11-26", "security_until": "2023-11-26"},
    "7.4": {"active_until": "2021-11-28", "security_until": "2022-11-28"},
    "7.3": {"active_until": "2020-12-06", "security_until": "2021-12-06"},
    "7.2": {"active_until": "2019-11-30", "security_until": "2020-11-30"},
    "7.1": {"active_until": "2018-12-01", "security_until": "2019-12-01"},
    "7.0": {"active_until": "2018-01-10", "security_until": "2019-01-10"},
    "5.6": {"active_until": "2017-01-19", "security_until": "2018-12-31"},
}

# Default ports commonly used by internal web servers / app servers.
DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 7001, 9000]
# Ports we should attempt TLS on first.
TLS_PORTS = {443, 8443}

# Paths probed to coax a PHP fingerprint out of servers that hide it from "/".
DEFAULT_PROBE_PATHS = ["/", "/index.php", "/login.php"]

PHP_VERSION_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
# phpinfo() and some banners render the version as "PHP Version 8.2.5".
PHP_BODY_VERSION_RE = re.compile(r"PHP\s*Version\s*(\d+\.\d+(?:\.\d+)?)",
                                 re.IGNORECASE)
USER_AGENT = f"phpscan/{__version__} (internal-inventory)"


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------
def parse_targets(specs):
    """Expand a list of target specs into an ordered, de-duplicated host list.

    Accepts: CIDR (10.0.0.0/24), dashed range (10.0.0.1-50 or
    10.0.0.1-10.0.0.50), single IP, or hostname. Comma-separated specs within
    a single string are also split.
    """
    hosts = []
    seen = set()

    def add(h):
        if h not in seen:
            seen.add(h)
            hosts.append(h)

    for raw in specs:
        for spec in str(raw).split(","):
            spec = spec.strip()
            if not spec:
                continue
            try:
                if "/" in spec:  # CIDR
                    net = ipaddress.ip_network(spec, strict=False)
                    iterable = net.hosts() if net.num_addresses > 2 else net
                    for ip in iterable:
                        add(str(ip))
                    continue
                if "-" in spec and _looks_like_range(spec):
                    for ip in _expand_range(spec):
                        add(ip)
                    continue
                # single IP or hostname
                add(spec)
            except ValueError as exc:
                print(f"[!] Skipping invalid target '{spec}': {exc}",
                      file=sys.stderr)
    return hosts


def _looks_like_range(spec):
    left = spec.split("-", 1)[0].strip()
    try:
        ipaddress.ip_address(left)
        return True
    except ValueError:
        return False


def _expand_range(spec):
    start_s, end_s = (p.strip() for p in spec.split("-", 1))
    start = ipaddress.ip_address(start_s)
    if "." not in end_s and ":" not in end_s:
        # shorthand last-octet form: 10.0.0.1-50
        prefix = start_s.rsplit(".", 1)[0]
        end = ipaddress.ip_address(f"{prefix}.{end_s}")
    else:
        end = ipaddress.ip_address(end_s)
    if int(end) < int(start):
        raise ValueError("range end is before range start")
    if int(end) - int(start) > 65535:
        raise ValueError("range too large (>65535 addresses)")
    return [str(ipaddress.ip_address(i))
            for i in range(int(start), int(end) + 1)]


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def tcp_open(host, port, timeout):
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def fetch_http(host, port, path, timeout, use_tls):
    """Make one HTTP(S) request; return (status, headers_dict, body_snippet).

    Uses http.client directly: it does not auto-follow redirects (so a 301 to
    an app's login page is reported as-is) and lets us disable TLS trust for
    internal self-signed certs. Returns None if no HTTP response was obtained.
    """
    conn = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            # Internal hosts routinely use self-signed / internal-CA certs;
            # we are fingerprinting, not establishing trust.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": USER_AGENT,
                                           "Accept": "*/*"})
        resp = conn.getresponse()
        status = resp.status
        # Preserve duplicate headers (e.g. multiple Set-Cookie) by joining.
        headers = {}
        for k, v in resp.getheaders():
            k = k.lower()
            headers[k] = f"{headers[k]}, {v}" if k in headers else v
        body = resp.read(4096)
    except (OSError, ssl.SSLError, http.client.HTTPException,
            socket.timeout, ValueError):
        return None
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    try:
        snippet = body.decode("utf-8", "replace")
    except Exception:
        snippet = ""
    return status, headers, snippet


def detect_php(status, headers, body):
    """Inspect one HTTP response for PHP signals.

    Returns (is_php, version_or_None, [signal_strings]).
    """
    signals = []
    version = None

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    set_cookie = headers.get("set-cookie", "")

    for field_name, value in (("Server", server),
                              ("X-Powered-By", powered)):
        if "php" in value.lower():
            signals.append(f"{field_name}: {value.strip()}")
            m = PHP_VERSION_RE.search(value)
            if m and not version:
                version = m.group(1)

    if re.search(r"PHPSESSID", set_cookie, re.IGNORECASE):
        signals.append("Set-Cookie: PHPSESSID")

    # Body-level hints (phpinfo pages, PHP error messages, framework cookies)
    if body:
        if re.search(r"phpinfo\(\)|<title>phpinfo", body, re.IGNORECASE):
            signals.append("Body: phpinfo() output")
        if re.search(r"on line <b>\d+</b>|Fatal error:.*php", body,
                     re.IGNORECASE):
            signals.append("Body: PHP error signature")
        if "laravel_session" in body.lower():
            signals.append("Body: Laravel session cookie")
        if not version:
            m = PHP_VERSION_RE.search(body) or PHP_BODY_VERSION_RE.search(body)
            if m and signals:
                version = m.group(1)

    return (bool(signals), version, signals)


def classify_version(version, today):
    """Map a PHP version string to a support status against today's date."""
    if not version:
        return {"status": "unknown",
                "detail": "PHP detected but version not disclosed"}
    branch = ".".join(version.split(".")[:2])
    info = PHP_LIFECYCLE.get(branch)
    if not info:
        return {"status": "unknown",
                "detail": f"Branch {branch} not in lifecycle table"}

    active = datetime.date.fromisoformat(info["active_until"])
    security = datetime.date.fromisoformat(info["security_until"])

    if today > security:
        status, detail = ("eol",
                          f"End of life since {info['security_until']} "
                          f"(no security fixes)")
    elif today > active:
        status, detail = ("security_only",
                          f"Security-only until {info['security_until']}; "
                          f"active support ended {info['active_until']}")
    else:
        status, detail = ("active",
                          f"Actively supported until {info['active_until']}")
    return {"status": status, "detail": detail, "branch": branch,
            "active_until": info["active_until"],
            "security_until": info["security_until"]}


def scan_host_port(host, port, args, today):
    """Full pipeline for one host:port. Returns a result dict or None."""
    if not tcp_open(host, port, args.timeout):
        return None

    use_tls = port in TLS_PORTS
    result = {
        "host": host, "port": port, "tls": use_tls,
        "open": True, "is_web": False, "is_php": False,
        "php_version": None, "server": None, "powered_by": None,
        "status_code": None, "signals": [], "support": None,
        "url": None, "note": None,
    }

    # Port 9000 with no HTTP response is very likely raw PHP-FPM (FastCGI).
    responded = False
    for path in args.paths:
        for attempt_tls in ([True, False] if use_tls else [False, True]):
            r = fetch_http(host, port, path, args.timeout, attempt_tls)
            if r is None:
                continue
            responded = True
            status, headers, body = r
            result["is_web"] = True
            result["tls"] = attempt_tls
            result["status_code"] = status
            result["server"] = headers.get("server")
            result["powered_by"] = headers.get("x-powered-by")
            scheme = "https" if attempt_tls else "http"
            result["url"] = f"{scheme}://{host}:{port}{path}"

            is_php, version, signals = detect_php(status, headers, body)
            if signals:
                result["signals"] = sorted(set(result["signals"] + signals))
            if is_php:
                result["is_php"] = True
            if version and not result["php_version"]:
                result["php_version"] = version
            break  # got an HTTP response on this path; move to next path
        if result["is_php"] and result["php_version"]:
            break  # no need to probe further paths

    if not responded:
        if port == 9000:
            result["is_php"] = True
            result["note"] = ("Port 9000 open, no HTTP response - likely "
                              "PHP-FPM / FastCGI listener")
            result["signals"].append("Port 9000 open (probable PHP-FPM)")
        else:
            result["note"] = "TCP open but no HTTP response"

    if result["is_php"]:
        result["support"] = classify_version(result["php_version"], today)

    return result


def run_scan(hosts, ports, args, on_progress=None):
    today = (datetime.date.fromisoformat(args.today) if args.today
             else datetime.date.today())
    jobs = [(h, p) for h in hosts for p in ports]
    total = len(jobs)
    results = []
    done = 0
    start = time.time()
    cli_progress = getattr(args, "progress", False)

    if cli_progress:
        print(f"[*] Scanning {len(hosts)} host(s) x {len(ports)} port(s) "
              f"= {total} probes, {args.workers} workers", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        future_map = {ex.submit(scan_host_port, h, p, args, today): (h, p)
                      for h, p in jobs}
        for fut in concurrent.futures.as_completed(future_map):
            done += 1
            if cli_progress and (done % 50 == 0 or done == total):
                print(f"\r[*] {done}/{total} probes complete", end="",
                      file=sys.stderr, flush=True)
            if on_progress and (done % 10 == 0 or done == total):
                on_progress(done, total)
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                results.append(res)
    if cli_progress:
        print("", file=sys.stderr)

    elapsed = round(time.time() - start, 1)
    results.sort(key=lambda r: (socket_sort_key(r["host"]), r["port"]))
    return results, today, elapsed


def run_pipeline(hosts, ports, args, on_progress=None, on_phase=None):
    """Full inventory pipeline shared by the CLI and the GUI server:
    scan -> (optional) reverse DNS -> (optional) KEV correlation.
    Returns (results, meta, summary)."""
    if on_phase:
        on_phase("scanning")
    results, today, elapsed = run_scan(hosts, ports, args,
                                       on_progress=on_progress)

    if getattr(args, "resolve", False):
        if on_phase:
            on_phase("resolving hostnames")
        resolve_hosts(results, timeout=getattr(args, "timeout", 3.0))
    else:
        for r in results:
            r.setdefault("hostname", None)

    kev_meta = None
    if getattr(args, "kev", False):
        if on_phase:
            on_phase("fetching CISA KEV")
        catalog, kev_meta = load_kev(args)
        if catalog:
            if on_phase:
                on_phase("correlating KEV")
            annotate_kev(results, catalog)

    summary = summarize(results)
    if getattr(args, "kev", False):
        summary["kev"] = kev_summary(results)

    meta = {
        "tool_version": __version__,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_date": today.isoformat(),
        "target_count": len(hosts),
        "port_count": len(ports),
        "ports": ports,
        "elapsed_s": elapsed,
        "resolve": bool(getattr(args, "resolve", False)),
        "kev_enabled": bool(getattr(args, "kev", False)),
        "kev_meta": kev_meta,
        "summary": summary,
    }
    return results, meta, summary


def socket_sort_key(host):
    try:
        return (0, int(ipaddress.ip_address(host)))
    except ValueError:
        return (1, host)


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------
def resolve_hosts(results, timeout=2.0, workers=50):
    """Reverse-resolve (PTR) each unique host in results, in parallel.

    Adds result['hostname'] (str or None). Lookups are capped at a short
    timeout so a missing PTR record does not stall the run.
    """
    hosts = sorted({r["host"] for r in results}, key=socket_sort_key)
    if not hosts:
        return {}
    socket.setdefaulttimeout(min(timeout, 3.0))

    def rev(h):
        try:
            return h, socket.gethostbyaddr(h)[0]
        except (OSError, socket.herror, socket.gaierror, UnicodeError):
            return h, None
        except Exception:
            return h, None

    cache = {}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(workers, len(hosts))) as ex:
        for h, name in ex.map(rev, hosts):
            cache[h] = name
    socket.setdefaulttimeout(None)
    for r in results:
        r["hostname"] = cache.get(r["host"])
    return cache


# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities) correlation
# ---------------------------------------------------------------------------
# Web-server products we can recognize in a Server header and map to a KEV
# vendor/product. Matching is word-boundary and product-specific to avoid
# correlating, say, an Apache HTTP Server banner with Apache Struts CVEs.
# (token-label, Server-header regex w/ optional version, vendor_sub, product_sub)
SERVER_PRODUCTS = [
    ("Apache httpd", r"apache(?:/(\d+\.\d+(?:\.\d+)?))?", "apache", "http server"),
    ("nginx", r"nginx(?:/(\d+\.\d+(?:\.\d+)?))?", "", "nginx"),
    ("OpenResty", r"openresty(?:/(\d+\.\d+(?:\.\d+)?))?", "", "openresty"),
    ("LiteSpeed", r"litespeed", "", "litespeed"),
    ("Microsoft IIS", r"iis(?:/(\d+\.\d+))?", "microsoft", "iis"),
    ("Apache Tomcat", r"tomcat(?:/(\d+\.\d+(?:\.\d+)?))?", "apache", "tomcat"),
]


def ver_tuple(v):
    """'8.3.8' -> (8, 3, 8); returns None if no digits."""
    parts = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in parts[:4]) if parts else None


def _word(token, text):
    return re.search(r"\b" + re.escape(token) + r"\b", text or "",
                     re.IGNORECASE) is not None


def software_targets(result):
    """Software fingerprinted on a host, as (label, version, vendor_sub,
    product_sub) tuples used to match KEV entries."""
    targets = []
    if result.get("is_php"):
        targets.append(("PHP", result.get("php_version"), "", "php"))
    server = result.get("server") or ""
    for label, rx, vendor_sub, product_sub in SERVER_PRODUCTS:
        m = re.search(rx, server, re.IGNORECASE)
        if m:
            ver = m.group(1) if m.re.groups else None
            targets.append((label, ver, vendor_sub, product_sub))
    return targets


def kev_match_entry(entry, vendor_sub, product_sub):
    prod = entry.get("product") or ""
    vend = entry.get("vendorProject") or ""
    if not _word(product_sub, prod):
        return False
    if vendor_sub and not _word(vendor_sub, vend):
        return False
    return True


def parse_constraints(desc):
    """Best-effort extraction of version constraints from a KEV description.

    KEV shortDescriptions are free text and often omit versions entirely, so
    this is advisory: it refines a match when a constraint is stated and is
    silent otherwise.
    """
    d = desc or ""
    rules = []
    # Branch-specific: "8.1.* before 8.1.29" / "8.1.x before 8.1.29"
    for m in re.finditer(r"\d+\.\d+\.(?:\*|x)\s+before\s+(\d+\.\d+\.\d+)",
                         d, re.IGNORECASE):
        rules.append(("branch_before", ver_tuple(m.group(1))))
    branch_patches = {t for typ, t in rules if typ == "branch_before"}
    # Generic "before X" / "prior to X" / "earlier than X"
    for m in re.finditer(
            r"(?:before|prior to|earlier than)\s+(\d+\.\d+(?:\.\d+)?)",
            d, re.IGNORECASE):
        t = ver_tuple(m.group(1))
        if t not in branch_patches:
            rules.append(("before", t))
    # "X and earlier/prior/below", "through X", "up to and including X"
    for m in re.finditer(
            r"(\d+\.\d+(?:\.\d+)?)\s+and\s+(?:earlier|prior|below)",
            d, re.IGNORECASE):
        rules.append(("le", ver_tuple(m.group(1))))
    for m in re.finditer(
            r"(?:through|up to and including)\s+(\d+\.\d+(?:\.\d+)?)",
            d, re.IGNORECASE):
        rules.append(("le", ver_tuple(m.group(1))))
    # Exact single version: "affecting version 2.4.49"
    for m in re.finditer(r"version\s+(\d+\.\d+\.\d+)", d, re.IGNORECASE):
        t = ver_tuple(m.group(1))
        if t not in branch_patches and ("before", t) not in rules:
            rules.append(("exact", t))
    return rules


def evaluate_constraints(detected, rules):
    """Return 'affected' | 'patched' | 'unknown' for a detected version."""
    if not detected or not rules:
        return "unknown"
    for typ, t in rules:
        if typ == "before" and detected < t:
            return "affected"
        if typ == "le" and detected <= t:
            return "affected"
        if typ == "exact" and detected[:len(t)] == t:
            return "affected"
    branch_rules = [t for typ, t in rules if typ == "branch_before"]
    if branch_rules:
        db = detected[:2]
        by_branch = {t[:2]: t for t in branch_rules}
        if db in by_branch:
            return "affected" if detected < by_branch[db] else "patched"
        branches = sorted(by_branch)
        if db < branches[0]:
            return "affected"   # older than the earliest patched branch
        if db > branches[-1]:
            return "patched"    # newer than the latest affected branch
        return "unknown"
    if any(typ in ("before", "le", "exact") for typ, _ in rules):
        return "patched"
    return "unknown"


def load_kev(args):
    """Load the KEV catalog. Priority: --kev-file, else fetch --kev-url (with
    optional cache fallback). Returns (catalog_or_None, meta_dict)."""
    meta = {"source": None, "catalogVersion": None, "dateReleased": None,
            "count": 0, "error": None}
    data = None
    kev_file = getattr(args, "kev_file", None)
    kev_cache = getattr(args, "kev_cache", None)

    if kev_file:
        try:
            with open(kev_file, "rb") as f:
                data = f.read()
            meta["source"] = f"file: {kev_file}"
        except OSError as e:
            meta["error"] = f"Could not read KEV file: {e}"
            return None, meta
    else:
        url = getattr(args, "kev_url", None) or KEV_URL_DEFAULT
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            timeout = max(getattr(args, "timeout", 3.0), 20)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                data = r.read()
            meta["source"] = url
            if kev_cache:
                try:
                    with open(kev_cache, "wb") as f:
                        f.write(data)
                except OSError:
                    pass
        except Exception as e:
            if kev_cache and os.path.exists(kev_cache):
                try:
                    with open(kev_cache, "rb") as f:
                        data = f.read()
                    meta["source"] = f"cache: {kev_cache} (live fetch failed)"
                    meta["error"] = f"Live fetch failed, used cache: {e}"
                except OSError:
                    pass
            if data is None:
                meta["error"] = f"KEV fetch failed: {e}"
                return None, meta

    try:
        catalog = json.loads(data)
    except Exception as e:
        meta["error"] = f"KEV parse failed: {e}"
        return None, meta

    meta["catalogVersion"] = catalog.get("catalogVersion")
    meta["dateReleased"] = catalog.get("dateReleased")
    meta["count"] = catalog.get("count") or len(catalog.get("vulnerabilities", []))
    return catalog, meta


def annotate_kev(results, catalog):
    """Attach result['kev_matches'] for each host based on fingerprinted
    software. Each match carries a best-effort verdict."""
    vulns = catalog.get("vulnerabilities", [])
    rules_cache = [(v, parse_constraints(v.get("shortDescription", "")))
                   for v in vulns]
    rank = {"affected": 0, "unknown": 1, "patched": 2}

    for r in results:
        best = {}
        for label, ver, vendor_sub, product_sub in software_targets(r):
            dt = ver_tuple(ver)
            for v, rules in rules_cache:
                if not kev_match_entry(v, vendor_sub, product_sub):
                    continue
                verdict = evaluate_constraints(dt, rules) if dt else "unknown"
                cve = v.get("cveID")
                m = {
                    "cveID": cve,
                    "name": v.get("vulnerabilityName"),
                    "product": v.get("product"),
                    "vendor": v.get("vendorProject"),
                    "dateAdded": v.get("dateAdded"),
                    "dueDate": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse"),
                    "matched_on": label + (f" {ver}" if ver else ""),
                    "verdict": verdict,
                }
                if cve not in best or rank[verdict] < rank[best[cve]["verdict"]]:
                    best[cve] = m
        r["kev_matches"] = sorted(
            best.values(), key=lambda m: (rank[m["verdict"]], m["cveID"] or ""))


def kev_summary(results):
    services, cves, affected, ransom = set(), set(), set(), set()
    for r in results:
        for m in r.get("kev_matches", []):
            cves.add(m["cveID"])
            services.add((r["host"], r["port"]))
            if m["verdict"] == "affected":
                affected.add((r["host"], r["port"], m["cveID"]))
            if (m.get("ransomware") or "").lower() == "known":
                ransom.add(m["cveID"])
    return {"services_with_kev": len(services), "unique_cves": len(cves),
            "likely_affected": len(affected), "ransomware_cves": len(ransom)}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
STATUS_LABEL = {
    "active": "Supported",
    "security_only": "Security-only",
    "eol": "END OF LIFE",
    "unknown": "Version unknown",
}


def summarize(results):
    php = [r for r in results if r["is_php"]]
    counts = {"active": 0, "security_only": 0, "eol": 0, "unknown": 0}
    for r in php:
        st = (r["support"] or {}).get("status", "unknown")
        counts[st] = counts.get(st, 0) + 1
    return {
        "hosts_with_open_ports": len({r["host"] for r in results}),
        "web_servers": sum(1 for r in results if r["is_web"]),
        "php_servers": len(php),
        "php_active": counts["active"],
        "php_security_only": counts["security_only"],
        "php_eol": counts["eol"],
        "php_unknown_version": counts["unknown"],
    }


def render_json(results, meta):
    return json.dumps({"meta": meta, "results": results}, indent=2)


def render_csv(results):
    cols = ["host", "hostname", "port", "tls", "is_web", "is_php",
            "php_version", "support_status", "support_detail", "server",
            "powered_by", "status_code", "url", "signals",
            "kev_cves", "kev_affected", "note"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in results:
        sup = r.get("support") or {}
        kev = r.get("kev_matches", [])
        kev_cves = "; ".join(f"{m['cveID']}({m['verdict']})" for m in kev)
        kev_aff = "; ".join(m["cveID"] for m in kev
                            if m["verdict"] == "affected")
        w.writerow([
            r["host"], r.get("hostname") or "", r["port"], r["tls"],
            r["is_web"], r["is_php"], r.get("php_version") or "",
            sup.get("status", ""), sup.get("detail", ""),
            r.get("server") or "", r.get("powered_by") or "",
            r.get("status_code") or "", r.get("url") or "",
            "; ".join(r.get("signals", [])), kev_cves, kev_aff,
            r.get("note") or "",
        ])
    return buf.getvalue()


def write_json(results, meta, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_json(results, meta))


def write_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write(render_csv(results))


def render_html(results, meta, summary, path=None):
    e = html.escape
    php = [r for r in results if r["is_php"]]
    order = {"eol": 0, "security_only": 1, "unknown": 2, "active": 3}
    php.sort(key=lambda r: order.get((r["support"] or {}).get("status",
                                                              "unknown"), 9))

    badge_css = {
        "eol": "background:#b91c1c;color:#fff;",
        "security_only": "background:#b45309;color:#fff;",
        "active": "background:#15803d;color:#fff;",
        "unknown": "background:#4b5563;color:#fff;",
    }

    def badge(st):
        return (f'<span class="badge" style="{badge_css.get(st, badge_css["unknown"])}">'
                f'{e(STATUS_LABEL.get(st, st))}</span>')

    def host_cell(r):
        url = r.get("url")
        inner = (f'<a href="{e(url)}" target="_blank" rel="noopener">{e(r["host"])}</a>'
                 if url else e(r["host"]))
        hn = r.get("hostname")
        if hn and hn != r["host"]:
            inner += f'<div class="hn">{e(hn)}</div>'
        return inner

    kev_verdict_css = {
        "affected": "background:#b91c1c;color:#fff;",
        "unknown": "background:#b45309;color:#fff;",
        "patched": "background:#4b5563;color:#fff;",
    }
    kev_verdict_label = {"affected": "Likely affected", "unknown": "Review",
                         "patched": "Likely patched"}

    def kev_cell(r):
        matches = r.get("kev_matches", [])
        if not matches:
            return '<span class="muted">—</span>'
        chips = []
        for m in matches[:6]:
            css = kev_verdict_css.get(m["verdict"], kev_verdict_css["unknown"])
            chips.append(f'<span class="kevchip" style="{css}" '
                         f'title="{e(m["verdict"])}">{e(m["cveID"])}</span>')
        more = (f' <span class="muted">+{len(matches) - 6}</span>'
                if len(matches) > 6 else "")
        return " ".join(chips) + more

    kev_on = meta.get("kev_enabled")
    kev_th = "<th>KEV</th>" if kev_on else ""

    rows = []
    for r in php:
        st = (r["support"] or {}).get("status", "unknown")
        detail = (r["support"] or {}).get("detail", "") if r["support"] else ""
        sig = e("; ".join(r.get("signals", [])) or (r.get("note") or ""))
        kev_td = f'<td>{kev_cell(r)}</td>' if kev_on else ""
        rows.append(f"""<tr class="row-{st}">
  <td>{host_cell(r)}</td>
  <td>{r['port']}{' <span class="tls">TLS</span>' if r['tls'] else ''}</td>
  <td>{e(r.get('php_version') or '—')}</td>
  <td>{badge(st)}</td>
  <td class="detail">{e(detail)}</td>
  <td class="server">{e(r.get('server') or r.get('powered_by') or '—')}</td>
  {kev_td}
  <td class="sig">{sig}</td>
</tr>""")

    other_web = [r for r in results if r["is_web"] and not r["is_php"]]
    other_rows = []
    for r in other_web:
        kev_td = f'<td>{kev_cell(r)}</td>' if kev_on else ""
        other_rows.append(f"""<tr>
  <td>{host_cell(r)}</td>
  <td>{r['port']}{' <span class="tls">TLS</span>' if r['tls'] else ''}</td>
  <td>{r.get('status_code') or '—'}</td>
  <td class="server">{e(r.get('server') or '—')}</td>
  {kev_td}
</tr>""")

    # KEV findings section (one row per host:port x CVE)
    kev_rows = []
    if kev_on:
        for r in results:
            for m in r.get("kev_matches", []):
                css = kev_verdict_css.get(m["verdict"], kev_verdict_css["unknown"])
                ransom = ("Yes" if (m.get("ransomware") or "").lower() == "known"
                          else "—")
                nvd = f"https://nvd.nist.gov/vuln/detail/{m['cveID']}"
                kev_rows.append((m["verdict"], f"""<tr>
  <td>{host_cell(r)}</td>
  <td>{r['port']}</td>
  <td><a href="{e(nvd)}" target="_blank" rel="noopener">{e(m['cveID'])}</a></td>
  <td>{e(m.get('name') or '')}</td>
  <td class="server">{e(m.get('matched_on') or '')}</td>
  <td><span class="badge" style="{css}">{e(kev_verdict_label.get(m['verdict'], m['verdict']))}</span></td>
  <td>{ransom}</td>
  <td class="detail">{e(m.get('dateAdded') or '')}</td>
</tr>"""))
        kev_rows.sort(key=lambda t: {"affected": 0, "unknown": 1,
                                     "patched": 2}.get(t[0], 9))
    kev_rows_html = "".join(h for _, h in kev_rows)

    # KEV header note, summary cards, findings section, and footnote.
    kev_header = kev_cards = kev_section = kev_note = ""
    if kev_on:
        ks = summary.get("kev", {})
        km = meta.get("kev_meta") or {}
        src = km.get("catalogVersion") or km.get("dateReleased") or "fetched"
        if km.get("error"):
            kev_header = (f' &middot; <span style="color:#fca5a5">KEV: '
                          f'{e(km["error"])}</span>')
        else:
            kev_header = f' &middot; CISA KEV {e(str(src))}'
        kev_cards = (
            f'    <div class="card kev"><div class="n">{ks.get("likely_affected", 0)}</div>'
            f'<div class="l">KEV likely affected</div></div>\n'
            f'    <div class="card"><div class="n">{ks.get("unique_cves", 0)}</div>'
            f'<div class="l">KEV CVEs matched</div></div>\n'
            f'    <div class="card kev"><div class="n">{ks.get("ransomware_cves", 0)}</div>'
            f'<div class="l">Ransomware-linked</div></div>\n')
        if kev_rows_html:
            kev_section = (
                '\n  <h2>Known exploited vulnerabilities (CISA KEV)</h2>\n'
                '  <table><thead><tr><th>Host</th><th>Port</th><th>CVE</th>'
                '<th>Vulnerability</th><th>Matched on</th><th>Verdict</th>'
                '<th>Ransomware</th><th>Added</th></tr></thead><tbody>'
                + kev_rows_html + '</tbody></table>\n')
        else:
            kev_section = ('\n  <h2>Known exploited vulnerabilities (CISA KEV)</h2>'
                           '\n  <p class="muted">No KEV entries matched the '
                           'detected software.</p>\n')
        kev_note = (' KEV correlation matches CISA\'s known-exploited catalog '
                    'by product/vendor; "Likely affected/patched" is a '
                    'best-effort guess from any version stated in the CVE '
                    'description and must be confirmed against each host\'s '
                    'actual patch level. "Review" means the CVE applies to the '
                    'product but the version could not be compared.')

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP Web Server Inventory</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
         Helvetica, Arial, sans-serif; margin: 0; background:#f6f7f9;
         color:#111827; line-height:1.45; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#0f1115; color:#e5e7eb; }}
    .card, table {{ background:#171a21 !important; }}
    th {{ background:#1f2430 !important; }}
    td, th {{ border-color:#2a2f3a !important; }}
    .muted {{ color:#9aa3b2 !important; }}
  }}
  header {{ background:#111827; color:#fff; padding:24px 28px; }}
  header h1 {{ margin:0 0 4px; font-size:20px; }}
  header .muted {{ color:#9ca3af; font-size:13px; }}
  main {{ max-width:1100px; margin:0 auto; padding:24px 20px 60px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:12px; margin:20px 0 28px; }}
  .card {{ background:#fff; border-radius:10px; padding:16px 18px;
          box-shadow:0 1px 2px rgba(0,0,0,.06); }}
  .card .n {{ font-size:26px; font-weight:700; }}
  .card .l {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em;
             color:#6b7280; margin-top:2px; }}
  .card.eol .n {{ color:#b91c1c; }}
  .card.sec .n {{ color:#b45309; }}
  .card.ok .n {{ color:#15803d; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.05em;
       color:#6b7280; margin:28px 0 10px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
          border-radius:10px; overflow:hidden; box-shadow:0 1px 2px rgba(0,0,0,.06); }}
  th, td {{ text-align:left; padding:9px 12px; border-bottom:1px solid #eceef1;
           font-size:13px; vertical-align:top; }}
  th {{ background:#f3f4f6; font-size:11px; text-transform:uppercase;
       letter-spacing:.04em; color:#6b7280; }}
  tr.row-eol td {{ background:rgba(185,28,28,.06); }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:999px;
           font-size:11px; font-weight:700; white-space:nowrap; }}
  .tls {{ font-size:9px; background:#2563eb; color:#fff; padding:1px 4px;
         border-radius:4px; vertical-align:middle; }}
  .detail, .sig {{ color:#4b5563; font-size:12px; }}
  .server {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size:11.5px; }}
  .hn {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size:11px; color:#6b7280; margin-top:2px; }}
  .kevchip {{ display:inline-block; padding:1px 6px; border-radius:4px;
             font-size:10.5px; font-weight:600; margin:1px 1px;
             font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }}
  .card.kev .n {{ color:#b91c1c; }}
  .muted {{ color:#6b7280; }}
  .note {{ font-size:12px; color:#6b7280; margin-top:8px; }}
  footer {{ max-width:1100px; margin:0 auto; padding:0 20px 40px;
           font-size:12px; color:#6b7280; }}
</style>
</head>
<body>
<header>
  <h1>PHP Web Server Inventory</h1>
  <div class="muted">Generated {e(meta['generated'])} &middot;
    {e(str(meta['target_count']))} target host(s) &middot;
    {e(str(meta['port_count']))} port(s) &middot; scan took {e(str(meta['elapsed_s']))}s{kev_header}</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n">{summary['web_servers']}</div><div class="l">Web servers</div></div>
    <div class="card"><div class="n">{summary['php_servers']}</div><div class="l">Running PHP</div></div>
    <div class="card eol"><div class="n">{summary['php_eol']}</div><div class="l">End of life</div></div>
    <div class="card sec"><div class="n">{summary['php_security_only']}</div><div class="l">Security-only</div></div>
    <div class="card ok"><div class="n">{summary['php_active']}</div><div class="l">Supported</div></div>
    <div class="card"><div class="n">{summary['php_unknown_version']}</div><div class="l">Version unknown</div></div>
{kev_cards}  </div>

  <h2>PHP servers ({len(php)})</h2>
  {"<table><thead><tr><th>Host</th><th>Port</th><th>PHP version</th><th>Support status</th><th>Lifecycle</th><th>Server</th>" + kev_th + "<th>Evidence</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>" if rows else '<p class="muted">No PHP servers detected.</p>'}

  <h2>Other web servers ({len(other_web)})</h2>
  {"<table><thead><tr><th>Host</th><th>Port</th><th>HTTP status</th><th>Server</th>" + kev_th + "</tr></thead><tbody>" + "".join(other_rows) + "</tbody></table>" if other_rows else '<p class="muted">None.</p>'}
{kev_section}
  <p class="note">PHP lifecycle dates are from php.net's supported-versions
  schedule. "End of life" means the branch no longer receives security fixes
  and should be prioritized for upgrade. Version detection relies on headers
  the server chooses to disclose; a server that hides its version can still be
  running an outdated PHP, so absence of a version is not evidence of safety.{kev_note}</p>
</main>
<footer>
  phpscan v{e(meta['tool_version'])} &middot; authorized internal inventory use only.
</footer>
</body>
</html>"""
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)
    return doc


def write_html(results, meta, summary, path):
    render_html(results, meta, summary, path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="phpscan",
        description="Inventory PHP web servers on an internal network and "
                    "flag unsupported versions.",
        epilog="AUTHORIZED USE ONLY. Scan only hosts you own or have written "
               "permission to assess.")
    p.add_argument("targets", nargs="*",
                   help="Targets: CIDR (10.0.0.0/24), range (10.0.0.1-50), "
                        "IP, or hostname. Space- or comma-separated.")
    p.add_argument("-t", "--targets-file",
                   help="File with one target spec per line (# comments ok).")
    p.add_argument("-p", "--ports", default=None,
                   help="Comma-separated ports (default: "
                        + ",".join(map(str, DEFAULT_PORTS)) + ").")
    p.add_argument("--paths", default=",".join(DEFAULT_PROBE_PATHS),
                   help="Comma-separated URL paths to probe per server.")
    p.add_argument("-w", "--workers", type=int, default=100,
                   help="Concurrent workers (default: 100).")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="Per-connection timeout in seconds (default: 3.0).")
    p.add_argument("-o", "--output", default="php_inventory",
                   help="Output basename; writes .html/.csv/.json "
                        "(default: php_inventory).")
    p.add_argument("--formats", default="html,csv,json",
                   help="Report formats to write (default: html,csv,json).")
    p.add_argument("--today", default=None,
                   help="Override 'today' (YYYY-MM-DD) for lifecycle checks.")
    p.add_argument("-r", "--resolve", action="store_true",
                   help="Reverse-resolve (PTR) responding hosts to hostnames.")
    p.add_argument("--kev", action="store_true",
                   help="Correlate findings with the CISA KEV catalog.")
    p.add_argument("--kev-url", default=KEV_URL_DEFAULT,
                   help="KEV JSON feed URL (default: CISA).")
    p.add_argument("--kev-file", default=None,
                   help="Use a local KEV JSON file instead of fetching "
                        "(for air-gapped networks).")
    p.add_argument("--kev-cache", default=None,
                   help="Cache the fetched KEV feed here; reused if a later "
                        "fetch fails.")
    p.add_argument("--serve", action="store_true",
                   help="Launch the browser GUI instead of scanning now.")
    p.add_argument("--bind", default="127.0.0.1",
                   help="GUI bind address (default: 127.0.0.1 - localhost).")
    p.add_argument("--serve-port", type=int, default=8600,
                   help="GUI port (default: 8600).")
    p.add_argument("--no-progress", dest="progress", action="store_false",
                   help="Suppress the progress counter.")
    p.add_argument("--yes", action="store_true",
                   help="Skip the authorization confirmation prompt.")
    p.add_argument("--version", action="version",
                   version=f"phpscan {__version__}")
    p.set_defaults(progress=True)
    return p


def load_targets_file(path):
    specs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                specs.append(line)
    return specs


def confirm_authorization(hosts, assume_yes):
    print("=" * 68, file=sys.stderr)
    print(" phpscan - authorized internal inventory use only", file=sys.stderr)
    print(f" About to scan {len(hosts)} host(s).", file=sys.stderr)
    print(" Scan only networks you own or are explicitly permitted to assess.",
          file=sys.stderr)
    print("=" * 68, file=sys.stderr)
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("[!] Non-interactive run without --yes; aborting for safety.",
              file=sys.stderr)
        return False
    try:
        return input("Proceed? [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Browser GUI (local web server)
# ---------------------------------------------------------------------------
GUI_MAX_PROBES = 200000  # guard against huge ranges in the synchronous GUI

GUI_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>phpscan - PHP Inventory</title>
<style>
  :root { color-scheme: light dark;
    --bg:#f6f7f9; --fg:#111827; --panel:#fff; --line:#eceef1; --muted:#6b7280;
    --head:#111827; --accent:#2563eb; --th:#f3f4f6; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0f1115; --fg:#e5e7eb; --panel:#171a21; --line:#2a2f3a;
      --muted:#9aa3b2; --head:#0b0d12; --th:#1f2430; } }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    margin:0; background:var(--bg); color:var(--fg); line-height:1.45; }
  header { background:var(--head); color:#fff; padding:18px 24px; }
  header h1 { margin:0; font-size:18px; letter-spacing:.3px; }
  header .sub { color:#9ca3af; font-size:12.5px; margin-top:3px; }
  main { max-width:1120px; margin:0 auto; padding:20px 18px 70px; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:12px;
    padding:18px; box-shadow:0 1px 2px rgba(0,0,0,.05); }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:14px 18px; }
  @media (max-width:720px){ .grid{ grid-template-columns:1fr; } }
  label { display:block; font-size:12px; font-weight:600; text-transform:uppercase;
    letter-spacing:.04em; color:var(--muted); margin:0 0 5px; }
  input[type=text], textarea, input[type=number] { width:100%; padding:9px 11px;
    border:1px solid var(--line); border-radius:8px; background:var(--bg); color:var(--fg);
    font-size:14px; font-family:inherit; }
  textarea { resize:vertical; min-height:70px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }
  .hint { font-size:11.5px; color:var(--muted); margin-top:4px; font-weight:400; text-transform:none; letter-spacing:0; }
  .row-inline { display:flex; gap:22px; flex-wrap:wrap; align-items:center; margin-top:4px; }
  .chk { display:flex; align-items:center; gap:7px; font-size:13.5px; }
  .chk input { width:16px; height:16px; }
  .actions { display:flex; gap:12px; align-items:center; margin-top:18px; flex-wrap:wrap; }
  button { background:var(--accent); color:#fff; border:0; border-radius:8px;
    padding:10px 18px; font-size:14px; font-weight:600; cursor:pointer; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  button.sec { background:transparent; color:var(--accent); border:1px solid var(--accent); }
  .warn { font-size:12px; color:var(--muted); margin-top:14px; border-top:1px solid var(--line); padding-top:12px; }
  #progress { margin-top:16px; display:none; }
  .bar { height:8px; background:var(--line); border-radius:999px; overflow:hidden; }
  .bar > div { height:100%; width:0%; background:var(--accent); transition:width .3s; }
  .phase { font-size:12.5px; color:var(--muted); margin-top:7px; }
  .err { color:#dc2626; font-size:13px; margin-top:12px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:10px; margin:16px 0; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:13px 15px; }
  .card .n { font-size:23px; font-weight:700; }
  .card .l { font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin-top:2px; }
  .card.eol .n{color:#b91c1c;} .card.sec .n{color:#b45309;} .card.ok .n{color:#15803d;} .card.kev .n{color:#b91c1c;}
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin:26px 0 9px; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
    border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  th,td { text-align:left; padding:8px 11px; border-bottom:1px solid var(--line); font-size:13px; vertical-align:top; }
  th { background:var(--th); font-size:10.5px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
  tr.eol td { background:rgba(185,28,28,.07); }
  .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; white-space:nowrap; color:#fff; }
  .b-eol{background:#b91c1c;} .b-sec{background:#b45309;} .b-active{background:#15803d;} .b-unknown{background:#4b5563;}
  .b-affected{background:#b91c1c;} .b-patched{background:#4b5563;} .b-review{background:#b45309;}
  .tls { font-size:9px; background:var(--accent); color:#fff; padding:1px 4px; border-radius:4px; }
  .hn,.mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:11px; color:var(--muted); }
  .kevchip { display:inline-block; padding:1px 6px; border-radius:4px; font-size:10.5px; font-weight:600;
    margin:1px; color:#fff; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .muted { color:var(--muted); }
  #exports { display:none; gap:10px; margin:6px 0 2px; flex-wrap:wrap; }
  a.dl { text-decoration:none; }
</style>
</head>
<body>
<header>
  <h1>phpscan &middot; PHP web-server inventory</h1>
  <div class="sub">Scan an internal network for PHP, flag unsupported versions, and correlate with CISA KEV. Authorized use only.</div>
</header>
<main>
  <div class="panel">
    <div class="grid">
      <div style="grid-column:1/-1">
        <label for="targets">Targets</label>
        <textarea id="targets" placeholder="10.0.0.0/24&#10;192.168.1.10-50&#10;intranet.corp.local"></textarea>
        <div class="hint">CIDR, dashed range, IP or hostname. One per line, or space/comma separated.</div>
      </div>
      <div>
        <label for="ports">Ports</label>
        <input type="text" id="ports" value="80,443,8080,8443,8000,8008,8888,3000,5000,7001,9000">
      </div>
      <div>
        <label for="paths">Probe paths</label>
        <input type="text" id="paths" value="/,/index.php,/login.php">
      </div>
      <div>
        <label for="workers">Workers</label>
        <input type="number" id="workers" value="100" min="1" max="500">
      </div>
      <div>
        <label for="timeout">Timeout (s)</label>
        <input type="number" id="timeout" value="3" min="0.2" step="0.1">
      </div>
      <div style="grid-column:1/-1">
        <label>Options</label>
        <div class="row-inline">
          <span class="chk"><input type="checkbox" id="resolve" checked><label for="resolve" style="margin:0;text-transform:none;letter-spacing:0;font-weight:500;color:var(--fg)">Resolve hostnames (reverse DNS)</label></span>
          <span class="chk"><input type="checkbox" id="kev" checked><label for="kev" style="margin:0;text-transform:none;letter-spacing:0;font-weight:500;color:var(--fg)">Check CISA KEV (known exploited CVEs)</label></span>
        </div>
      </div>
      <div style="grid-column:1/-1" id="kevUrlWrap">
        <label for="kev_url">KEV feed URL</label>
        <input type="text" id="kev_url" value="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json">
        <div class="hint">Fetched by this machine at scan time. On an air-gapped network, point the CLI at a downloaded copy with --kev-file.</div>
      </div>
    </div>
    <div class="actions">
      <button id="scanBtn" onclick="startScan()">Scan</button>
      <span class="chk"><input type="checkbox" id="authack"><label for="authack" style="margin:0;text-transform:none;letter-spacing:0;font-weight:500;color:var(--fg)">I am authorized to scan these hosts</label></span>
    </div>
    <div id="progress">
      <div class="bar"><div id="barFill"></div></div>
      <div class="phase" id="phaseText"></div>
    </div>
    <div class="err" id="errBox" style="display:none"></div>
    <div class="warn">phpscan performs best-effort fingerprinting over normal HTTP requests. Only scan networks you own or are explicitly permitted to assess.</div>
  </div>

  <div id="results" style="display:none">
    <div id="exports">
      <a class="dl" id="dlHtml" target="_blank"><button class="sec">Export HTML</button></a>
      <a class="dl" id="dlCsv"><button class="sec">Export CSV</button></a>
      <a class="dl" id="dlJson"><button class="sec">Export JSON</button></a>
    </div>
    <div class="cards" id="cards"></div>
    <div id="tables"></div>
  </div>
</main>
<script>
var curJob = null, poll = null;
function $(id){ return document.getElementById(id); }
function esc(s){ var d=document.createElement('div'); d.textContent = (s==null?'':String(s)); return d.innerHTML; }

function startScan(){
  if(!$('authack').checked){ showErr("Please confirm you are authorized to scan these hosts."); return; }
  var targets = $('targets').value.split(/[\s,]+/).filter(Boolean);
  if(!targets.length){ showErr("Enter at least one target."); return; }
  showErr(null);
  var body = {
    targets: targets,
    ports: $('ports').value,
    paths: $('paths').value,
    workers: parseInt($('workers').value)||100,
    timeout: parseFloat($('timeout').value)||3,
    resolve: $('resolve').checked,
    kev: $('kev').checked,
    kev_url: $('kev_url').value
  };
  $('scanBtn').disabled = true;
  $('results').style.display='none';
  $('progress').style.display='block';
  setBar(0); $('phaseText').textContent = 'Starting...';
  fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(function(r){ return r.json().then(function(j){ return {ok:r.ok,j:j}; }); })
    .then(function(x){
      if(!x.ok){ throw new Error(x.j.error||'scan failed'); }
      curJob = x.j.job;
      $('phaseText').textContent = 'Scanning '+x.j.hosts+' host(s) x '+x.j.ports+' port(s)...';
      poll = setInterval(checkStatus, 700);
    })
    .catch(function(e){ fail(e.message); });
}

function checkStatus(){
  if(!curJob) return;
  fetch('/api/status?job='+curJob).then(function(r){ return r.json(); }).then(function(j){
    if(j.error){ fail(j.error); return; }
    if(j.total){ setBar(Math.round(100*j.done/j.total)); }
    $('phaseText').textContent = labelPhase(j.phase) + (j.total?(' - '+j.done+'/'+j.total+' probes'):'');
    if(j.state==='done'){ clearInterval(poll); poll=null; render(j.result); }
    else if(j.state==='error'){ fail(j.error||'scan error'); }
  }).catch(function(e){ /* transient; keep polling */ });
}

function labelPhase(p){
  var m={scanning:'Scanning ports','resolving hostnames':'Resolving hostnames',
    'fetching CISA KEV':'Fetching CISA KEV feed','correlating KEV':'Correlating KEV','done':'Complete'};
  return m[p]||p||'Working';
}
function setBar(pct){ $('barFill').style.width = pct+'%'; }
function showErr(msg){ var b=$('errBox'); if(!msg){ b.style.display='none'; return; } b.style.display='block'; b.textContent=msg; }
function fail(msg){ if(poll){clearInterval(poll);poll=null;} $('scanBtn').disabled=false; $('progress').style.display='none'; showErr(msg); }

function render(res){
  $('scanBtn').disabled=false;
  $('progress').style.display='none';
  var s = res.summary, meta = res.meta, rows = res.results;
  var kevOn = meta.kev_enabled;
  // export links
  $('dlHtml').href = '/api/report?job='+curJob+'&fmt=html';
  $('dlCsv').href  = '/api/report?job='+curJob+'&fmt=csv';
  $('dlJson').href = '/api/report?job='+curJob+'&fmt=json';
  $('exports').style.display='flex';

  var cards = [
    card(s.web_servers,'Web servers',''), card(s.php_servers,'Running PHP',''),
    card(s.php_eol,'End of life','eol'), card(s.php_security_only,'Security-only','sec'),
    card(s.php_active,'Supported','ok'), card(s.php_unknown_version,'Version unknown','')
  ];
  if(kevOn && s.kev){
    cards.push(card(s.kev.likely_affected,'KEV likely affected','kev'));
    cards.push(card(s.kev.unique_cves,'KEV CVEs matched',''));
    cards.push(card(s.kev.ransomware_cves,'Ransomware-linked','kev'));
  }
  $('cards').innerHTML = cards.join('');

  var php = rows.filter(function(r){return r.is_php;});
  var ord = {eol:0,security_only:1,unknown:2,active:3};
  php.sort(function(a,b){ return (ord[sStat(a)]||9)-(ord[sStat(b)]||9); });
  var other = rows.filter(function(r){return r.is_web && !r.is_php;});

  var html = '';
  html += '<h2>PHP servers ('+php.length+')</h2>';
  html += php.length ? phpTable(php,kevOn) : '<p class="muted">No PHP servers detected.</p>';
  html += '<h2>Other web servers ('+other.length+')</h2>';
  html += other.length ? otherTable(other) : '<p class="muted">None.</p>';
  if(kevOn){
    var km = meta.kev_meta||{};
    if(km.error){ html += '<h2>CISA KEV</h2><p class="err">'+esc(km.error)+'</p>'; }
    else { html += kevTable(rows, km); }
  }
  $('tables').innerHTML = html;
  $('results').style.display='block';
  $('results').scrollIntoView({behavior:'smooth'});
}

function card(n,l,cls){ return '<div class="card '+cls+'"><div class="n">'+n+'</div><div class="l">'+l+'</div></div>'; }
function sStat(r){ return (r.support&&r.support.status)||'unknown'; }
function hostCell(r){
  var h = r.url ? '<a href="'+esc(r.url)+'" target="_blank" rel="noopener">'+esc(r.host)+'</a>' : esc(r.host);
  if(r.hostname && r.hostname!==r.host){ h += '<div class="hn">'+esc(r.hostname)+'</div>'; }
  return h;
}
function statBadge(st){
  var m={eol:['b-eol','END OF LIFE'],security_only:['b-sec','Security-only'],active:['b-active','Supported'],unknown:['b-unknown','Version unknown']};
  var x=m[st]||m.unknown; return '<span class="badge '+x[0]+'">'+x[1]+'</span>';
}
function kevChips(r){
  var ms=r.kev_matches||[]; if(!ms.length) return '<span class="muted">—</span>';
  var cls={affected:'b-affected',patched:'b-patched',unknown:'b-review'};
  var out=ms.slice(0,6).map(function(m){ return '<span class="kevchip '+(cls[m.verdict]||'b-review')+'" title="'+esc(m.verdict)+'">'+esc(m.cveID)+'</span>'; }).join(' ');
  if(ms.length>6) out += ' <span class="muted">+'+(ms.length-6)+'</span>';
  return out;
}
function phpTable(php,kevOn){
  var th='<tr><th>Host</th><th>Port</th><th>PHP</th><th>Support</th><th>Lifecycle</th><th>Server</th>'+(kevOn?'<th>KEV</th>':'')+'<th>Evidence</th></tr>';
  var body=php.map(function(r){
    var st=sStat(r), det=(r.support&&r.support.detail)||'';
    var ev=(r.signals&&r.signals.join('; '))||r.note||'';
    return '<tr class="'+(st==='eol'?'eol':'')+'"><td>'+hostCell(r)+'</td><td>'+r.port+(r.tls?' <span class="tls">TLS</span>':'')+'</td>'+
      '<td>'+esc(r.php_version||'—')+'</td><td>'+statBadge(st)+'</td><td class="muted">'+esc(det)+'</td>'+
      '<td class="mono">'+esc(r.server||r.powered_by||'—')+'</td>'+(kevOn?('<td>'+kevChips(r)+'</td>'):'')+'<td class="muted">'+esc(ev)+'</td></tr>';
  }).join('');
  return '<table><thead>'+th+'</thead><tbody>'+body+'</tbody></table>';
}
function otherTable(other){
  var body=other.map(function(r){
    return '<tr><td>'+hostCell(r)+'</td><td>'+r.port+(r.tls?' <span class="tls">TLS</span>':'')+'</td><td>'+(r.status_code||'—')+'</td><td class="mono">'+esc(r.server||'—')+'</td></tr>';
  }).join('');
  return '<table><thead><tr><th>Host</th><th>Port</th><th>HTTP</th><th>Server</th></tr></thead><tbody>'+body+'</tbody></table>';
}
function kevTable(rows, km){
  var cls={affected:'b-affected',patched:'b-patched',unknown:'b-review'};
  var lbl={affected:'Likely affected',patched:'Likely patched',unknown:'Review'};
  var items=[];
  rows.forEach(function(r){ (r.kev_matches||[]).forEach(function(m){ items.push([r,m]); }); });
  items.sort(function(a,b){ var o={affected:0,unknown:1,patched:2}; return (o[a[1].verdict]||9)-(o[b[1].verdict]||9); });
  var src = km.catalogVersion||km.dateReleased||'feed';
  var head = '<h2>Known exploited vulnerabilities (CISA KEV '+esc(src)+')</h2>';
  if(!items.length) return head+'<p class="muted">No KEV entries matched the detected software.</p>';
  var body=items.map(function(it){
    var r=it[0], m=it[1];
    var nvd='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(m.cveID);
    var ransom=(m.ransomware&&m.ransomware.toLowerCase()==='known')?'Yes':'—';
    return '<tr><td>'+hostCell(r)+'</td><td>'+r.port+'</td>'+
      '<td><a href="'+nvd+'" target="_blank" rel="noopener">'+esc(m.cveID)+'</a></td>'+
      '<td>'+esc(m.name||'')+'</td><td class="mono">'+esc(m.matched_on||'')+'</td>'+
      '<td><span class="badge '+(cls[m.verdict]||'b-review')+'">'+(lbl[m.verdict]||m.verdict)+'</span></td>'+
      '<td>'+ransom+'</td><td class="muted">'+esc(m.dateAdded||'')+'</td></tr>';
  }).join('');
  return head+'<p class="muted" style="font-size:12px">Matched by product/vendor against CISA\'s known-exploited catalog. "Likely affected/patched" is inferred from any version in the CVE text and should be confirmed against the host\'s real patch level.</p>'+
    '<table><thead><tr><th>Host</th><th>Port</th><th>CVE</th><th>Vulnerability</th><th>Matched on</th><th>Verdict</th><th>Ransomware</th><th>Added</th></tr></thead><tbody>'+body+'</tbody></table>';
}
// hide KEV URL field when KEV unchecked
$('kev').addEventListener('change', function(){ $('kevUrlWrap').style.display = this.checked?'block':'none'; });
</script>
</body>
</html>
"""

_JOBS = {}
_JOBS_LOCK = threading.Lock()


def _job_new():
    jid = uuid.uuid4().hex[:12]
    with _JOBS_LOCK:
        _JOBS[jid] = {"state": "running", "phase": "starting", "done": 0,
                      "total": 0, "error": None, "result": None,
                      "started": time.time()}
    return jid


def _job_set(jid, **kw):
    with _JOBS_LOCK:
        if jid in _JOBS:
            _JOBS[jid].update(kw)


def _job_get(jid):
    with _JOBS_LOCK:
        j = _JOBS.get(jid)
        return dict(j) if j else None


def _run_job(jid, params, cli_args):
    try:
        specs = params.get("targets") or []
        hosts = parse_targets(specs)
        ports = parse_ports(params.get("ports"))
        a = argparse.Namespace(**vars(cli_args))
        a.timeout = max(0.2, float(params.get("timeout") or cli_args.timeout))
        a.workers = max(1, min(500, int(params.get("workers") or cli_args.workers)))
        a.resolve = bool(params.get("resolve"))
        a.kev = bool(params.get("kev"))
        a.kev_url = params.get("kev_url") or cli_args.kev_url
        a.today = None
        a.progress = False
        a.paths = normalize_paths(params.get("paths")
                                  or ",".join(DEFAULT_PROBE_PATHS))
        total = len(hosts) * len(ports)
        _job_set(jid, total=total, phase="scanning")

        def on_prog(done, tot):
            _job_set(jid, done=done, total=tot)

        def on_phase(ph):
            _job_set(jid, phase=ph)

        results, meta, summary = run_pipeline(hosts, ports, a,
                                              on_progress=on_prog,
                                              on_phase=on_phase)
        _job_set(jid, state="done", phase="done", done=total, total=total,
                 result={"meta": meta, "summary": summary, "results": results})
    except Exception as e:
        _job_set(jid, state="error", error=f"{type(e).__name__}: {e}")


class GUIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, GUI_HTML, "text/html; charset=utf-8")
        if u.path == "/api/status":
            q = urllib.parse.parse_qs(u.query)
            j = _job_get((q.get("job") or [""])[0])
            if not j:
                return self._send(404, json.dumps({"error": "no such job"}))
            out = {k: j[k] for k in ("state", "phase", "done", "total", "error")}
            if j["state"] == "done":
                out["result"] = j["result"]
            return self._send(200, json.dumps(out))
        if u.path == "/api/report":
            q = urllib.parse.parse_qs(u.query)
            j = _job_get((q.get("job") or [""])[0])
            fmt = (q.get("fmt") or ["html"])[0]
            if not j or j["state"] != "done":
                return self._send(404, json.dumps({"error": "job not complete"}))
            res = j["result"]
            results, meta, summary = res["results"], res["meta"], res["summary"]
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            if fmt == "json":
                return self._send(
                    200, render_json(results, meta), "application/json",
                    {"Content-Disposition":
                     f'attachment; filename="php_inventory_{ts}.json"'})
            if fmt == "csv":
                return self._send(
                    200, render_csv(results), "text/csv; charset=utf-8",
                    {"Content-Disposition":
                     f'attachment; filename="php_inventory_{ts}.csv"'})
            return self._send(
                200, render_html(results, meta, summary),
                "text/html; charset=utf-8",
                {"Content-Disposition":
                 f'attachment; filename="php_inventory_{ts}.html"'})
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path != "/api/scan":
            return self._send(404, json.dumps({"error": "not found"}))
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            params = json.loads(raw or b"{}")
        except Exception:
            return self._send(400, json.dumps({"error": "bad JSON"}))

        specs = params.get("targets") or []
        if isinstance(specs, str):
            specs = [s for s in re.split(r"[,\s]+", specs) if s]
        if not specs:
            return self._send(400, json.dumps({"error": "No targets provided."}))
        try:
            ports = parse_ports(params.get("ports"))
        except ValueError:
            return self._send(400, json.dumps({"error": "Invalid ports list."}))
        if not ports:
            return self._send(400, json.dumps({"error": "No valid ports."}))
        hosts = parse_targets(specs)
        if not hosts:
            return self._send(400, json.dumps({"error": "No valid targets."}))
        if len(hosts) * len(ports) > GUI_MAX_PROBES:
            return self._send(400, json.dumps({"error":
                f"Scan too large for the GUI ({len(hosts)} hosts x "
                f"{len(ports)} ports). Use the command line for this size."}))
        params["targets"] = specs
        jid = _job_new()
        threading.Thread(target=_run_job,
                         args=(jid, params, self.server.cli_args),
                         daemon=True).start()
        return self._send(200, json.dumps(
            {"job": jid, "hosts": len(hosts), "ports": len(ports)}))


def serve_gui(args):
    try:
        httpd = http.server.ThreadingHTTPServer((args.bind, args.serve_port),
                                                GUIHandler)
    except OSError as e:
        print(f"[!] Could not bind {args.bind}:{args.serve_port}: {e}",
              file=sys.stderr)
        return 2
    httpd.cli_args = args
    url = f"http://{args.bind}:{args.serve_port}/"
    print("=" * 68, file=sys.stderr)
    print(" phpscan GUI - authorized internal inventory use only", file=sys.stderr)
    print(f" Open {url} in your browser.", file=sys.stderr)
    if args.bind not in ("127.0.0.1", "localhost", "::1"):
        print(" [!] Bound to a non-loopback address: the GUI is reachable by",
              file=sys.stderr)
        print("     other hosts and has NO authentication. Prefer 127.0.0.1.",
              file=sys.stderr)
    print(" Press Ctrl+C to stop.", file=sys.stderr)
    print("=" * 68, file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] GUI stopped.", file=sys.stderr)
    finally:
        httpd.server_close()
    return 0


def normalize_paths(paths_str):
    return [p if p.startswith("/") else "/" + p
            for p in paths_str.split(",") if p.strip()]


def parse_ports(ports_str):
    if not ports_str:
        return list(DEFAULT_PORTS)
    return [int(x) for x in ports_str.split(",") if x.strip()]


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.serve:
        return serve_gui(args)

    specs = list(args.targets)
    if args.targets_file:
        specs.extend(load_targets_file(args.targets_file))
    if not specs:
        print("[!] No targets given. Try: phpscan 10.0.0.0/24  (or -t "
              "targets.txt), or --serve for the GUI. Use -h for help.",
              file=sys.stderr)
        return 2

    hosts = parse_targets(specs)
    if not hosts:
        print("[!] No valid targets after parsing.", file=sys.stderr)
        return 2

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print("[!] Invalid --ports value.", file=sys.stderr)
        return 2
    args.paths = normalize_paths(args.paths)

    if not confirm_authorization(hosts, args.yes):
        print("[*] Aborted.", file=sys.stderr)
        return 1

    results, meta, summary = run_pipeline(hosts, ports, args)

    formats = {f.strip().lower() for f in args.formats.split(",") if f.strip()}
    written = []
    if "json" in formats:
        write_json(results, meta, args.output + ".json")
        written.append(args.output + ".json")
    if "csv" in formats:
        write_csv(results, args.output + ".csv")
        written.append(args.output + ".csv")
    if "html" in formats:
        write_html(results, meta, summary, args.output + ".html")
        written.append(args.output + ".html")

    # Console summary
    print("\n" + "-" * 60, file=sys.stderr)
    print(f"  Web servers found : {summary['web_servers']}", file=sys.stderr)
    print(f"  Running PHP       : {summary['php_servers']}", file=sys.stderr)
    print(f"    End of life     : {summary['php_eol']}", file=sys.stderr)
    print(f"    Security-only   : {summary['php_security_only']}", file=sys.stderr)
    print(f"    Supported       : {summary['php_active']}", file=sys.stderr)
    print(f"    Version unknown : {summary['php_unknown_version']}", file=sys.stderr)
    if summary.get("kev"):
        ks = summary["kev"]
        km = meta.get("kev_meta") or {}
        if km.get("error"):
            print(f"  CISA KEV          : {km['error']}", file=sys.stderr)
        else:
            print(f"  CISA KEV ({km.get('catalogVersion') or 'feed'})",
                  file=sys.stderr)
            print(f"    CVEs matched    : {ks['unique_cves']}", file=sys.stderr)
            print(f"    Likely affected : {ks['likely_affected']}",
                  file=sys.stderr)
            print(f"    Ransomware-linked: {ks['ransomware_cves']}",
                  file=sys.stderr)
    print("-" * 60, file=sys.stderr)
    for w in written:
        print(f"  [+] Wrote {w}", file=sys.stderr)

    # Non-zero exit if anything EOL was found (useful in CI / cron).
    return 3 if summary["php_eol"] else 0


if __name__ == "__main__":
    sys.exit(main())
