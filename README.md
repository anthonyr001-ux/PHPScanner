# phpscan

A single-file tool that inventories **PHP web servers on an internal network**
and flags versions that are out of support. It sweeps the hosts/ports you give
it, fingerprints each responding web server, detects PHP and (where the server
discloses it) its version, checks that version against PHP.net's support
lifecycle, optionally **resolves hostnames** and **correlates findings with the
CISA Known Exploited Vulnerabilities (KEV) catalog**, and writes an **HTML, CSV
and JSON** report — from the command line or a **browser GUI**.

> ⚠️ **Authorized use only.** Scan only networks and hosts you own or have
> explicit written permission to assess. Port and HTTP scanning without
> authorization may break your organization's policy or the law in your
> jurisdiction.

## Requirements

- **Python 3.8+** — standard library only. No `pip install`, no dependencies.

## Quick start

### Browser GUI

```bash
python3 phpscan.py --serve
# then open http://127.0.0.1:8600/ in your browser
```

Fill in the targets, tick **Resolve hostnames** and **Check CISA KEV** as
needed, confirm you're authorized, and hit **Scan**. A progress bar tracks the
sweep; when it finishes you get the summary, tables, and **Export HTML / CSV /
JSON** buttons. The GUI binds to `127.0.0.1` (localhost only) by default.

### Command line

```bash
# Scan a /24, answer the authorization prompt, write php_inventory.{html,csv,json}
python3 phpscan.py 192.168.1.0/24

# With reverse DNS and CISA KEV correlation
python3 phpscan.py 10.0.0.0/24 --resolve --kev

# Several target forms at once
python3 phpscan.py 10.0.0.0/24 10.0.5.10-50 172.16.1.5 intranet.corp.local

# Targets from a file, custom output name, skip the prompt (for automation)
python3 phpscan.py -t targets.txt -o q4_audit --resolve --kev --yes
```

Open `php_inventory.html` in a browser for the report. The PHP table is sorted
**risk-first**: end-of-life servers at the top, then security-only, then
version-unknown, then supported.

## Target formats

| Form | Example | Meaning |
|------|---------|---------|
| CIDR | `10.0.0.0/24` | all usable hosts in the subnet |
| Dashed range (shorthand) | `10.0.0.1-50` | `10.0.0.1` through `10.0.0.50` |
| Dashed range (full) | `10.0.0.254-10.0.1.10` | spans octets |
| Single IP | `10.0.0.5` | one host |
| Hostname | `intranet.local` | resolved at scan time |

Targets can be space- or comma-separated on the command line, or one per line
in a `--targets-file` (`#` comments and blank lines are ignored).

## Options

```
positional:
  targets                 CIDR / range / IP / hostname (space- or comma-separated)

  -t, --targets-file F    read target specs from file F (one per line)
  -p, --ports LIST        comma-separated ports
                          (default: 80,443,8080,8443,8000,8008,8888,3000,5000,7001,9000)
      --paths LIST        URL paths to probe per server
                          (default: /,/index.php,/login.php)
  -w, --workers N         concurrent workers (default: 100)
      --timeout SEC       per-connection timeout (default: 3.0)
  -r, --resolve           reverse-resolve (PTR) responding hosts to hostnames
      --kev               correlate findings with the CISA KEV catalog
      --kev-url URL       KEV feed URL (default: CISA's feed)
      --kev-file PATH     use a local KEV JSON file instead of fetching (air-gapped)
      --kev-cache PATH    cache the fetched feed here; reused if a later fetch fails
      --serve             launch the browser GUI instead of scanning now
      --bind ADDR         GUI bind address (default: 127.0.0.1)
      --serve-port N      GUI port (default: 8600)
  -o, --output NAME       output basename -> NAME.html/.csv/.json (default: php_inventory)
      --formats LIST      which reports to write (default: html,csv,json)
      --today YYYY-MM-DD  override "today" for lifecycle checks (testing/forecasting)
      --no-progress       suppress the progress counter
      --yes               skip the authorization prompt (required for non-interactive runs)
      --version           print version
```

## Reverse DNS

With `-r`/`--resolve` (and the GUI checkbox), phpscan does a PTR lookup for each
responding host, in parallel with a short timeout, and shows the hostname under
the IP in every report and in the `hostname` CSV/JSON field. Hosts without a PTR
record are simply left blank.

## CISA KEV correlation

With `--kev` (and the GUI checkbox), phpscan downloads CISA's **Known Exploited
Vulnerabilities** catalog and matches it against the software it fingerprinted:
PHP on every detected PHP server, plus the web-server product parsed from the
`Server` header (Apache httpd, nginx, IIS, …). Matching is by **product/vendor**
and word-boundary-exact, so an Apache HTTP Server banner isn't correlated with,
say, Apache Struts CVEs.

Each match gets a best-effort **verdict**:

| Verdict | Meaning |
|---------|---------|
| **Likely affected** | A version was detected and the CVE text names a fixed version the host is below. |
| **Likely patched** | A version was detected and it's at or above the fixed version (or a newer branch). |
| **Review** | The CVE applies to the product, but no version could be compared (host hid its version, or the KEV entry states no version). |

> **Important:** KEV descriptions are free text and often omit version ranges,
> so treat "likely affected/patched" as a prioritization hint, not proof.
> Always confirm against each host's actual patch level. The report flags
> whether a CVE is **linked to ransomware campaigns** and links each CVE to its
> NVD page.

**Air-gapped networks:** the machine running phpscan needs reach to
`cisa.gov` for a live fetch. If it doesn't, download the feed elsewhere and pass
it in:

```bash
# on an internet-connected host
curl -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# on the scanning host
python3 phpscan.py 10.0.0.0/24 --kev --kev-file kev.json
```

Or start the GUI with `--kev-file kev.json` so GUI scans use the local copy.

## How PHP is detected

phpscan looks for signals a server commonly exposes, in order of reliability:

1. **`X-Powered-By: PHP/x.y.z`** response header — gives the exact version.
2. **`Server:`** header containing `PHP/x.y.z` (e.g. `Apache/2.4 (…) PHP/8.2.1`).
3. **`Set-Cookie: PHPSESSID=…`** — confirms PHP, no version.
4. **Body signatures** — `phpinfo()` output (`PHP Version 8.2.5`), PHP fatal/parse
   error text, or a `laravel_session` cookie.
5. **Port 9000 open with no HTTP reply** — flagged as a probable **PHP-FPM /
   FastCGI** listener.

Both HTTP and HTTPS are tried on each open port (TLS first on 443/8443), and
self-signed / internal-CA certificates are accepted for fingerprinting.
Redirects are **not** followed, so a server that 301s to a login page is still
reported with its real headers.

> **Version absence is not safety.** A server can be configured to hide its
> version (`expose_php = Off`) while still running an end-of-life PHP. Those
> show as "Version unknown" — worth checking by hand.

## Version lifecycle

Versions are classified against PHP.net's published schedule
(<https://www.php.net/supported-versions.php>), confirmed October 2026:

| Branch | Status today (2026-10) | Security support ends |
|--------|------------------------|-----------------------|
| 8.5 | Active | 2029-12-31 |
| 8.4 | Active | 2028-12-31 |
| 8.3 | Security-only | 2027-12-31 |
| 8.2 | Security-only | 2026-12-31 |
| 8.1 and older | **End of life** | — (past) |

- **Supported** — in active support (bug + security fixes).
- **Security-only** — critical security fixes only; plan your upgrade.
- **End of life** — no fixes; prioritize for upgrade.

The lifecycle table lives at the top of `phpscan.py` (`PHP_LIFECYCLE`). When
PHP.net publishes new dates, edit that dict — nothing else depends on it.

## Output files

- **`.html`** — human-readable report with summary cards, risk-sorted tables,
  hostnames, and a Known-Exploited-Vulnerabilities section (when `--kev`).
- **`.csv`** — one row per responding host:port, for spreadsheets / ticketing.
  Includes `hostname`, `kev_cves` (every match with its verdict) and
  `kev_affected` (just the likely-affected CVE IDs).
- **`.json`** — full structured results plus scan metadata (including the KEV
  catalog version used), for pipelines.

From the GUI, the same three reports download via the **Export** buttons.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | completed, no end-of-life PHP found |
| 1 | aborted at the authorization prompt |
| 2 | bad arguments / no valid targets |
| 3 | completed, **at least one end-of-life PHP server found** |

Exit 3 lets you wire phpscan into CI or a scheduled job that should fail when an
EOL server appears:

```bash
python3 phpscan.py -t targets.txt --yes -o nightly || \
  echo "Review nightly.html — EOL PHP detected" | mail -s "PHP audit" ops@corp
```

## Tuning

- **Faster sweeps:** raise `-w` (e.g. `-w 300`) and/or lower `--timeout`. Too
  aggressive and slow/overloaded hosts may be missed.
- **Fewer ports:** pass `-p 80,443` to scan only standard web ports.
- **Catch more app paths:** add to `--paths`, e.g.
  `--paths /,/index.php,/wp-login.php,/admin/`.

## The GUI, in more detail

- `--serve` starts a small local web server (stdlib only) that serves the form
  and runs the scan engine behind it. **It has no authentication**, so keep it
  on `127.0.0.1` (the default). Binding elsewhere (`--bind 0.0.0.0`) exposes it
  to anyone who can reach the port — phpscan warns when you do.
- Scans run as background jobs with a live progress bar; the browser polls for
  status and renders results when done.
- The GUI caps a single scan at 200,000 probes (hosts × ports). For sweeps
  bigger than that, use the command line.
- To make GUI scans use a local KEV file (air-gapped), start it with
  `python3 phpscan.py --serve --kev-file kev.json`.

## Notes & limits

- Detection is best-effort fingerprinting, not an exploit or auth bypass; it
  only reads what a server voluntarily returns on a normal GET.
- Hostnames are resolved via the OS resolver; split-horizon DNS applies.
- IPv6 targets work anywhere an address/CIDR is accepted.
- Reverse proxies can mask or rewrite backend headers; a load-balanced service
  may answer differently across requests.
- KEV correlation is only as precise as the catalog's free-text descriptions;
  it's built to prioritize review, not to replace authenticated patch auditing.
