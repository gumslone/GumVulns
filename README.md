# GumVulns

A single-file PHP CLI that searches **many vulnerability APIs in parallel** and
returns a normalized record for each hit: **CVE id, description, score, severity,
vector, source**.

## Requirements

PHP 8.1+ with `curl`, `json`, and `mbstring` extensions.

## Usage

Three query modes, auto-detected from the input:

```bash
# CVE id — queried against every source
php gumvulns.php CVE-2021-44228

# keyword — NVD + Vulners
php gumvulns.php "apache log4j"

# GitHub download / source link — commit -> OSV.dev, owner/repo/tag -> CPE sources
php gumvulns.php https://github.com/jquery/jquery/archive/refs/tags/3.3.1.zip
php gumvulns.php https://github.com/owner/repo/commit/<sha>

# CPE / CPE stub — parses the platform, resolves its title, returns ALL matching CVEs
php gumvulns.php "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
php gumvulns.php --cpe apache:log4j
php gumvulns.php --cpe a:openbsd:openssh:9.1 --limit=20

# common options
php gumvulns.php CVE-2021-44228 --json
php gumvulns.php CVE-2021-44228 --source=nvd,redhat
php gumvulns.php --list-sources
php gumvulns.php --help
```

### CPE mode

Accepts a full **CPE 2.3** string (`cpe:2.3:a:vendor:product:version:...`), a
legacy **CPE 2.2 URI** (`cpe:/a:vendor:product:version`), or a bare **stub**
(`product`, `vendor:product`, `vendor:product:version`, `a:vendor:product`).

It then:
1. Parses the CPE into all 11 fields and prints the breakdown.
2. Resolves the platform title from the **NVD CPE dictionary**.
3. Returns **every matching CVE** from the CPE-capable sources (NVD
   `virtualMatchString`, Shodan CVEDB, Vulners), **deduplicated by CVE id**.
   Each row lists every source that reported it.

Results are ordered: **confirmed-vulnerable first** (when a version is given),
then by **CVSS score**, and at the same score a CVE with a **known public
exploit** (see below) ranks above an unexploited one.

> An unspecified CPE *part* defaults to `a` (application) when querying, since
> NVD and Shodan reject a wildcard part. Pass `o:` or `h:` for OS/hardware.
> Results are capped at 50 by default in CPE mode — raise it with `--limit`.

### GitHub link mode

Paste a GitHub download or source URL and GumVulns extracts the relevant pieces:

| URL form | Extracted |
|---|---|
| `…/archive/<sha>.tar.gz`, `…/commit/<sha>`, codeload `…/zip/<sha>` | commit SHA |
| `…/archive/refs/tags/<tag>.zip`, `…/releases/download/<tag>/…` | owner, repo, version |
| `…/tree/<ref>`, `…/blob/<ref>/…`, `raw.githubusercontent.com/<o>/<r>/<ref>/…` | owner, repo, ref |

Then it searches:
- **By commit** in **OSV.dev** (`/v1/query` with `{"commit": …}`) — OSV matches the
  hash against each advisory's git ranges. Short SHAs are resolved to the full
  hash via the GitHub API first (`GITHUB_TOKEN` raises the rate limit).
- **By CPE** (`owner`→vendor, `repo`→product, `tag`→version) in the CPE-capable
  sources (NVD, Shodan, Vulners).

Results from both paths are merged and deduplicated by CVE id.

> Owner/repo names don't always match NVD's CPE vendor/product strings, so the
> commit path (OSV) is the precise one; the CPE path is best-effort.

## Affected version ranges

Results include the **affected version range(s)** for each CVE — the version the
range starts from and the version it ends at, with inclusive/exclusive bounds:

- **NVD** — `versionStartIncluding/Excluding` + `versionEndIncluding/Excluding`
  from the CPE configuration nodes.
- **OSV** — `introduced` / `fixed` / `last_affected` events (GIT commit ranges
  are skipped in favor of ecosystem/semver versions).
- **GitHub Advisory** — the `vulnerable_version_range` per affected package.
- **EUVD** — the ENISA `product_version` string (free-form).

In the table they appear as an `Affected` block, e.g.:

```
  Affected:    org.apache.logging.log4j:log4j-core: >= 2.13.0, < 2.16.0
               org.apache.logging.log4j:log4j-core: < 2.12.2
```

`>=`/`<=` mean the bound is **including** that version, `>`/`<` mean
**excluding**, and `= X` is a single affected version. In CPE mode the ranges
from every source are merged and deduplicated. The `--json` output carries them
structurally under `affected[]`:

```json
{
  "product": "org.apache.logging.log4j:log4j-core",
  "version_start_including": "2.13.0",
  "version_start_excluding": null,
  "version_end_including": null,
  "version_end_excluding": "2.16.0",
  "range": "org.apache.logging.log4j:log4j-core: >= 2.13.0, < 2.16.0"
}
```

## Version vulnerability flag

When you supply a **version** (a CPE like `apache:log4j:2.14.1` or a GitHub tag
link), GumVulns compares it against each CVE's affected ranges and flags it:

```
Status:  ⚠ VULNERABLE — queried version is within log4j: >= 2.13.0, < 2.16.0
Status:  ✓ not affected — queried version is outside the affected ranges
Status:  ? unknown — no comparable version range for this product
```

Comparison uses PHP's `version_compare` (handles `2.0-beta9`, `1.2.1.2-jre17`,
etc.), respecting inclusive/exclusive bounds. Only ranges whose **product**
matches the query are considered, so a log4j query won't be judged against, say,
a Siemens-firmware range that merely bundles log4j. Confirmed-vulnerable results
are sorted to the top. The `--json` output adds `vulnerable` (`true`/`false`/
`null`) and `matched_range` per result.

> Affected ranges in CPE/GitHub mode come mainly from NVD, so an `NVD_API_KEY`
> makes the flag far more reliable (keyless NVD requests are heavily throttled).

## Exploit / PoC availability

Each result is annotated with known **public exploits / PoCs** for its CVE
(`Exploit:` line in the table, `exploits[]` in JSON). Indicators adopted from
[search_vulns](https://github.com/ra1nb0rn/search_vulns):

| Indicator | Source file | Modes |
|---|---|---|
| **Nuclei** templates | `projectdiscovery/nuclei-templates` `cves.json` | all |
| **Exploit-DB** | `exploit-database/exploitdb` `files_exploits.csv` | all |
| **Metasploit** | `rapid7/metasploit-framework` `db/modules_metadata_base.json` | all |
| **PoC-in-GitHub** | `nomi-sec/PoC-in-GitHub` (per-CVE JSON) | CVE-id lookups |

The three bulk files are downloaded once (in parallel) and cached under
`~/.cache/gumvulns` for 6 hours; warm runs add no latency. PoC-in-GitHub is
fetched per CVE, so it only runs for single CVE lookups. Use `--no-poc` to skip
all exploit enrichment.

## End-of-life status

In CPE / GitHub mode with a version, GumVulns queries
[endoflife.date](https://endoflife.date) for the product and reports whether the
queried version's release branch is **supported** or **END-OF-LIFE**:

```
Lifecycle:  ⚠ END-OF-LIFE (branch 1, latest 1.2.17, EOL 2015-10-15)
Lifecycle:  supported (branch 2, latest 2.26.0)
```

It appears in the CPE info header and as `eol` in the JSON output.

## CVSS scoring

When a source provides only a CVSS **vector** but no base score (e.g. OSV), the
score and qualitative severity are computed from the vector with a built-in
calculator that supports **CVSS v2 and v3.0/v3.1** (prefixed, bare, or
parenthesized vectors). CVSS v4 vectors are surfaced but not yet scored.

## Sources

| Source | API key | CVE lookup | Keyword | CPE | Commit |
|---|---|---|---|---|---|
| NVD (NIST) | optional `NVD_API_KEY` | ✅ | ✅ | ✅ | — |
| CIRCL CVE Search | — | ✅ | — | — | — |
| Red Hat Security Data | — | ✅ | — | — | — |
| Shodan CVEDB | — | ✅ | — | ✅ | — |
| Ubuntu Security | — | ✅ | — | — | — |
| OSV.dev (Google) | — | ✅ | — | — | ✅ |
| GitHub Advisory DB | optional `GITHUB_TOKEN` | ✅ | — | — | — |
| CISA KEV (known-exploited) | — | ✅ | — | — | — |
| FIRST EPSS (exploit probability) | — | ✅ | — | — | — |
| EUVD (ENISA, EU database) | — | ✅ | ✅ | ✅ | — |
| CVE Details (HTML scrape) | cookie, see below | ✅ | — | — | — |
| Vulners | `VULNERS_API_KEY` | ✅ | ✅ | ✅ | — |
| VulnCheck | `VULNCHECK_API_KEY` | ✅ | — | — | — |
| Exploit/PoC indicators | — | enrichment (all modes) | | | |
| endoflife.date | — | EOL status (with version) | | | |

Beyond the lookup sources above, results are **enriched**: every CVE is annotated
with known public exploits/PoCs (Nuclei, Exploit-DB, Metasploit, PoC-in-GitHub —
adopted from [search_vulns](https://github.com/ra1nb0rn/search_vulns)), and when
a version is supplied its end-of-life status is pulled from endoflife.date. See
[Exploit / PoC availability](#exploit--poc-availability) and
[End-of-life status](#end-of-life-status) below.

Nine sources work with **zero configuration**. The keyed sources auto-enable
when their environment variable is set:

```bash
export NVD_API_KEY=...        # strongly recommended — NVD throttles hard without it
export GITHUB_TOKEN=...
export VULNERS_API_KEY=...
export VULNCHECK_API_KEY=...
```

### EUVD (ENISA) and CVE Details

- **EUVD** uses the ENISA EU Vulnerability Database JSON search API
  (`euvdservices.enisa.europa.eu/api/search`). CVE lookups search by text and
  keep the record whose `aliases` contain the CVE; CPE mode filters by
  `product`/`vendor`.
- **CVE Details** has no free API and sits behind Cloudflare, so GumVulns
  **scrapes the public CVE page** (`cvedetails.com/cve/<id>/`), pulling the
  description from the page meta tags and the CVSS vector from the HTML (the
  score is then computed locally). Anonymous server requests get a `403`
  Cloudflare challenge — to use it, copy a `cf_clearance`/session cookie from a
  browser and export it:

  ```bash
  export CVEDETAILS_COOKIE='cf_clearance=...; ...'
  ```

> **Note:** Without `NVD_API_KEY`, NVD requests are rate-limited and may time out.
> Set the key for fast, reliable NVD results.

## Output

Every source is normalized to the same fields, and severity is derived from the
CVSS base score when a source does not provide one. Requests run concurrently via
`curl_multi`, so total latency is roughly that of the slowest source. The
`Sources queried` footer reports the HTTP status, result count, and any error
per source.

## Adding a source

Implement `VulnSource` (`id`, `name`, `buildRequest`, `parse`) and add an instance
to `gumvulns_sources()`. The aggregator handles parallelism, timeouts, and
error reporting for you.
