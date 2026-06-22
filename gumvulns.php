<?php

/**
 * GumVulns — multi-source vulnerability search.
 *
 * Queries several public vulnerability APIs in parallel and prints a normalized
 * view of each result: CVE id, description, score, severity, vector and source.
 *
 * Three query modes, auto-detected from the input:
 *   - CVE id      php gumvulns.php CVE-2021-44228
 *   - keyword     php gumvulns.php "apache log4j"
 *   - CPE / stub  php gumvulns.php "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
 *                 php gumvulns.php --cpe apache:log4j
 *
 * In CPE mode the platform is parsed into all its fields, its title is resolved
 * from the NVD CPE dictionary, and every matching CVE is returned (deduplicated
 * across sources, sorted by score).
 *
 * Options:
 *   --json              JSON output instead of a table.
 *   --cpe               Treat the input as a CPE / CPE stub (vendor:product[:version]).
 *   --source=a,b,c      Only query the named sources (see --list-sources).
 *   --limit=N           Cap the number of results (default 50 in CPE mode).
 *   --list-sources      List sources and whether they are enabled.
 *   -h, --help          Show help.
 *
 * Optional API keys (read from the environment; sources auto-enable when present):
 *   NVD_API_KEY        https://nvd.nist.gov/developers/request-an-api-key
 *   GITHUB_TOKEN       https://github.com/settings/tokens
 *   VULNERS_API_KEY    https://vulners.com/
 *   VULNCHECK_API_KEY  https://vulncheck.com/
 *
 * Requires: php-curl, php-json, php-mbstring.
 */

declare(strict_types=1);

/* -------------------------------------------------------------------------- */
/* Query model                                                                */
/* -------------------------------------------------------------------------- */

enum QueryType: string
{
    case CveId   = 'cve';
    case Keyword = 'keyword';
    case Cpe     = 'cpe';
}

/** A parsed user query: its type plus, for CPE mode, the parsed platform. */
final class Query
{
    public QueryType $type;
    public string $raw;
    public ?Cpe $cpe;
    public ?string $commit;        // git commit SHA to query (OSV)
    public ?GitHubRef $github;     // parsed GitHub download link, if any
    /** @var array{ecosystem:?string,name:?string,purl:?string,version:?string}|null */
    public ?array $osv = null;     // explicit OSV package query (--osv-package)
    public bool $cpeResolved = false; // CPE vendor/product resolved from a purl
    /** @var array{raw:string,type:string,namespace:?string,name:string,version:?string}|null */
    public ?array $purl = null;    // full purl (raw) + parsed parts, when the query was a purl

    public function __construct(
        QueryType $type,
        string $raw,
        ?Cpe $cpe = null,
        ?string $commit = null,
        ?GitHubRef $github = null
    ) {
        $this->type   = $type;
        $this->raw    = $raw;
        $this->cpe    = $cpe;
        $this->commit = $commit;
        $this->github = $github;
    }

    /** Best-effort CVE id for sources that need a fallback identifier. */
    public function cveIdGuess(): string
    {
        return $this->type === QueryType::CveId ? strtoupper($this->raw) : '';
    }
}

/**
 * Common Platform Enumeration parser/normalizer.
 *
 * Accepts CPE 2.3 formatted strings, CPE 2.2 URIs, or bare stubs
 * ("vendor:product", "vendor:product:version", "product", "a:vendor:product")
 * and normalizes them to the 11-field CPE 2.3 model.
 */
final class Cpe
{
    public string $part      = '*';
    public string $vendor    = '*';
    public string $product   = '*';
    public string $version   = '*';
    public string $update    = '*';
    public string $edition   = '*';
    public string $language  = '*';
    public string $swEdition = '*';
    public string $targetSw  = '*';
    public string $targetHw  = '*';
    public string $other     = '*';

    /** Build a CPE from discrete vendor/product/version parts. */
    public static function fromParts(string $vendor, string $product, string $version = '*'): Cpe
    {
        $cpe = new self();
        $cpe->vendor  = $vendor !== '' ? strtolower($vendor) : '*';
        $cpe->product = $product !== '' ? strtolower($product) : '*';
        $cpe->version = $version !== '' ? $version : '*';
        return $cpe;
    }

    /** Parse any supported CPE form. Returns null if there is no product to match. */
    public static function parse(string $input): ?Cpe
    {
        $input = trim($input);
        if ($input === '') {
            return null;
        }
        $cpe = new self();

        if (stripos($input, 'cpe:2.3:') === 0) {
            $cpe->fromFormatted(substr($input, 8));
        } elseif (stripos($input, 'cpe:/') === 0) {
            $cpe->fromUri(substr($input, 5));
        } else {
            $cpe->fromStub($input);
        }

        // Need at least a product (or vendor) to be searchable.
        if ($cpe->product === '*' && $cpe->vendor === '*') {
            return null;
        }
        return $cpe;
    }

    /** CPE 2.3 formatted string body (after "cpe:2.3:"). */
    private function fromFormatted(string $body): void
    {
        // Split on ':' that is not escaped as '\:'.
        $parts = preg_split('/(?<!\\\\):/', $body) ?: [];
        $parts = array_map([self::class, 'unescape'], $parts);
        $fields = ['part','vendor','product','version','update','edition',
                   'language','swEdition','targetSw','targetHw','other'];
        foreach ($fields as $i => $name) {
            if (isset($parts[$i]) && $parts[$i] !== '') {
                $this->$name = $parts[$i];
            }
        }
    }

    /** CPE 2.2 URI body (after "cpe:/"): part:vendor:product:version:update:edition:language */
    private function fromUri(string $body): void
    {
        $parts  = array_map([self::class, 'unescape'], explode(':', $body));
        $fields = ['part','vendor','product','version','update','edition','language'];
        foreach ($fields as $i => $name) {
            if (isset($parts[$i]) && $parts[$i] !== '' && $parts[$i] !== '*') {
                $this->$name = $parts[$i];
            }
        }
    }

    /** Bare stub: "product", "vendor:product", "vendor:product:version", "a:vendor:product". */
    private function fromStub(string $input): void
    {
        $tok = array_values(array_filter(explode(':', $input), static fn ($t) => $t !== ''));
        // Leading single-letter a/o/h is a CPE "part".
        if (count($tok) >= 3 && in_array(strtolower($tok[0]), ['a', 'o', 'h'], true)) {
            $this->part = strtolower(array_shift($tok));
        }
        switch (count($tok)) {
            case 1:
                $this->product = $tok[0];
                break;
            case 2:
                $this->vendor  = $tok[0];
                $this->product = $tok[1];
                break;
            default:
                $this->vendor  = $tok[0];
                $this->product = $tok[1];
                $this->version = $tok[2];
        }
    }

    private static function unescape(string $s): string
    {
        return str_replace(['\\:', '\\\\'], [':', '\\'], $s);
    }

    public function hasVersion(): bool
    {
        return $this->version !== '*' && $this->version !== '' && $this->version !== '-';
    }

    /** Canonical CPE 2.3 formatted string (faithful to the input). */
    public function toCpe23(): string
    {
        return 'cpe:2.3:' . implode(':', [
            $this->part, $this->vendor, $this->product, $this->version, $this->update,
            $this->edition, $this->language, $this->swEdition, $this->targetSw,
            $this->targetHw, $this->other,
        ]);
    }

    /**
     * CPE 2.3 string for querying APIs. NVD and Shodan reject a wildcard part,
     * so an unspecified part defaults to "a" (application, the common case).
     */
    public function toQueryCpe23(): string
    {
        $part = in_array($this->part, ['a', 'o', 'h'], true) ? $this->part : 'a';
        return 'cpe:2.3:' . implode(':', [
            $part, $this->vendor, $this->product, $this->version, $this->update,
            $this->edition, $this->language, $this->swEdition, $this->targetSw,
            $this->targetHw, $this->other,
        ]);
    }

    /** Human-readable component breakdown for the info header. */
    public function components(): array
    {
        $partLabel = [
            'a' => 'a (application)',
            'o' => 'o (operating system)',
            'h' => 'h (hardware)',
        ][$this->part] ?? $this->part;

        return [
            'Part'        => $partLabel,
            'Vendor'      => $this->vendor,
            'Product'     => $this->product,
            'Version'     => $this->version,
            'Update'      => $this->update,
            'Edition'     => $this->edition,
            'Language'    => $this->language,
            'SW edition'  => $this->swEdition,
            'Target SW'   => $this->targetSw,
            'Target HW'   => $this->targetHw,
            'Other'       => $this->other,
            'Normalized'  => $this->toCpe23(),
        ];
    }
}

/**
 * Parses a GitHub download/source link into owner, repo and a ref, classifying
 * the ref as a commit, tag or branch.
 *
 * Recognized hosts: github.com, codeload.github.com, raw.githubusercontent.com.
 * Recognized paths: /archive/..., /releases/download|tag/..., /commit|tree|blob/...,
 * codeload /zip|/tar.gz/..., raw /<owner>/<repo>/<ref>/... and bare /<owner>/<repo>.
 */
final class GitHubRef
{
    public string $owner;
    public string $repo;
    public string $refType = 'none'; // commit | tag | branch | none
    public string $ref     = '';     // raw ref text
    public ?string $commit = null;   // commit SHA when refType === commit
    public ?string $version = null;  // version derived from a tag

    public static function parse(string $url): ?GitHubRef
    {
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));
        $allowed = ['github.com', 'www.github.com', 'codeload.github.com', 'raw.githubusercontent.com'];
        if (!in_array($host, $allowed, true)) {
            return null;
        }
        $path = (string) parse_url($url, PHP_URL_PATH);
        $seg  = array_values(array_filter(explode('/', $path), static fn ($s) => $s !== ''));
        if (count($seg) < 2) {
            return null;
        }

        $g = new self();
        $g->owner = $seg[0];
        $g->repo  = preg_replace('/\.git$/', '', $seg[1]) ?? $seg[1];

        $hint = '';   // tags | heads | commit
        $ref  = '';

        if ($host === 'raw.githubusercontent.com') {
            $ref = $seg[2] ?? '';
        } elseif ($host === 'codeload.github.com') {
            // /owner/repo/{zip|tar.gz|legacy.zip|legacy.tar.gz}/<ref...>
            $rest = array_slice($seg, 3);
            [$hint, $ref] = self::splitRef($rest);
        } else { // github.com
            $kind = $seg[2] ?? '';
            switch ($kind) {
                case 'archive':
                    [$hint, $ref] = self::splitRef(array_slice($seg, 3));
                    $ref = preg_replace('/\.(zip|tar\.gz|tgz)$/i', '', $ref) ?? $ref;
                    break;
                case 'releases':
                    // /releases/download/<tag>/<asset> or /releases/tag/<tag>
                    $ref  = $seg[4] ?? ($seg[3] ?? '');
                    $hint = 'tags';
                    break;
                case 'commit':
                    $ref  = $seg[3] ?? '';
                    $hint = 'commit';
                    break;
                case 'tree':
                case 'blob':
                    $ref = $seg[3] ?? '';
                    break;
                default:
                    $ref = ''; // bare /owner/repo
            }
        }

        $g->ref = $ref;
        $g->classify($hint, $ref);
        return $g;
    }

    /** Strip a leading refs/tags/ or refs/heads/ marker and report the hint. */
    private static function splitRef(array $rest): array
    {
        if (($rest[0] ?? '') === 'refs' && in_array($rest[1] ?? '', ['tags', 'heads'], true)) {
            return [$rest[1], implode('/', array_slice($rest, 2))];
        }
        return ['', implode('/', $rest)];
    }

    private function classify(string $hint, string $ref): void
    {
        if ($ref === '') {
            $this->refType = 'none';
            return;
        }
        $isSha = (bool) preg_match('/^[0-9a-f]{7,40}$/i', $ref);

        if ($hint === 'commit' || ($hint === '' && $isSha && strlen($ref) >= 7)) {
            $this->refType = 'commit';
            $this->commit  = strtolower($ref);
        } elseif ($hint === 'heads') {
            $this->refType = 'branch';
        } elseif ($hint === 'tags' || self::looksLikeVersion($ref)) {
            $this->refType = 'tag';
            $this->version = self::toVersion($ref);
        } else {
            $this->refType = 'branch';
        }
    }

    private static function looksLikeVersion(string $ref): bool
    {
        return (bool) preg_match('/^v?\d+(\.\d+)+/i', $ref) || (bool) preg_match('/\d+\.\d+/', $ref);
    }

    /** Reduce a tag like "v2.14.1" or "release-2.14.1" to "2.14.1". */
    private static function toVersion(string $tag): string
    {
        if (preg_match('/(\d+(?:\.\d+){1,3}(?:[.-][0-9A-Za-z]+)*)/', $tag, $m)) {
            return $m[1];
        }
        return ltrim($tag, 'vV');
    }

    public function toCpe(): Cpe
    {
        return Cpe::fromParts($this->owner, $this->repo, $this->version ?? '*');
    }

    /** Display fields for the info header. */
    public function describe(): array
    {
        return [
            'Owner'    => $this->owner,
            'Repo'     => $this->repo,
            'Ref'      => $this->ref !== '' ? $this->ref : '—',
            'Ref type' => $this->refType,
            'Commit'   => $this->commit ?? '—',
            'Version'  => $this->version ?? '—',
        ];
    }
}

/* -------------------------------------------------------------------------- */
/* CVSS                                                                        */
/* -------------------------------------------------------------------------- */

/** Computes a CVSS base score from a v2 or v3.0/v3.1 vector string. */
final class Cvss
{
    /** @return float|null the base score, or null if the vector can't be scored. */
    public static function baseScore(string $vector): ?float
    {
        $vector = trim($vector, " \t()");
        $m = self::metrics($vector);
        if (!$m) {
            return null;
        }
        // v2 vectors carry an "Au" (Authentication) metric; v3 carries "PR"/"UI".
        if (preg_match('/^CVSS:3\.[01]/', $vector) || isset($m['PR'], $m['UI'])) {
            return self::scoreV3($m);
        }
        if (isset($m['Au']) || preg_match('/^CVSS:2/', $vector)) {
            return self::scoreV2($m);
        }
        return null; // v4 and unknown formats are not scored here.
    }

    /** Detect the CVSS major version ("2","3","4") from a vector, or null. */
    public static function version(string $vector): ?string
    {
        $v = trim($vector, " \t()");
        if (preg_match('/^CVSS:4\.\d/', $v)) return '4';
        if (preg_match('/^CVSS:3\.[01]/', $v)) return '3';
        if (preg_match('/^CVSS:2/', $v)) return '2';
        $m = self::metrics($v);
        if (isset($m['PR'], $m['UI'])) return '3';
        if (isset($m['Au'])) return '2';
        return null;
    }

    /** @return array<string,string> */
    private static function metrics(string $vector): array
    {
        $m = [];
        foreach (explode('/', $vector) as $pair) {
            if (str_contains($pair, ':')) {
                [$k, $v] = explode(':', $pair, 2);
                $m[$k] = $v;
            }
        }
        return $m;
    }

    /** @param array<string,string> $m */
    private static function scoreV3(array $m): ?float
    {
        foreach (['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as $req) {
            if (!isset($m[$req])) {
                return null;
            }
        }
        $changed = $m['S'] === 'C';

        $av = ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2][$m['AV']] ?? null;
        $ac = ['L' => 0.77, 'H' => 0.44][$m['AC']] ?? null;
        $pr = $changed
            ? (['N' => 0.85, 'L' => 0.68, 'H' => 0.5][$m['PR']] ?? null)
            : (['N' => 0.85, 'L' => 0.62, 'H' => 0.27][$m['PR']] ?? null);
        $ui = ['N' => 0.85, 'R' => 0.62][$m['UI']] ?? null;
        $cia = ['H' => 0.56, 'L' => 0.22, 'N' => 0.0];
        $c = $cia[$m['C']] ?? null;
        $i = $cia[$m['I']] ?? null;
        $a = $cia[$m['A']] ?? null;
        if (in_array(null, [$av, $ac, $pr, $ui, $c, $i, $a], true)) {
            return null;
        }

        $iscBase = 1 - ((1 - $c) * (1 - $i) * (1 - $a));
        $impact  = $changed
            ? 7.52 * ($iscBase - 0.029) - 3.25 * pow($iscBase - 0.02, 15)
            : 6.42 * $iscBase;
        $expl = 8.22 * $av * $ac * $pr * $ui;

        if ($impact <= 0) {
            return 0.0;
        }
        $raw = $changed ? 1.08 * ($impact + $expl) : $impact + $expl;
        return self::roundUp(min($raw, 10.0));
    }

    /** @param array<string,string> $m */
    private static function scoreV2(array $m): ?float
    {
        foreach (['AV', 'AC', 'Au', 'C', 'I', 'A'] as $req) {
            if (!isset($m[$req])) {
                return null;
            }
        }
        $av = ['L' => 0.395, 'A' => 0.646, 'N' => 1.0][$m['AV']] ?? null;
        $ac = ['H' => 0.35, 'M' => 0.61, 'L' => 0.71][$m['AC']] ?? null;
        $au = ['M' => 0.45, 'S' => 0.56, 'N' => 0.704][$m['Au']] ?? null;
        $cia = ['N' => 0.0, 'P' => 0.275, 'C' => 0.660];
        $c = $cia[$m['C']] ?? null;
        $i = $cia[$m['I']] ?? null;
        $a = $cia[$m['A']] ?? null;
        if (in_array(null, [$av, $ac, $au, $c, $i, $a], true)) {
            return null;
        }

        $impact = 10.41 * (1 - (1 - $c) * (1 - $i) * (1 - $a));
        $expl   = 20 * $av * $ac * $au;
        $f      = $impact == 0.0 ? 0.0 : 1.176;
        $score  = ((0.6 * $impact) + (0.4 * $expl) - 1.5) * $f;
        return round($score, 1); // v2 rounds to one decimal place
    }

    /** CVSS 3.1 "Roundup": round up to the nearest 0.1. */
    private static function roundUp(float $input): float
    {
        $int = (int) round($input * 100000);
        if ($int % 10000 === 0) {
            return $int / 100000;
        }
        return (floor($int / 10000) + 1) / 10;
    }
}

/* -------------------------------------------------------------------------- */
/* Value object                                                               */
/* -------------------------------------------------------------------------- */

/**
 * An affected version range for a product/package, normalized across sources.
 * Mirrors NVD's start/end "including/excluding" model.
 */
final class VersionRange
{
    public ?string $product;
    public ?string $start = null;
    public bool $startIncluding = true;   // true => ">=", false => ">"
    public ?string $end = null;
    public bool $endIncluding = false;    // true => "<=", false => "<"
    public ?string $raw = null;           // free-form text when bounds can't be parsed

    private function __construct(?string $product)
    {
        $this->product = ($product !== null && trim($product) !== '') ? trim($product) : null;
    }

    public static function bounded(?string $product, ?string $start, bool $startIncl, ?string $end, bool $endIncl): self
    {
        $r = new self($product);
        $r->start = ($start !== null && $start !== '' && $start !== '0') ? $start : null;
        $r->startIncluding = $startIncl;
        $r->end = ($end !== null && $end !== '') ? $end : null;
        $r->endIncluding = $endIncl;
        return $r;
    }

    public static function exact(?string $product, string $version): self
    {
        $r = new self($product);
        $r->start = $version;
        $r->startIncluding = true;
        $r->end = $version;
        $r->endIncluding = true;
        return $r;
    }

    public static function rawText(?string $product, string $text): self
    {
        $r = new self($product);
        $r->raw = trim($text);
        return $r;
    }

    public function isEmpty(): bool
    {
        return $this->start === null && $this->end === null && ($this->raw === null || $this->raw === '');
    }

    /** e.g. "log4j-core: >= 2.13.0, < 2.15.0" or "= 2.14.1" */
    public function format(): string
    {
        if ($this->raw !== null && $this->raw !== '') {
            $body = $this->raw;
        } elseif ($this->start !== null && $this->start === $this->end && $this->startIncluding && $this->endIncluding) {
            $body = '= ' . $this->start;
        } else {
            $parts = [];
            if ($this->start !== null) {
                $parts[] = ($this->startIncluding ? '>= ' : '> ') . $this->start;
            }
            if ($this->end !== null) {
                $parts[] = ($this->endIncluding ? '<= ' : '< ') . $this->end;
            }
            $body = $parts ? implode(', ', $parts) : 'all versions';
        }
        return $this->product !== null ? $this->product . ': ' . $body : $body;
    }

    public function key(): string
    {
        return strtolower($this->format());
    }

    /**
     * Whether $version falls inside this range.
     * Returns null when the range can't be evaluated (free-form text).
     */
    public function contains(string $version): ?bool
    {
        if ($this->raw !== null) {
            return null;
        }
        if ($this->start === null && $this->end === null) {
            return null;
        }
        if ($this->start !== null) {
            $c = version_compare($version, $this->start);
            if ($this->startIncluding ? $c < 0 : $c <= 0) {
                return false;
            }
        }
        if ($this->end !== null) {
            $c = version_compare($version, $this->end);
            if ($this->endIncluding ? $c > 0 : $c >= 0) {
                return false;
            }
        }
        return true;
    }

    /** Loose product match (handles "log4j" vs "org.apache...:log4j-core"). */
    public function productMatches(?string $query): bool
    {
        if ($this->product === null || $query === null || $query === '' || $query === '*') {
            return true;
        }
        $a = strtolower($this->product);
        $b = strtolower($query);
        $seg  = preg_split('/[:\/]/', $a) ?: [$a];
        $last = (string) end($seg);
        return str_contains($a, $b) || str_contains($b, $a)
            || ($last !== '' && (str_contains($last, $b) || str_contains($b, $last)));
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'product'                 => $this->product,
            'version_start_including' => ($this->start !== null && $this->startIncluding) ? $this->start : null,
            'version_start_excluding' => ($this->start !== null && !$this->startIncluding) ? $this->start : null,
            'version_end_including'   => ($this->end !== null && $this->endIncluding) ? $this->end : null,
            'version_end_excluding'   => ($this->end !== null && !$this->endIncluding) ? $this->end : null,
            'range'                   => $this->format(),
        ];
    }
}

/** Normalized vulnerability record shared by every source. */
final class Vulnerability
{
    public string $cveId;
    public string $description;
    public ?float $score;
    public string $severity;
    public string $vector;
    public string $source;
    /** @var VersionRange[] */
    public array $versions;

    // Set post-hoc when a target version is checked / PoC enrichment runs.
    public bool $versionChecked = false;
    public ?bool $vulnerable = null;     // true=in range, false=outside, null=unknown
    public ?string $matchedRange = null; // the range that matched, when vulnerable
    /** @var array<int,array{source:string,url:string}> Known public exploits/PoCs. */
    public array $exploits = [];
    public ?float $epss = null;          // EPSS probability 0..1 (not a CVSS score)
    public ?float $epssPercentile = null;
    public bool $kev = false;            // listed in CISA KEV / flagged known-exploited
    /** @var array<string,array{score:?float,vector:string,status:string}> per-version CVSS, keyed "2"/"3"/"4". */
    public array $cvss = [];

    /** @param VersionRange[] $versions */
    public function __construct(
        string $cveId,
        string $description,
        ?float $score,
        string $severity,
        string $vector,
        string $source,
        array $versions = []
    ) {
        $this->cveId       = trim($cveId) !== '' ? trim($cveId) : 'N/A';
        $this->description = self::clean($description);
        $this->vector      = trim($vector);
        // Some sources (e.g. OSV) supply only a CVSS vector; derive the score.
        if ($score === null && $this->vector !== '') {
            $score = Cvss::baseScore($this->vector);
        }
        $this->score       = $score;
        $this->severity    = $severity !== '' ? strtoupper($severity) : self::severityFromScore($score);
        $this->source      = $source;
        $this->versions    = self::dedupeRanges($versions);
        // Record the primary metric under its CVSS version (best-effort).
        if ($this->vector !== '') {
            $this->addCvss(Cvss::version($this->vector) ?? '', $this->score, $this->vector, $this->severity);
        }
    }

    /**
     * Record a CVSS metric for a specific version ("2"/"3"/"4"). Missing scores
     * are computed from the vector (v2/v3); a richer existing entry (with a
     * vector) is not overwritten by a barer one.
     */
    public function addCvss(string $version, ?float $score, string $vector, string $status = ''): void
    {
        if (!in_array($version, ['2', '3', '4'], true)) {
            return;
        }
        $vector = trim($vector);
        if ($score === null && $vector !== '') {
            $score = Cvss::baseScore($vector);
        }
        if ($status === '') {
            $status = self::severityFromScore($score);
        }
        $existing = $this->cvss[$version] ?? null;
        if ($existing !== null && $existing['vector'] !== '' && $vector === '') {
            return;
        }
        $this->cvss[$version] = ['score' => $score, 'vector' => $vector, 'status' => strtoupper($status)];
    }

    /**
     * Drop empty ranges and de-duplicate by formatted value (capped for sanity).
     *
     * @param VersionRange[] $ranges
     * @return VersionRange[]
     */
    public static function dedupeRanges(array $ranges): array
    {
        $seen = [];
        $out  = [];
        foreach ($ranges as $r) {
            if (!$r instanceof VersionRange || $r->isEmpty()) {
                continue;
            }
            $k = $r->key();
            if (!isset($seen[$k])) {
                $seen[$k] = true;
                $out[] = $r;
            }
            if (count($out) >= 16) {
                break;
            }
        }
        return $out;
    }

    private static function clean(string $text): string
    {
        $text = preg_replace('/\s+/u', ' ', $text) ?? $text;
        return trim($text);
    }

    /** Map a CVSS v3 base score onto the standard qualitative rating. */
    public static function severityFromScore(?float $score): string
    {
        if ($score === null) return 'UNKNOWN';
        if ($score <= 0.0)   return 'NONE';
        if ($score < 4.0)    return 'LOW';
        if ($score < 7.0)    return 'MEDIUM';
        if ($score < 9.0)    return 'HIGH';
        return 'CRITICAL';
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        $out = [
            'cve_id'      => $this->cveId,
            'description' => $this->description,
            'score'       => $this->score,
            'severity'    => $this->severity,
            'vector'      => $this->vector,
            'source'      => $this->source,
            'affected'    => array_map(static fn (VersionRange $r) => $r->toArray(), $this->versions),
            'exploits'    => $this->exploits,
            'epss'        => $this->epss,
            'epss_percentile' => $this->epssPercentile,
            'kev'         => $this->kev,
        ];
        foreach (['2', '3', '4'] as $ver) {
            if (isset($this->cvss[$ver])) {
                $out['cvss' . $ver] = $this->cvss[$ver];
            }
        }
        if ($this->versionChecked) {
            $out['vulnerable']    = $this->vulnerable;
            $out['matched_range'] = $this->matchedRange;
        }
        return $out;
    }
}

/* -------------------------------------------------------------------------- */
/* HTTP plumbing                                                              */
/* -------------------------------------------------------------------------- */

/** A single HTTP request a source wants the aggregator to perform. */
final class HttpRequest
{
    public string $url;
    public string $method;
    /** @var array<int,string> */
    public array $headers;
    public ?string $body;
    public int $timeout = 0;  // per-request override; 0 = use the batch default
    public int $cacheTtl = 0; // cache the response this many seconds; 0 = no cache

    /** @param array<int,string> $headers */
    public function __construct(string $url, string $method = 'GET', array $headers = [], ?string $body = null)
    {
        $this->url     = $url;
        $this->method  = $method;
        $this->headers = $headers;
        $this->body    = $body;
    }
}

/** The result of performing an HttpRequest. */
final class HttpResponse
{
    public int $status;
    public string $body;
    public string $error;

    public function __construct(int $status, string $body, string $error = '')
    {
        $this->status = $status;
        $this->body   = $body;
        $this->error  = $error;
    }

    public function ok(): bool
    {
        return $this->error === '' && $this->status >= 200 && $this->status < 300;
    }
}

/** Performs many HTTP requests concurrently with curl_multi. */
final class Http
{
    public static bool $cacheEnabled = true;

    /** On-disk cache path for a (method,url,body) tuple. */
    public static function cachePath(HttpRequest $req): string
    {
        return gumvulns_cache_dir() . '/http_' . sha1($req->method . ' ' . $req->url . ' ' . ($req->body ?? '')) . '.cache';
    }

    /**
     * @param array<string,HttpRequest> $requests keyed by an arbitrary id
     * @return array<string,HttpResponse> same keys
     */
    public static function parallel(array $requests, int $timeout = 30): array
    {
        $responses = [];

        // Serve fresh cached responses without touching the network.
        foreach ($requests as $id => $req) {
            if (self::$cacheEnabled && $req->cacheTtl > 0) {
                $cf = self::cachePath($req);
                if (gumvulns_cache_fresh($cf, $req->cacheTtl)) {
                    $responses[$id] = new HttpResponse(200, (string) file_get_contents($cf), '');
                    unset($requests[$id]);
                }
            }
        }
        if (!$requests) {
            return $responses;
        }

        $mh      = curl_multi_init();
        $handles = [];

        foreach ($requests as $id => $req) {
            $ch = curl_init();
            // Let a source override the User-Agent via its own header.
            $hasUa = false;
            foreach ($req->headers as $h) {
                if (stripos($h, 'user-agent:') === 0) {
                    $hasUa = true;
                    break;
                }
            }
            curl_setopt_array($ch, [
                CURLOPT_URL            => $req->url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_CONNECTTIMEOUT => 8,
                CURLOPT_TIMEOUT        => $req->timeout > 0 ? $req->timeout : $timeout,
                CURLOPT_ENCODING       => '',
                CURLOPT_HTTPHEADER     => $req->headers,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            if (!$hasUa) {
                curl_setopt($ch, CURLOPT_USERAGENT, 'GumVulns/1.2 (+https://github.com/GumVulns)');
            }
            if ($req->method === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
                if ($req->body !== null) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $req->body);
                }
            } elseif ($req->method !== 'GET') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $req->method);
            }
            curl_multi_add_handle($mh, $ch);
            $handles[$id] = $ch;
        }

        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) {
                curl_multi_select($mh, 1.0);
            }
        } while ($running && $status === CURLM_OK);

        // Capture accurate per-transfer error codes (status 0 cases).
        $errors = [];
        while ($info = curl_multi_info_read($mh)) {
            if ($info['result'] !== CURLE_OK) {
                $errors[spl_object_id($info['handle'])] = curl_strerror($info['result']);
            }
        }

        foreach ($handles as $id => $ch) {
            $err  = curl_error($ch) ?: ($errors[spl_object_id($ch)] ?? '');
            $body = (string) curl_multi_getcontent($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $resp = new HttpResponse($code, $body, $err);
            // Cache successful responses for sources that asked for it.
            if (self::$cacheEnabled && $requests[$id]->cacheTtl > 0 && $resp->ok() && $body !== '') {
                @file_put_contents(self::cachePath($requests[$id]), $body);
            }
            $responses[$id] = $resp;
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);

        return $responses;
    }
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

/** Runtime configuration (overridable base URLs, etc.). */
final class Config
{
    /** Override for the vulnerability-lookup API base; null = use env/default. */
    public static ?string $circlBase = null;

    /**
     * Base URL of a vulnerability-lookup API (the software behind cve.circl.lu;
     * https://github.com/vulnerability-lookup/vulnerability-lookup), e.g. a local
     * install. Precedence: explicit override > env VULNERABILITY_LOOKUP_URL >
     * env CIRCL_API_URL > public default. Returned without a trailing slash.
     */
    public static function circlBase(): string
    {
        if (self::$circlBase !== null && self::$circlBase !== '') {
            return rtrim(self::$circlBase, '/');
        }
        foreach (['VULNERABILITY_LOOKUP_URL', 'CIRCL_API_URL'] as $var) {
            $env = getenv($var);
            if ($env !== false && $env !== '') {
                return rtrim($env, '/');
            }
        }
        return 'https://cve.circl.lu/api';
    }
}

/* -------------------------------------------------------------------------- */
/* Source contract                                                            */
/* -------------------------------------------------------------------------- */

abstract class VulnSource
{
    abstract public function id(): string;
    abstract public function name(): string;

    public function isEnabled(): bool
    {
        return true;
    }

    /** Build the request for this query, or null if the source can't serve it. */
    abstract public function buildRequest(Query $q): ?HttpRequest;

    /** @return array<int,Vulnerability> */
    abstract public function parse(HttpResponse $resp, Query $q): array;

    /* ---- shared helpers ---- */

    protected function json(string $body): array
    {
        $data = json_decode($body, true);
        return is_array($data) ? $data : [];
    }

    protected function get(array $arr, string $path, $default = null)
    {
        $cur = $arr;
        foreach (explode('.', $path) as $key) {
            if (is_array($cur) && array_key_exists($key, $cur)) {
                $cur = $cur[$key];
            } else {
                return $default;
            }
        }
        return $cur;
    }

    protected function toFloat($value): ?float
    {
        if ($value === null || $value === '' || !is_numeric($value)) {
            return null;
        }
        return (float) $value;
    }
}

/* -------------------------------------------------------------------------- */
/* Sources                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Maps an NVD 2.0 "cve" object (id, descriptions, metrics, configurations) into
 * a Vulnerability. Shared by NVD and CIRCL (whose fkie_nvd feed uses the same
 * shape). Requires the host class's get()/toFloat() helpers (VulnSource).
 */
trait NvdRecordMapper
{
    protected function mapNvdCve(array $cve, string $source): Vulnerability
    {
        $desc = '';
        foreach ($this->get($cve, 'descriptions', []) ?? [] as $d) {
            if (($d['lang'] ?? '') === 'en') {
                $desc = $d['value'] ?? '';
                break;
            }
        }
        [$score, $severity, $vector] = $this->bestMetric($cve['metrics'] ?? []);
        $ranges = $this->versionRanges($cve['configurations'] ?? []);
        $v = new Vulnerability((string) ($cve['id'] ?? ''), $desc, $score, $severity, $vector, $source, $ranges);
        $this->addNvdMetrics($v, $cve['metrics'] ?? []);
        return $v;
    }

    /** Record every CVSS version present in an NVD metrics block. */
    protected function addNvdMetrics(Vulnerability $v, array $metrics): void
    {
        // V3.0 then V3.1 so the richer 3.1 wins the "3" slot.
        foreach (['cvssMetricV2' => '2', 'cvssMetricV30' => '3', 'cvssMetricV31' => '3', 'cvssMetricV40' => '4'] as $k => $ver) {
            if (empty($metrics[$k][0]['cvssData'])) {
                continue;
            }
            $entry = $metrics[$k][0];
            $c     = $entry['cvssData'];
            $sev   = (string) ($c['baseSeverity'] ?? ($entry['baseSeverity'] ?? '')); // v2 severity sits outside cvssData
            $v->addCvss($ver, isset($c['baseScore']) ? (float) $c['baseScore'] : null, (string) ($c['vectorString'] ?? ''), $sev);
        }
    }

    /** @return VersionRange[] */
    protected function versionRanges(array $configurations): array
    {
        $ranges = [];
        foreach ($configurations as $cfg) {
            foreach ($this->get($cfg, 'nodes', []) ?? [] as $node) {
                foreach ($this->get($node, 'cpeMatch', []) ?? [] as $cm) {
                    if (empty($cm['vulnerable'])) {
                        continue;
                    }
                    $parts   = explode(':', (string) ($cm['criteria'] ?? ''));
                    $product = $parts[4] ?? null;
                    $cpeVer  = $parts[5] ?? '*';

                    [$start, $startIncl] = isset($cm['versionStartIncluding'])
                        ? [$cm['versionStartIncluding'], true]
                        : (isset($cm['versionStartExcluding']) ? [$cm['versionStartExcluding'], false] : [null, true]);
                    [$end, $endIncl] = isset($cm['versionEndIncluding'])
                        ? [$cm['versionEndIncluding'], true]
                        : (isset($cm['versionEndExcluding']) ? [$cm['versionEndExcluding'], false] : [null, false]);

                    if ($start === null && $end === null) {
                        if (!in_array($cpeVer, ['*', '-', ''], true)) {
                            $ranges[] = VersionRange::exact($product, $cpeVer);
                        }
                        continue;
                    }
                    $ranges[] = VersionRange::bounded($product, $start, $startIncl, $end, $endIncl);
                }
            }
        }
        return $ranges;
    }

    /** @return array{0:?float,1:string,2:string} [score, severity, vector] */
    protected function bestMetric(array $metrics): array
    {
        foreach (['cvssMetricV31', 'cvssMetricV30'] as $k) {
            if (!empty($metrics[$k][0]['cvssData'])) {
                $c = $metrics[$k][0]['cvssData'];
                return [
                    $this->toFloat($c['baseScore'] ?? null),
                    (string) ($c['baseSeverity'] ?? ''),
                    (string) ($c['vectorString'] ?? ''),
                ];
            }
        }
        if (!empty($metrics['cvssMetricV2'][0]['cvssData'])) {
            $m = $metrics['cvssMetricV2'][0];
            return [
                $this->toFloat($m['cvssData']['baseScore'] ?? null),
                (string) ($m['baseSeverity'] ?? ''),
                (string) ($m['cvssData']['vectorString'] ?? ''),
            ];
        }
        return [null, '', ''];
    }
}

/** NIST NVD — supports CVE id, keyword and CPE (virtualMatchString). */
final class NvdSource extends VulnSource
{
    use NvdRecordMapper;

    public function id(): string   { return 'nvd'; }
    public function name(): string { return 'NVD (NIST)'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $base = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
        $url = match ($q->type) {
            QueryType::CveId   => $base . '?cveId=' . rawurlencode(strtoupper($q->raw)),
            QueryType::Keyword => $base . '?keywordSearch=' . rawurlencode($q->raw) . '&resultsPerPage=20',
            QueryType::Cpe     => $base . '?virtualMatchString=' . rawurlencode($q->cpe->toQueryCpe23()) . '&resultsPerPage=50',
        };

        $headers = ['Accept: application/json'];
        $hasKey  = ($k = getenv('NVD_API_KEY')) !== false && $k !== '';
        if ($hasKey) {
            $headers[] = 'apiKey: ' . $k;
        }
        $req = new HttpRequest($url, 'GET', $headers);
        // Keyless NVD is heavily throttled and slow; give it more room and cache.
        $req->timeout  = $hasKey ? 25 : 55;
        $req->cacheTtl = 21600; // 6h
        return $req;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $data = $this->json($resp->body);
        $out  = [];
        foreach ($this->get($data, 'vulnerabilities', []) ?? [] as $item) {
            $cve = $item['cve'] ?? null;
            if (is_array($cve)) {
                $out[] = $this->mapNvdCve($cve, $this->name());
            }
        }
        return $out;
    }
}

/** CIRCL CVE Search — CVE id (single record) and CPE (cpesearch, NVD feed). */
final class CirclSource extends VulnSource
{
    use NvdRecordMapper;

    public function id(): string   { return 'circl'; }
    public function name(): string { return 'CIRCL CVE Search'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $h    = ['Accept: application/json'];
        $base = Config::circlBase();
        if ($q->type === QueryType::CveId) {
            // Native vulnerability-lookup endpoint (works on a local install too;
            // /api/cve/ is only a cve-search compatibility shim on cve.circl.lu).
            return new HttpRequest($base . '/vulnerability/' . rawurlencode(strtoupper($q->raw)), 'GET', $h);
        }
        // CPE -> dedicated CPE search (needs a concrete vendor; wildcard returns {}).
        // The fkie_nvd feed carries CVSS + version ranges for (almost) every CVE,
        // unlike cvelistv5 which omits scores for many older records.
        if ($q->type === QueryType::Cpe && $q->cpe && $q->cpe->vendor !== '*' && $q->cpe->product !== '*') {
            return new HttpRequest(
                $base . '/vulnerability/cpesearch/' . rawurlencode($q->cpe->toQueryCpe23())
                    . '?per_page=50&page=1&source=fkie_nvd',
                'GET', $h
            );
        }
        return null;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $data = $this->json($resp->body);
        if (!$data) {
            return [];
        }
        // CPE search returns NVD-shaped records under a per-feed key (fkie_nvd).
        if ($q->type === QueryType::Cpe) {
            $out = [];
            foreach ($data as $bucket) {
                if (!is_array($bucket)) {
                    continue;
                }
                foreach ($bucket as $record) {
                    if (is_array($record) && !empty($record['id'])) {
                        $out[] = $this->mapNvdCve($record, $this->name());
                    }
                }
            }
            return $out;
        }
        $v = $this->mapRecord($data, strtoupper($q->raw));
        return $v ? [$v] : [];
    }

    /** CVE 5.0 single record (new API). */
    private function mapRecord(array $data, string $fallbackId): ?Vulnerability
    {
        $cna = $this->get($data, 'containers.cna', []) ?? [];
        $id  = $this->get($data, 'cveMetadata.cveId', null) ?? ($data['id'] ?? $fallbackId);

        $desc = '';
        foreach ($this->get($cna, 'descriptions', []) ?? [] as $d) {
            if (in_array($d['lang'] ?? '', ['en', 'en-US'], true)) {
                $desc = $d['value'] ?? '';
                break;
            }
        }
        if ($desc === '') {
            $desc = (string) ($data['summary'] ?? '');
        }
        [$score, $severity, $vector] = $this->metrics($cna, $data);
        $v = new Vulnerability((string) $id, $desc, $score, $severity, $vector, $this->name());
        $this->addAllMetrics($v, $cna, $data);
        return $v;
    }

    /** @return array<int,array<string,mixed>> all CVSS metric buckets (cna + adp). */
    private function buckets(array $cna, array $root): array
    {
        $buckets = $this->get($cna, 'metrics', []) ?? [];
        foreach ($this->get($root, 'containers.adp', []) ?? [] as $adp) {
            foreach ($this->get($adp, 'metrics', []) ?? [] as $m) {
                $buckets[] = $m;
            }
        }
        return $buckets;
    }

    private function metrics(array $cna, array $root): array
    {
        foreach (['cvssV3_1', 'cvssV3_0', 'cvssV4_0', 'cvssV2_0'] as $key) {
            foreach ($this->buckets($cna, $root) as $m) {
                if (!empty($m[$key])) {
                    $c = $m[$key];
                    return [
                        $this->toFloat($c['baseScore'] ?? null),
                        (string) ($c['baseSeverity'] ?? ''),
                        (string) ($c['vectorString'] ?? ''),
                    ];
                }
            }
        }
        return [null, '', ''];
    }

    private function addAllMetrics(Vulnerability $v, array $cna, array $root): void
    {
        $buckets = $this->buckets($cna, $root);
        foreach (['cvssV2_0' => '2', 'cvssV3_0' => '3', 'cvssV3_1' => '3', 'cvssV4_0' => '4'] as $key => $ver) {
            foreach ($buckets as $m) {
                if (!empty($m[$key])) {
                    $c = $m[$key];
                    $v->addCvss($ver, $this->toFloat($c['baseScore'] ?? null),
                        (string) ($c['vectorString'] ?? ''), (string) ($c['baseSeverity'] ?? ''));
                }
            }
        }
    }
}

/** Red Hat Security Data API (CVE id only). */
final class RedHatSource extends VulnSource
{
    public function id(): string   { return 'redhat'; }
    public function name(): string { return 'Red Hat'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $h = ['Accept: application/json'];
        if ($q->type === QueryType::CveId) {
            return new HttpRequest(
                'https://access.redhat.com/hydra/rest/securitydata/cve/' . rawurlencode(strtoupper($q->raw)) . '.json',
                'GET', $h
            );
        }
        // CPE -> product search.
        if ($q->type === QueryType::Cpe && $q->cpe && $q->cpe->product !== '*') {
            return new HttpRequest(
                'https://access.redhat.com/hydra/rest/securitydata/cve.json?product='
                . rawurlencode($q->cpe->product) . '&per_page=50',
                'GET', $h
            );
        }
        return null;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $d = $this->json($resp->body);
        if (!$d) {
            return [];
        }
        // Product search returns a list of summary objects.
        if ($q->type === QueryType::Cpe) {
            $out = [];
            foreach ($d as $row) {
                if (!is_array($row) || empty($row['CVE'])) {
                    continue;
                }
                $out[] = new Vulnerability(
                    (string) $row['CVE'],
                    (string) ($row['bugzilla_description'] ?? ''),
                    $this->toFloat($row['cvss3_score'] ?? null),
                    (string) ($row['severity'] ?? ''),
                    (string) ($row['cvss3_scoring_vector'] ?? ''),
                    $this->name()
                );
            }
            return $out;
        }
        if (empty($d['name'])) {
            return [];
        }
        $desc = $this->get($d, 'bugzilla.description', '') ?? '';
        if ($desc === '' && is_array($d['details'] ?? null)) {
            $desc = implode(' ', $d['details']);
        }
        return [new Vulnerability(
            (string) $d['name'],
            (string) $desc,
            $this->toFloat($this->get($d, 'cvss3.cvss3_base_score', null)),
            (string) ($d['threat_severity'] ?? ''),
            (string) $this->get($d, 'cvss3.cvss3_scoring_vector', ''),
            $this->name()
        )];
    }
}

/** Shodan CVEDB — CVE id (single) and CPE (by product). */
final class ShodanSource extends VulnSource
{
    public function id(): string   { return 'shodan'; }
    public function name(): string { return 'Shodan CVEDB'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $h = ['Accept: application/json'];
        if ($q->type === QueryType::CveId) {
            return new HttpRequest('https://cvedb.shodan.io/cve/' . rawurlencode(strtoupper($q->raw)), 'GET', $h);
        }
        if ($q->type === QueryType::Cpe) {
            // Shodan's cpe23 filter needs a concrete part AND version; without a
            // version fall back to the broader product filter.
            $params = $q->cpe->hasVersion()
                ? ['cpe23' => $q->cpe->toQueryCpe23(), 'limit' => '50']
                : ['product' => $q->cpe->product, 'limit' => '50'];
            return new HttpRequest('https://cvedb.shodan.io/cves?' . http_build_query($params), 'GET', $h);
        }
        return null;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $d = $this->json($resp->body);
        if (!$d) {
            return [];
        }
        if ($q->type === QueryType::Cpe) {
            $out = [];
            foreach ($this->get($d, 'cves', []) ?? [] as $row) {
                if (is_array($row)) {
                    $out[] = $this->mapRow($row);
                }
            }
            return array_filter($out);
        }
        return empty($d['cve_id']) ? [] : array_filter([$this->mapRow($d)]);
    }

    private function mapRow(array $d): ?Vulnerability
    {
        $id = (string) ($d['cve_id'] ?? '');
        if ($id === '') {
            return null;
        }
        $score = $this->toFloat($d['cvss_v3'] ?? ($d['cvss'] ?? null));
        $desc  = (string) ($d['summary'] ?? '');
        $v = new Vulnerability($id, $desc, $score, '', (string) ($d['cvss_v3_vector'] ?? ''), $this->name());
        $v->kev = !empty($d['kev']);
        return $v;
    }
}

/** Ubuntu Security CVE API (CVE id + package search). */
final class UbuntuSource extends VulnSource
{
    public function id(): string   { return 'ubuntu'; }
    public function name(): string { return 'Ubuntu Security'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $h = ['Accept: application/json'];
        if ($q->type === QueryType::CveId) {
            return new HttpRequest(
                'https://ubuntu.com/security/cves/' . rawurlencode(strtoupper($q->raw)) . '.json', 'GET', $h
            );
        }
        // CPE -> package search.
        if ($q->type === QueryType::Cpe && $q->cpe && $q->cpe->product !== '*') {
            return new HttpRequest(
                'https://ubuntu.com/security/cves.json?package=' . rawurlencode($q->cpe->product) . '&limit=50',
                'GET', $h
            );
        }
        return null;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $d = $this->json($resp->body);
        if (!$d) {
            return [];
        }
        // Package search returns { cves: [...] }.
        if ($q->type === QueryType::Cpe) {
            $out = [];
            foreach ($this->get($d, 'cves', []) ?? [] as $row) {
                if (is_array($row) && !empty($row['id'])) {
                    $out[] = $this->map($row);
                }
            }
            return $out;
        }
        return empty($d['id']) ? [] : [$this->map($d)];
    }

    private function map(array $d): Vulnerability
    {
        return new Vulnerability(
            (string) $d['id'],
            (string) ($d['description'] ?? ''),
            $this->toFloat($d['cvss3'] ?? null),
            (string) ($d['priority'] ?? ''),
            '',
            $this->name()
        );
    }
}

/** OSV.dev (CVE id only). */
final class OsvSource extends VulnSource
{
    public function id(): string   { return 'osv'; }
    public function name(): string { return 'OSV.dev'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $h = ['Content-Type: application/json', 'Accept: application/json'];

        // Commit-based query (e.g. from a GitHub download link) takes priority.
        if ($q->commit !== null && $q->commit !== '') {
            $body = json_encode(['commit' => $q->commit]);
            return new HttpRequest('https://api.osv.dev/v1/query', 'POST', $h, $body ?: null);
        }
        // Explicit package query (--osv-package): name+ecosystem or purl, +version.
        if ($q->osv !== null) {
            $pkg = $q->osv['purl'] !== null
                ? ['purl' => $q->osv['purl']]
                : ['name' => $q->osv['name'], 'ecosystem' => $q->osv['ecosystem']];
            $payload = ['package' => $pkg];
            if (!empty($q->osv['version'])) {
                $payload['version'] = $q->osv['version'];
            }
            return new HttpRequest('https://api.osv.dev/v1/query', 'POST', $h, json_encode($payload) ?: null);
        }
        if ($q->type === QueryType::CveId) {
            return new HttpRequest(
                'https://api.osv.dev/v1/vulns/' . rawurlencode(strtoupper($q->raw)),
                'GET',
                ['Accept: application/json']
            );
        }
        return null;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $d = $this->json($resp->body);
        if (!$d) {
            return [];
        }
        // A /query response is a list under "vulns"; /vulns/{id} is a single object.
        if (isset($d['vulns']) && is_array($d['vulns'])) {
            return array_filter(array_map([$this, 'mapVuln'], $d['vulns']));
        }
        if (empty($d['id'])) {
            return [];
        }
        $v = $this->mapVuln($d, strtoupper($q->raw));
        return $v ? [$v] : [];
    }

    private function mapVuln($d, string $fallbackId = ''): ?Vulnerability
    {
        if (!is_array($d) || empty($d['id'])) {
            return null;
        }
        // Collect CVSS vectors, preferring a version we can score (V3, then V2).
        $vectors = [];
        foreach ($this->get($d, 'severity', []) ?? [] as $sev) {
            $vectors[$sev['type'] ?? ''] = (string) ($sev['score'] ?? '');
        }
        $vector = $vectors['CVSS_V3'] ?? $vectors['CVSS_V2'] ?? $vectors['CVSS_V4'] ?? '';

        // Prefer the CVE alias as the id, falling back to the OSV/GHSA id.
        $cveId = '';
        foreach ($this->get($d, 'aliases', []) ?? [] as $alias) {
            if (stripos((string) $alias, 'CVE-') === 0) {
                $cveId = (string) $alias;
                break;
            }
        }
        if ($cveId === '') {
            $cveId = $fallbackId !== '' ? $fallbackId : (string) $d['id'];
        }
        $v = new Vulnerability(
            $cveId,
            (string) ($d['summary'] ?? ($d['details'] ?? '')),
            null,
            '',
            $vector,
            $this->name(),
            $this->versionRanges($d)
        );
        // Record every CVSS version OSV provides (each is a vector string).
        foreach (['CVSS_V2' => '2', 'CVSS_V3' => '3', 'CVSS_V4' => '4'] as $type => $ver) {
            if (!empty($vectors[$type])) {
                $v->addCvss($ver, null, $vectors[$type], '');
            }
        }
        return $v;
    }

    /** @return VersionRange[] */
    private function versionRanges(array $d): array
    {
        $ranges = [];
        foreach ($this->get($d, 'affected', []) ?? [] as $aff) {
            $product = $this->get($aff, 'package.name', null);
            foreach ($this->get($aff, 'ranges', []) ?? [] as $range) {
                // GIT ranges express bounds as commit hashes, not versions.
                if (($range['type'] ?? '') === 'GIT') {
                    continue;
                }
                $start = null;
                foreach ($this->get($range, 'events', []) ?? [] as $ev) {
                    if (array_key_exists('introduced', $ev)) {
                        $start = $ev['introduced'];
                    } elseif (array_key_exists('fixed', $ev)) {
                        $ranges[] = VersionRange::bounded($product, $start, true, $ev['fixed'], false);
                        $start = null;
                    } elseif (array_key_exists('last_affected', $ev)) {
                        $ranges[] = VersionRange::bounded($product, $start, true, $ev['last_affected'], true);
                        $start = null;
                    }
                }
                if ($start !== null && $start !== '0') {
                    $ranges[] = VersionRange::bounded($product, $start, true, null, false);
                }
            }
        }
        return $ranges;
    }
}

/** GitHub Advisory Database (CVE id + package/ecosystem search). */
final class GitHubSource extends VulnSource
{
    /** purl type -> GitHub advisory ecosystem. */
    private const ECOSYSTEM = [
        'maven' => 'maven', 'npm' => 'npm', 'pypi' => 'pip', 'gem' => 'rubygems',
        'golang' => 'go', 'go' => 'go', 'cargo' => 'rust', 'composer' => 'composer',
        'nuget' => 'nuget', 'hex' => 'erlang', 'pub' => 'pub', 'swift' => 'swift',
    ];

    public function id(): string   { return 'github'; }
    public function name(): string { return 'GitHub Advisory'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $headers = [
            'Accept: application/vnd.github+json',
            'X-GitHub-Api-Version: 2022-11-28',
            'User-Agent: GumVulns',
        ];
        $token = getenv('GITHUB_TOKEN');
        if ($token !== false && $token !== '') {
            $headers[] = 'Authorization: Bearer ' . $token;
        }
        if ($q->type === QueryType::CveId) {
            return new HttpRequest(
                'https://api.github.com/advisories?cve_id=' . rawurlencode(strtoupper($q->raw)),
                'GET', $headers
            );
        }
        // CPE/purl -> affected-package search.
        if ($q->type === QueryType::Cpe) {
            $params = $this->affectsParams($q);
            if ($params === null) {
                return null;
            }
            return new HttpRequest('https://api.github.com/advisories?' . http_build_query($params) . '&per_page=50',
                'GET', $headers);
        }
        return null;
    }

    /** Build the affects (+ ecosystem) query from a purl when available, else the CPE product. */
    private function affectsParams(Query $q): ?array
    {
        if ($q->purl !== null) {
            $type = $q->purl['type'];
            $name = $q->purl['name'];
            $ns   = $q->purl['namespace'];
            $pkg  = $ns !== null && $ns !== ''
                ? $ns . ($type === 'maven' ? ':' : '/') . $name
                : $name;
            $params = ['affects' => $pkg];
            if (isset(self::ECOSYSTEM[$type])) {
                $params['ecosystem'] = self::ECOSYSTEM[$type];
            }
            return $params;
        }
        if ($q->cpe && $q->cpe->product !== '*') {
            return ['affects' => $q->cpe->product];
        }
        return null;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $out = [];
        foreach ($this->json($resp->body) as $adv) {
            if (!is_array($adv)) {
                continue;
            }
            $ranges = [];
            foreach ($this->get($adv, 'vulnerabilities', []) ?? [] as $vuln) {
                $product = $this->get($vuln, 'package.name', null);
                $r = $this->parseRange($product, (string) ($vuln['vulnerable_version_range'] ?? ''));
                if ($r !== null) {
                    $ranges[] = $r;
                }
            }
            $out[] = new Vulnerability(
                (string) ($adv['cve_id'] ?? strtoupper($q->raw)),
                (string) ($adv['summary'] ?? ($adv['description'] ?? '')),
                $this->toFloat($this->get($adv, 'cvss.score', null)),
                (string) ($adv['severity'] ?? ''),
                (string) $this->get($adv, 'cvss.vector_string', ''),
                $this->name(),
                $ranges
            );
        }
        return $out;
    }

    /** Parse a range like ">= 2.0.0, < 2.15.0" or "= 1.2.3" into a VersionRange. */
    private function parseRange(?string $product, string $spec): ?VersionRange
    {
        $spec = trim($spec);
        if ($spec === '') {
            return null;
        }
        $start = $end = null;
        $startIncl = true;
        $endIncl = false;
        foreach (explode(',', $spec) as $clause) {
            if (!preg_match('/^\s*(>=|<=|>|<|=)?\s*(.+?)\s*$/', $clause, $m)) {
                continue;
            }
            $op  = $m[1] ?: '=';
            $ver = $m[2];
            switch ($op) {
                case '>=': $start = $ver; $startIncl = true;  break;
                case '>':  $start = $ver; $startIncl = false; break;
                case '<=': $end = $ver;   $endIncl = true;    break;
                case '<':  $end = $ver;   $endIncl = false;   break;
                case '=':  return VersionRange::exact($product, $ver);
            }
        }
        return VersionRange::bounded($product, $start, $startIncl, $end, $endIncl);
    }
}

/** CISA Known Exploited Vulnerabilities catalog (CVE id only). */
final class CisaKevSource extends VulnSource
{
    public function id(): string   { return 'cisa-kev'; }
    public function name(): string { return 'CISA KEV'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        if ($q->type !== QueryType::CveId) {
            return null;
        }
        return new HttpRequest(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'GET',
            ['Accept: application/json']
        );
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        return $this->parseBatch($resp, [strtoupper($q->raw)]);
    }

    /** One feed download serves any number of CVEs (used by enrichment). */
    public function buildBatchRequest(array $cveIds): HttpRequest
    {
        return new HttpRequest(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'GET',
            ['Accept: application/json']
        );
    }

    /** @param string[] $cveIds @return Vulnerability[] */
    public function parseBatch(HttpResponse $resp, array $cveIds): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $want = array_flip(array_map('strtoupper', $cveIds));
        $out  = [];
        foreach ($this->get($this->json($resp->body), 'vulnerabilities', []) ?? [] as $v) {
            $id = strtoupper((string) ($v['cveID'] ?? ''));
            if (!isset($want[$id])) {
                continue;
            }
            $desc = trim(($v['vulnerabilityName'] ?? '') . ' — ' . ($v['shortDescription'] ?? ''));
            if (!empty($v['requiredAction'])) {
                $desc .= ' Required action: ' . $v['requiredAction'];
            }
            $vuln = new Vulnerability($id, $desc, null, 'KNOWN EXPLOITED', '', $this->name());
            $vuln->kev = true;
            $out[] = $vuln;
        }
        return $out;
    }
}

/** FIRST EPSS — Exploit Prediction Scoring System (CVE id only). */
final class EpssSource extends VulnSource
{
    public function id(): string   { return 'epss'; }
    public function name(): string { return 'FIRST EPSS'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        if ($q->type !== QueryType::CveId) {
            return null;
        }
        return $this->buildBatchRequest([strtoupper($q->raw)]);
    }

    /** EPSS accepts a comma-separated list of CVEs in one request. */
    public function buildBatchRequest(array $cveIds): HttpRequest
    {
        $list = implode(',', array_map('strtoupper', array_slice($cveIds, 0, 100)));
        return new HttpRequest(
            'https://api.first.org/data/v1/epss?cve=' . rawurlencode($list),
            'GET',
            ['Accept: application/json']
        );
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $out = [];
        foreach ($this->get($this->json($resp->body), 'data', []) ?? [] as $row) {
            $cve = strtoupper((string) ($row['cve'] ?? $q->raw));
            if ($cve === '') {
                continue;
            }
            $epss       = $this->toFloat($row['epss'] ?? null);
            $percentile = $this->toFloat($row['percentile'] ?? null);
            $pct        = $epss !== null ? round($epss * 100, 2) : 0.0;
            $desc = sprintf(
                'Exploit probability (next 30 days): %s%%%s',
                $pct,
                $percentile !== null ? sprintf(' (percentile %.2f)', $percentile * 100) : ''
            );
            // EPSS is a probability, not a CVSS score — keep it off score/severity.
            $v = new Vulnerability($cve, $desc, null, '', '', $this->name());
            $v->epss = $epss;
            $v->epssPercentile = $percentile;
            $out[] = $v;
        }
        return $out;
    }
}

/** Vulners — CVE id, keyword and CPE (requires VULNERS_API_KEY). */
final class VulnersSource extends VulnSource
{
    public function id(): string   { return 'vulners'; }
    public function name(): string { return 'Vulners'; }

    public function isEnabled(): bool
    {
        $k = getenv('VULNERS_API_KEY');
        return $k !== false && $k !== '';
    }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $key = (string) getenv('VULNERS_API_KEY');
        $h   = ['Content-Type: application/json', 'Accept: application/json'];

        if ($q->type === QueryType::CveId) {
            $body = json_encode(['id' => strtoupper($q->raw), 'apiKey' => $key]);
            return new HttpRequest('https://vulners.com/api/v3/search/id/', 'POST', $h, $body ?: null);
        }
        // Keyword and CPE both go through Lucene search.
        $lucene = $q->type === QueryType::Cpe
            ? sprintf('type:cve AND affectedSoftware.name:"%s"', $q->cpe->product)
            : $q->raw;
        $body = json_encode(['query' => $lucene, 'size' => 50, 'apiKey' => $key]);
        return new HttpRequest('https://vulners.com/api/v3/search/lucene/', 'POST', $h, $body ?: null);
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $d   = $this->json($resp->body);
        $out = [];

        $docs = $this->get($d, 'data.documents', null);
        if (is_array($docs)) {
            foreach ($docs as $doc) {
                $v = $this->mapDoc($doc, strtoupper($q->raw));
                if ($v) {
                    $out[] = $v;
                }
            }
            return $out;
        }
        foreach ($this->get($d, 'data.search', []) ?? [] as $hit) {
            $v = $this->mapDoc($hit['_source'] ?? $hit, strtoupper($q->raw));
            if ($v) {
                $out[] = $v;
            }
        }
        return $out;
    }

    private function mapDoc($doc, string $fallbackId): ?Vulnerability
    {
        if (!is_array($doc)) {
            return null;
        }
        $id = (string) ($doc['id'] ?? $fallbackId);
        // Only surface CVE records, not scanner plugins etc.
        if (stripos($id, 'CVE-') !== 0) {
            $cves = $doc['cvelist'] ?? [];
            if (!is_array($cves) || !$cves) {
                return null;
            }
            $id = (string) $cves[0];
        }
        $score  = $this->toFloat($this->get($doc, 'cvss3.cvssV3.baseScore', null))
            ?? $this->toFloat($this->get($doc, 'cvss.score', null));
        $vector = (string) ($this->get($doc, 'cvss3.cvssV3.vectorString', '')
            ?: $this->get($doc, 'cvss.vector', ''));
        $sev    = (string) $this->get($doc, 'cvss3.cvssV3.baseSeverity', '');
        $desc   = (string) ($doc['description'] ?? ($doc['title'] ?? ''));
        return new Vulnerability($id, $desc, $score, $sev, $vector, $this->name());
    }
}

/** VulnCheck NVD-2 index (CVE id; requires VULNCHECK_API_KEY). */
final class VulnCheckSource extends VulnSource
{
    public function id(): string   { return 'vulncheck'; }
    public function name(): string { return 'VulnCheck'; }

    public function isEnabled(): bool
    {
        $k = getenv('VULNCHECK_API_KEY');
        return $k !== false && $k !== '';
    }

    public function buildRequest(Query $q): ?HttpRequest
    {
        if ($q->type !== QueryType::CveId) {
            return null;
        }
        $key = (string) getenv('VULNCHECK_API_KEY');
        return new HttpRequest(
            'https://api.vulncheck.com/v3/index/nist-nvd2?cve=' . rawurlencode(strtoupper($q->raw)),
            'GET',
            ['Accept: application/json', 'Authorization: Bearer ' . $key]
        );
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $out = [];
        foreach ($this->get($this->json($resp->body), 'data', []) ?? [] as $item) {
            $desc = '';
            foreach ($this->get($item, 'descriptions', []) ?? [] as $de) {
                if (($de['lang'] ?? '') === 'en') {
                    $desc = $de['value'] ?? '';
                    break;
                }
            }
            $out[] = new Vulnerability(
                (string) ($item['id'] ?? $q->raw),
                (string) $desc,
                $this->toFloat($this->get($item, 'metrics.cvssMetricV31.0.cvssData.baseScore', null)),
                (string) $this->get($item, 'metrics.cvssMetricV31.0.cvssData.baseSeverity', ''),
                (string) $this->get($item, 'metrics.cvssMetricV31.0.cvssData.vectorString', ''),
                $this->name()
            );
        }
        return $out;
    }
}

/**
 * search_vulns (search-vulns.com) — an aggregator API that matches by product /
 * version / CPE / purl / CVE and returns CVSS, EPSS, exploits and KEV.
 * Requires SEARCH_VULNS_API_KEY; base overridable via SEARCH_VULNS_URL.
 */
final class SearchVulnsSource extends VulnSource
{
    public function id(): string   { return 'search-vulns'; }
    public function name(): string { return 'search_vulns'; }

    public function isEnabled(): bool
    {
        $k = getenv('SEARCH_VULNS_API_KEY');
        return $k !== false && $k !== '';
    }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $query = $this->queryString($q);
        if ($query === '') {
            return null;
        }
        $base = getenv('SEARCH_VULNS_URL');
        $base = ($base !== false && $base !== '') ? rtrim($base, '/') : 'https://search-vulns.com/api';
        return new HttpRequest(
            $base . '/search-vulns?query=' . rawurlencode($query),
            'GET',
            ['Accept: application/json', 'API-Key: ' . (string) getenv('SEARCH_VULNS_API_KEY')]
        );
    }

    /** Turn the query into search_vulns' free-text "query" (product/CPE/purl/CVE). */
    private function queryString(Query $q): string
    {
        if ($q->purl !== null) {
            return $q->purl['raw'];
        }
        if ($q->type === QueryType::Cpe && $q->cpe) {
            $parts = array_filter(
                [$q->cpe->vendor, $q->cpe->product, $q->cpe->hasVersion() ? $q->cpe->version : ''],
                static fn ($p) => $p !== '' && $p !== '*'
            );
            return implode(' ', $parts);
        }
        return $q->type === QueryType::CveId ? strtoupper($q->raw) : $q->raw;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $out = [];
        foreach ($this->get($this->json($resp->body), 'vulns', []) ?? [] as $vid => $vd) {
            if (!is_array($vd)) {
                continue;
            }
            // Prefer a CVE id (the key, or one of the aliases).
            $cveId = stripos((string) $vid, 'CVE-') === 0 ? (string) $vid : '';
            if ($cveId === '') {
                foreach (array_keys($this->get($vd, 'aliases', []) ?? []) as $alias) {
                    if (stripos((string) $alias, 'CVE-') === 0) {
                        $cveId = (string) $alias;
                        break;
                    }
                }
            }
            $cvss   = $this->get($vd, 'severity.CVSS', []) ?? [];
            $score  = $this->toFloat($cvss['score'] ?? null);
            $vector = (string) ($cvss['vector'] ?? '');

            $v = new Vulnerability(
                $cveId !== '' ? $cveId : (string) $vid,
                (string) ($vd['description'] ?? ''),
                $score,
                '',
                $vector,
                $this->name()
            );
            if ($vector !== '' || $score !== null) {
                $ver = isset($cvss['version']) ? explode('.', (string) $cvss['version'])[0] : (Cvss::version($vector) ?? '');
                $v->addCvss($ver, $score, $vector, '');
            }
            $epss = $this->toFloat($this->get($vd, 'severity.EPSS.score', null));
            if ($epss !== null) {
                $v->epss = $epss;
            }
            if (!empty($vd['kev'])) {
                $v->kev = true;
            }
            foreach (array_slice($this->get($vd, 'exploits', []) ?? [], 0, 15) as $url) {
                $v->exploits[] = ['source' => 'search_vulns', 'url' => (string) $url];
            }
            $out[] = $v;
        }
        return $out;
    }
}

/** EUVD — the EU Vulnerability Database (ENISA). JSON search API. */
final class EuvdSource extends VulnSource
{
    public function id(): string   { return 'euvd'; }
    public function name(): string { return 'EUVD (ENISA)'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        $base = 'https://euvdservices.enisa.europa.eu/api/search';
        $h    = ['Accept: application/json'];
        switch ($q->type) {
            case QueryType::CveId:
                // No per-CVE endpoint; search by text and filter on alias.
                return new HttpRequest($base . '?text=' . rawurlencode(strtoupper($q->raw)) . '&size=40', 'GET', $h);
            case QueryType::Keyword:
                return new HttpRequest($base . '?text=' . rawurlencode($q->raw) . '&size=40', 'GET', $h);
            case QueryType::Cpe:
                $params = ['product' => $q->cpe->product, 'size' => '40'];
                if ($q->cpe->vendor !== '*') {
                    $params['vendor'] = $q->cpe->vendor;
                }
                return new HttpRequest($base . '?' . http_build_query($params), 'GET', $h);
        }
        return null;
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $items = $this->get($this->json($resp->body), 'items', []) ?? [];
        $want  = strtoupper($q->raw);
        $out   = [];
        foreach ($items as $it) {
            if (!is_array($it)) {
                continue;
            }
            $aliases = $this->aliases($it);
            // In CVE mode keep only the record that actually carries that CVE.
            if ($q->type === QueryType::CveId
                && !in_array($want, $aliases, true)
                && strtoupper((string) ($it['id'] ?? '')) !== $want) {
                continue;
            }
            $cveId = '';
            foreach ($aliases as $a) {
                if (stripos($a, 'CVE-') === 0) {
                    $cveId = $a;
                    break;
                }
            }
            $ranges = [];
            foreach ($this->get($it, 'enisaIdProduct', []) ?? [] as $p) {
                $name = $this->get($p, 'product.name', null);
                $pv   = trim((string) ($p['product_version'] ?? ''));
                if ($pv !== '') {
                    $ranges[] = VersionRange::rawText($name, $pv);
                }
            }
            $out[] = new Vulnerability(
                $cveId !== '' ? $cveId : (string) ($it['id'] ?? ''),
                (string) ($it['description'] ?? ''),
                $this->toFloat($it['baseScore'] ?? null),
                '',
                (string) ($it['baseScoreVector'] ?? ''),
                $this->name(),
                $ranges
            );
        }
        return $out;
    }

    /** EUVD "aliases" is a newline/space separated string of CVE/GHSA ids. */
    private function aliases(array $it): array
    {
        $raw = (string) ($it['aliases'] ?? '');
        return array_values(array_filter(array_map(
            static fn ($s) => strtoupper(trim($s)),
            preg_split('/\s+/', $raw) ?: []
        )));
    }
}

/**
 * CVE Details (cvedetails.com). The site has a paid API and is otherwise behind
 * Cloudflare, so this scrapes the public CVE page (CVE id only).
 *
 * Set CVEDETAILS_COOKIE to a browser "cf_clearance"/session cookie to get past
 * the Cloudflare challenge from a server IP.
 */
final class CveDetailsSource extends VulnSource
{
    private const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

    public function id(): string   { return 'cvedetails'; }
    public function name(): string { return 'CVE Details'; }

    public function buildRequest(Query $q): ?HttpRequest
    {
        if ($q->type !== QueryType::CveId) {
            return null;
        }
        $headers = [
            'User-Agent: ' . self::UA,
            'Accept: text/html,application/xhtml+xml',
            'Accept-Language: en-US,en;q=0.9',
        ];
        $cookie = getenv('CVEDETAILS_COOKIE');
        if ($cookie !== false && $cookie !== '') {
            $headers[] = 'Cookie: ' . $cookie;
        }
        return new HttpRequest(
            'https://www.cvedetails.com/cve/' . rawurlencode(strtoupper($q->raw)) . '/',
            'GET',
            $headers
        );
    }

    public function parse(HttpResponse $resp, Query $q): array
    {
        if (!$resp->ok()) {
            return [];
        }
        $html = $resp->body;
        // Detect a Cloudflare interstitial rather than the real page.
        if (stripos($html, 'Just a moment') !== false || stripos($html, 'cf-browser-verification') !== false) {
            return [];
        }
        $desc   = $this->metaDescription($html);
        $vector = $this->cvssVector($html);
        $score  = $this->cvssScore($html); // numeric fallback if no vector

        if ($desc === '' && $vector === '' && $score === null) {
            return [];
        }
        return [new Vulnerability(strtoupper($q->raw), $desc, $score, '', $vector, $this->name())];
    }

    private function metaDescription(string $html): string
    {
        foreach (['og:description', 'description'] as $name) {
            $attr = str_contains($name, ':') ? 'property' : 'name';
            if (preg_match('/<meta[^>]+' . $attr . '=["\']' . preg_quote($name, '/')
                . '["\'][^>]*content=["\']([^"\']*)["\']/i', $html, $m)) {
                $text = html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5);
                if (trim($text) !== '') {
                    return $text;
                }
            }
        }
        return '';
    }

    private function cvssVector(string $html): string
    {
        if (preg_match('#CVSS:3\.[01]/[A-Z:/]+#', $html, $m)) {
            return $m[0];
        }
        if (preg_match('#AV:[NALP]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]#', $html, $m)) {
            return $m[0];
        }
        return '';
    }

    private function cvssScore(string $html): ?float
    {
        if (preg_match('/CVSS\s*Score[^0-9]{0,30}(10(?:\.0)?|\d\.\d)/i', $html, $m)) {
            return (float) $m[1];
        }
        return null;
    }
}

/* -------------------------------------------------------------------------- */
/* Aggregator                                                                  */
/* -------------------------------------------------------------------------- */

final class Aggregator
{
    /** @var VulnSource[] */
    private array $sources;
    private int $timeout;

    /** @param VulnSource[] $sources */
    public function __construct(array $sources, int $timeout = 30)
    {
        $this->sources = $sources;
        $this->timeout = $timeout;
    }

    /**
     * Run every applicable source in parallel. In CPE mode it also fetches the
     * CPE dictionary entry from NVD so the platform can be described.
     *
     * @return array{results: Vulnerability[], diagnostics: array<int,array<string,mixed>>, cpe_meta: ?HttpResponse}
     */
    public function search(Query $q): array
    {
        $jobs = []; // id => VulnSource
        $reqs = []; // id => HttpRequest
        foreach ($this->sources as $src) {
            if (!$src->isEnabled()) {
                continue;
            }
            $req = $src->buildRequest($q);
            if ($req !== null) {
                $jobs[$src->id()] = $src;
                $reqs[$src->id()] = $req;
            }
        }

        // CPE info ("Title"/known): prefer NVD's CPE dictionary when a key is set;
        // otherwise use CIRCL's vendor catalog so we don't make a second, slow,
        // keyless NVD call that competes with the main NVD search.
        $hasNvdKey = ($k = getenv('NVD_API_KEY')) !== false && $k !== '';
        $metaKind  = null;
        if ($q->type === QueryType::Cpe && $q->cpe !== null) {
            if ($hasNvdKey) {
                $reqs['__cpe_meta'] = $this->cpeMetaRequest($q->cpe);
                $metaKind = 'nvd';
            } elseif ($q->cpe->vendor !== '*') {
                $reqs['__cpe_meta'] = $this->circlBrowseRequest($q->cpe->vendor);
                $metaKind = 'circl';
            }
        }

        $responses = Http::parallel($reqs, $this->timeout);

        $results     = [];
        $diagnostics = [];
        foreach ($jobs as $id => $src) {
            $resp  = $responses[$id];
            $vulns = [];
            try {
                $vulns = $resp->error === '' ? $src->parse($resp, $q) : [];
            } catch (\Throwable $e) {
                $resp = new HttpResponse($resp->status, '', 'parse error: ' . $e->getMessage());
            }
            foreach ($vulns as $v) {
                $results[] = $v;
            }
            $diagnostics[] = [
                'source' => $src->name(),
                'status' => $resp->status,
                'count'  => count($vulns),
                'error'  => $resp->error,
            ];
        }

        return [
            'results'        => $results,
            'diagnostics'    => $diagnostics,
            'cpe_meta'       => $responses['__cpe_meta'] ?? null,
            'cpe_meta_kind'  => $metaKind,
            'ran'            => array_keys($jobs),
        ];
    }

    private function circlBrowseRequest(string $vendor): HttpRequest
    {
        $req = new HttpRequest(
            Config::circlBase() . '/browse/' . rawurlencode(strtolower($vendor)),
            'GET',
            ['Accept: application/json']
        );
        $req->timeout  = 20;
        $req->cacheTtl = 21600; // 6h
        return $req;
    }

    /**
     * Cross-reference a set of CVE ids against every CVE-keyed source that did
     * NOT already run (by id in $skipIds). Bulk sources (CISA KEV feed, EPSS
     * batch) make a single request; the rest do one request per CVE. All run
     * in one parallel batch.
     *
     * @param string[] $cveIds
     * @param string[] $skipIds
     * @return array{results: Vulnerability[], diagnostics: array<int,array<string,mixed>>}
     */
    public function enrich(array $cveIds, array $skipIds): array
    {
        $cveIds = array_values(array_unique(array_filter(
            array_map('strtoupper', $cveIds),
            static fn ($c) => (bool) preg_match('/^CVE-\d{4}-\d{4,}$/', $c)
        )));
        if (!$cveIds) {
            return ['results' => [], 'diagnostics' => []];
        }
        $skip = array_flip($skipIds);

        $reqs = [];   // key => HttpRequest
        $plan = [];   // key => ['src'=>VulnSource,'cve'=>?string,'batch'=>bool]
        foreach ($this->sources as $src) {
            if (!$src->isEnabled() || isset($skip[$src->id()])) {
                continue;
            }
            // Only sources that can answer a CVE-id query.
            if ($src->buildRequest(new Query(QueryType::CveId, $cveIds[0])) === null) {
                continue;
            }
            if (method_exists($src, 'buildBatchRequest')) {
                $key = $src->id() . '|batch';
                $reqs[$key] = $src->buildBatchRequest($cveIds);
                $plan[$key] = ['src' => $src, 'cve' => null, 'batch' => true];
            } else {
                foreach ($cveIds as $cve) {
                    $key = $src->id() . '|' . $cve;
                    $reqs[$key] = $src->buildRequest(new Query(QueryType::CveId, $cve));
                    $plan[$key] = ['src' => $src, 'cve' => $cve, 'batch' => false];
                }
            }
        }
        if (!$reqs) {
            return ['results' => [], 'diagnostics' => []];
        }

        $responses = Http::parallel($reqs, $this->timeout);

        $results = [];
        $counts  = []; // source name => count
        foreach ($plan as $key => $p) {
            $src  = $p['src'];
            $resp = $responses[$key];
            $vs   = [];
            try {
                if ($p['batch']) {
                    $vs = method_exists($src, 'parseBatch')
                        ? $src->parseBatch($resp, $cveIds)
                        : $src->parse($resp, new Query(QueryType::CveId, ''));
                } elseif ($resp->error === '') {
                    $vs = $src->parse($resp, new Query(QueryType::CveId, (string) $p['cve']));
                }
            } catch (\Throwable $e) {
                $vs = [];
            }
            foreach ($vs as $v) {
                $results[] = $v;
            }
            $counts[$src->name()] = ($counts[$src->name()] ?? 0) + count($vs);
        }

        $diagnostics = [];
        foreach ($counts as $name => $n) {
            $diagnostics[] = ['source' => $name . ' (enrich)', 'status' => 200, 'count' => $n, 'error' => ''];
        }
        return ['results' => $results, 'diagnostics' => $diagnostics];
    }

    private function cpeMetaRequest(Cpe $cpe): HttpRequest
    {
        $url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString='
            . rawurlencode($cpe->toQueryCpe23()) . '&resultsPerPage=10';
        $headers = ['Accept: application/json'];
        $key = getenv('NVD_API_KEY');
        if ($key !== false && $key !== '') {
            $headers[] = 'apiKey: ' . $key;
        }
        $req = new HttpRequest($url, 'GET', $headers);
        $req->timeout  = 25;
        $req->cacheTtl = 21600; // 6h
        return $req;
    }
}

/* -------------------------------------------------------------------------- */
/* Version flagging + exploit enrichment                                       */
/* -------------------------------------------------------------------------- */

final class VersionFlag
{
    /**
     * Decide whether $version is affected, based on the result's ranges.
     * Only ranges whose product matches $product are considered.
     *
     * @return array{0: ?bool, 1: ?string} [verdict, matched range]
     */
    public static function evaluate(Vulnerability $v, string $version, ?string $product): array
    {
        $sawEvaluable = false;
        foreach ($v->versions as $r) {
            if (!$r->productMatches($product)) {
                continue;
            }
            $hit = $r->contains($version);
            if ($hit === null) {
                continue;
            }
            $sawEvaluable = true;
            if ($hit) {
                return [true, $r->format()];
            }
        }
        return [$sawEvaluable ? false : null, null];
    }
}

/** Persistent cache directory (survives between runs, unlike the temp dir). */
function gumvulns_cache_dir(): string
{
    $base = getenv('XDG_CACHE_HOME') ?: ((getenv('HOME') ?: sys_get_temp_dir()) . '/.cache');
    $dir  = $base . '/gumvulns';
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    return is_dir($dir) ? $dir : sys_get_temp_dir();
}

function gumvulns_cache_fresh(string $path, int $ttl): bool
{
    return is_file($path) && filesize($path) > 0 && (time() - filemtime($path)) < $ttl;
}

/**
 * Exploit/PoC indexes adopted from search_vulns. Each is a single bulk file,
 * downloaded once into the cache (cold-cache files fetched in parallel) and
 * parsed into CVE id (upper) => URLs.
 *
 * @return array<string, array<string,string[]>> source name => (CVE => URLs)
 */
function gumvulns_exploit_indexes(int $ttl = 21600): array
{
    $dir  = gumvulns_cache_dir();
    $defs = [
        'Nuclei'     => ['nuclei.jsonl',   'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json'],
        'ExploitDB'  => ['exploitdb.csv',  'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'],
        'Metasploit' => ['metasploit.json','https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json'],
    ];

    // Download any stale/missing files concurrently.
    $reqs = [];
    foreach ($defs as $src => [$file, $url]) {
        if (!gumvulns_cache_fresh($dir . '/' . $file, $ttl)) {
            $reqs[$src] = new HttpRequest($url, 'GET', ['Accept: */*']);
        }
    }
    if ($reqs) {
        foreach (Http::parallel($reqs, 60) as $src => $resp) {
            if ($resp->ok() && $resp->body !== '') {
                @file_put_contents($dir . '/' . $defs[$src][0], $resp->body);
            }
        }
    }

    return [
        'Nuclei'     => gumvulns_parse_nuclei($dir . '/' . $defs['Nuclei'][0]),
        'ExploitDB'  => gumvulns_parse_exploitdb($dir . '/' . $defs['ExploitDB'][0]),
        'Metasploit' => gumvulns_parse_metasploit($dir . '/' . $defs['Metasploit'][0]),
    ];
}

/** ProjectDiscovery Nuclei templates (cves.json, JSONL). */
function gumvulns_parse_nuclei(string $path): array
{
    $map = [];
    if (is_file($path) && ($fh = @fopen($path, 'r'))) {
        while (($line = fgets($fh)) !== false) {
            $o = json_decode($line, true);
            if (is_array($o) && !empty($o['ID']) && !empty($o['file_path'])) {
                $map[strtoupper($o['ID'])][] =
                    'https://github.com/projectdiscovery/nuclei-templates/blob/main/' . $o['file_path'];
            }
        }
        fclose($fh);
    }
    return $map;
}

/** Exploit-DB (files_exploits.csv); the "codes" column lists CVE ids. */
function gumvulns_parse_exploitdb(string $path): array
{
    $map = [];
    if (!is_file($path) || !($fh = @fopen($path, 'r'))) {
        return $map;
    }
    $header   = fgetcsv($fh);
    $idIdx    = is_array($header) ? array_search('id', $header, true) : 0;
    $codesIdx = is_array($header) ? array_search('codes', $header, true) : false;
    if ($codesIdx === false) {
        fclose($fh);
        return $map;
    }
    while (($row = fgetcsv($fh)) !== false) {
        $codes = $row[$codesIdx] ?? '';
        if ($codes === '' || stripos($codes, 'CVE-') === false) {
            continue;
        }
        if (preg_match_all('/CVE-\d{4}-\d{4,}/i', $codes, $m)) {
            $url = 'https://www.exploit-db.com/exploits/' . ($row[$idIdx] ?? '');
            foreach ($m[0] as $cve) {
                $map[strtoupper($cve)][] = $url;
            }
        }
    }
    fclose($fh);
    return $map;
}

/** Metasploit framework module metadata; references[] carry CVE ids. */
function gumvulns_parse_metasploit(string $path): array
{
    $map = [];
    if (!is_file($path)) {
        return $map;
    }
    $data = json_decode((string) file_get_contents($path), true);
    if (!is_array($data)) {
        return $map;
    }
    foreach ($data as $mod) {
        $refs = $mod['references'] ?? [];
        $p    = $mod['path'] ?? '';
        if (!is_array($refs) || $p === '') {
            continue;
        }
        $url = 'https://github.com/rapid7/metasploit-framework/blob/master' . $p;
        foreach ($refs as $ref) {
            if (stripos((string) $ref, 'CVE-') === 0) {
                $map[strtoupper($ref)][] = $url;
            }
        }
    }
    return $map;
}

/** PoC-in-GitHub (nomi-sec): per-CVE JSON file of public PoC repositories. */
function gumvulns_poc_in_github(string $cve): array
{
    if (!preg_match('/^CVE-(\d{4})-\d+$/i', $cve, $m)) {
        return [];
    }
    $url  = sprintf('https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/%s/%s.json',
        $m[1], strtoupper($cve));
    $resp = Http::parallel(['p' => new HttpRequest($url, 'GET', ['Accept: application/json'])], 15)['p'];
    if (!$resp->ok()) {
        return [];
    }
    $data = json_decode($resp->body, true);
    $urls = [];
    foreach (is_array($data) ? $data : [] as $item) {
        if (!empty($item['html_url'])) {
            $urls[] = $item['html_url'];
        }
        if (count($urls) >= 15) {
            break;
        }
    }
    return $urls;
}

/**
 * endoflife.date lifecycle status for a product/version.
 *
 * @return array{status:string,cycle:?string,eol:?string,latest:?string}|null
 */
function gumvulns_eol(string $product, string $version): ?array
{
    $product = strtolower(trim($product));
    if ($product === '' || $product === '*') {
        return null;
    }
    $resp = Http::parallel(
        ['e' => new HttpRequest('https://endoflife.date/api/' . rawurlencode($product) . '.json',
            'GET', ['Accept: application/json'])],
        15
    )['e'];
    if (!$resp->ok()) {
        return null;
    }
    $cycles = json_decode($resp->body, true);
    if (!is_array($cycles)) {
        return null;
    }
    foreach ($cycles as $c) {
        $cycle = (string) ($c['cycle'] ?? '');
        if ($cycle === '') {
            continue;
        }
        // The version belongs to this branch if it equals or starts with the cycle.
        if ($version === $cycle || str_starts_with($version . '.', $cycle . '.') || str_starts_with($version, $cycle . '.')) {
            $eol = $c['eol'] ?? null;
            $isEol = $eol === true
                || (is_string($eol) && strtotime($eol) !== false && strtotime($eol) <= time());
            return [
                'status' => $isEol ? 'END-OF-LIFE' : 'supported',
                'cycle'  => $cycle,
                'eol'    => is_string($eol) ? $eol : ($eol === true ? 'yes' : 'no'),
                'latest' => isset($c['latest']) ? (string) $c['latest'] : null,
            ];
        }
    }
    return null;
}

/* -------------------------------------------------------------------------- */
/* Result merging                                                              */
/* -------------------------------------------------------------------------- */

final class Merger
{
    /**
     * Collapse multiple source records for the same CVE into one row, keeping the
     * richest data and listing every contributing source. Sorted by score desc.
     *
     * @param Vulnerability[] $results
     * @return Vulnerability[]
     */
    public static function mergeByCve(array $results): array
    {
        /** @var array<string,Vulnerability> $byCve */
        $byCve   = [];
        $sources = []; // cve => set of source names

        foreach ($results as $v) {
            $key = strtoupper($v->cveId);
            $sources[$key][$v->source] = true;

            if (!isset($byCve[$key])) {
                $byCve[$key] = clone $v;
                continue;
            }
            $cur = $byCve[$key];
            // Prefer the higher score and fill in any missing fields.
            if ($v->score !== null && ($cur->score === null || $v->score > $cur->score)) {
                $cur->score    = $v->score;
                $cur->severity = $v->severity;
                $cur->vector   = $v->vector !== '' ? $v->vector : $cur->vector;
            }
            if ($cur->vector === '' && $v->vector !== '') {
                $cur->vector = $v->vector;
            }
            if (strlen($v->description) > strlen($cur->description)) {
                $cur->description = $v->description;
            }
            // Union the affected version ranges reported by each source.
            $cur->versions = Vulnerability::dedupeRanges(array_merge($cur->versions, $v->versions));
            // Carry over enrichment signals.
            $cur->exploits = array_merge($cur->exploits, $v->exploits);
            $cur->epss           = $cur->epss ?? $v->epss;
            $cur->epssPercentile = $cur->epssPercentile ?? $v->epssPercentile;
            $cur->kev            = $cur->kev || $v->kev;
            // Union per-version CVSS, preferring entries that carry a vector.
            foreach ($v->cvss as $ver => $entry) {
                if (!isset($cur->cvss[$ver]) || ($cur->cvss[$ver]['vector'] === '' && $entry['vector'] !== '')) {
                    $cur->cvss[$ver] = $entry;
                }
            }
        }

        foreach ($byCve as $key => $v) {
            $names = array_keys($sources[$key]);
            sort($names);
            $v->source = implode(', ', $names);
        }

        $merged = array_values($byCve);
        usort($merged, static function (Vulnerability $a, Vulnerability $b): int {
            return ($b->score ?? -1.0) <=> ($a->score ?? -1.0);
        });
        return $merged;
    }

    /**
     * Final CPE-mode ordering: confirmed-vulnerable first (when a version was
     * checked), then by CVSS score, then a known public exploit ranks above an
     * unexploited CVE at the same score.
     *
     * @param Vulnerability[] $results
     * @return Vulnerability[]
     */
    public static function orderForCpe(array $results): array
    {
        $rank   = static fn (Vulnerability $v): int =>
            $v->versionChecked ? ($v->vulnerable === true ? 0 : ($v->vulnerable === null ? 1 : 2)) : 0;
        $hasExp = static fn (Vulnerability $v): int => $v->exploits ? 0 : 1;

        usort($results, static function (Vulnerability $a, Vulnerability $b) use ($rank, $hasExp): int {
            return [$rank($a), -($a->score ?? -1.0), $hasExp($a), $a->cveId]
                <=> [$rank($b), -($b->score ?? -1.0), $hasExp($b), $b->cveId];
        });
        return $results;
    }
}

/* -------------------------------------------------------------------------- */
/* Output                                                                       */
/* -------------------------------------------------------------------------- */

final class Renderer
{
    private const RULE = "────────────────────────────────────────────────────────────\n";

    /** @param Vulnerability[] $results */
    public static function table(array $results): string
    {
        if (!$results) {
            return "No results.\n";
        }
        $out = '';
        foreach ($results as $v) {
            $score = $v->score !== null ? rtrim(rtrim(number_format($v->score, 1, '.', ''), '0'), '.') : '—';
            $out .= self::RULE;
            $out .= self::row('CVE',         $v->cveId);
            $out .= self::row('Source',      $v->source);
            $out .= self::row('Score',       $score);
            $out .= self::row('Severity',    $v->severity . ($v->kev ? '  [KEV: known exploited]' : ''));
            if ($v->epss !== null) {
                $out .= self::row('EPSS', sprintf('%.1f%% probability%s', $v->epss * 100,
                    $v->epssPercentile !== null ? sprintf(' (percentile %.1f)', $v->epssPercentile * 100) : ''));
            }
            if ($v->versionChecked) {
                $out .= self::row('Status', self::status($v));
            }
            if ($v->cvss) {
                foreach (['4', '3', '2'] as $ver) {
                    if (!isset($v->cvss[$ver])) {
                        continue;
                    }
                    $c     = $v->cvss[$ver];
                    $score = $c['score'] !== null ? rtrim(rtrim(number_format($c['score'], 1, '.', ''), '0'), '.') : '—';
                    $out  .= self::row('CVSS v' . $ver, trim($score . ' ' . $c['status'] . '  ' . ($c['vector'] !== '' ? $c['vector'] : '—')));
                }
            } else {
                $out .= self::row('Vector', $v->vector !== '' ? $v->vector : '—');
            }
            if ($v->versions) {
                $lines = array_map(static fn (VersionRange $r) => $r->format(), $v->versions);
                $shown = array_slice($lines, 0, 6);
                if (count($lines) > 6) {
                    $shown[] = sprintf('(+%d more)', count($lines) - 6);
                }
                $out .= self::row('Affected', implode("\n               ", $shown));
            }
            if ($v->exploits) {
                $lines = array_map(static fn (array $e) => $e['source'] . ': ' . $e['url'], $v->exploits);
                $shown = array_slice($lines, 0, 5);
                if (count($lines) > 5) {
                    $shown[] = sprintf('(+%d more)', count($lines) - 5);
                }
                $out .= self::row('Exploit', implode("\n               ", $shown));
            }
            $out .= self::row('Description', self::wrap($v->description !== '' ? $v->description : '—', 62));
        }
        return $out . self::RULE;
    }

    private static function status(Vulnerability $v): string
    {
        if ($v->vulnerable === true) {
            return '⚠ VULNERABLE — queried version is within ' . ($v->matchedRange ?? 'an affected range');
        }
        if ($v->vulnerable === false) {
            return '✓ not affected — queried version is outside the affected ranges';
        }
        return '? unknown — no comparable version range for this product';
    }

    public static function cpeInfo(Cpe $cpe, ?HttpResponse $meta, ?string $metaKind = 'nvd', ?array $eol = null): string
    {
        $out = "\nParsed CPE\n" . self::RULE;
        foreach ($cpe->components() as $label => $value) {
            $out .= self::row($label, $value !== '' ? $value : '—');
        }
        if ($metaKind === 'circl') {
            [$title, $known] = self::circlMeta($meta, $cpe->product);
            if ($title !== '') {
                $out .= self::row('Title', $title . '  (CIRCL)');
            }
            if ($known !== null) {
                $out .= self::row('In CIRCL DB', $known ? 'yes' : 'no');
            }
        } else {
            [$titles, $deprecated] = self::cpeMeta($meta);
            if ($titles) {
                $out .= self::row('Title', implode("\n               ", array_slice($titles, 0, 3)));
            }
            if ($deprecated !== null) {
                $out .= self::row('Deprecated', $deprecated ? 'yes' : 'no');
            }
        }
        if ($eol !== null) {
            $flag = $eol['status'] === 'END-OF-LIFE' ? '⚠ ' : '';
            $extra = [];
            if (!empty($eol['cycle']))  $extra[] = 'branch ' . $eol['cycle'];
            if (!empty($eol['latest'])) $extra[] = 'latest ' . $eol['latest'];
            if (is_string($eol['eol']) && !in_array($eol['eol'], ['yes', 'no'], true)) {
                $extra[] = 'EOL ' . $eol['eol'];
            }
            $out .= self::row('Lifecycle', $flag . $eol['status'] . ($extra ? ' (' . implode(', ', $extra) . ')' : ''));
        }
        return $out . self::RULE;
    }

    /** @return array{0:string[],1:?bool} */
    private static function cpeMeta(?HttpResponse $meta): array
    {
        if ($meta === null || !$meta->ok()) {
            return [[], null];
        }
        $data = json_decode($meta->body, true);
        if (!is_array($data)) {
            return [[], null];
        }
        $titles = [];
        $deprecated = null;
        foreach ($data['products'] ?? [] as $p) {
            $cpe = $p['cpe'] ?? [];
            $deprecated = $deprecated ?? (bool) ($cpe['deprecated'] ?? false);
            foreach ($cpe['titles'] ?? [] as $t) {
                if (($t['lang'] ?? '') === 'en' && !empty($t['title'])) {
                    $titles[$t['title']] = true;
                }
            }
        }
        return [array_keys($titles), $deprecated];
    }

    /**
     * Derive a CPE title from CIRCL's /api/browse/<vendor> product list.
     * @return array{0:string,1:?bool} [title, product-known-in-CIRCL]
     */
    private static function circlMeta(?HttpResponse $meta, string $product): array
    {
        if ($meta === null || !$meta->ok()) {
            return ['', null];
        }
        $products = json_decode($meta->body, true);
        if (!is_array($products)) {
            return ['', null];
        }
        $needle = strtolower($product);
        $match  = '';
        foreach ($products as $p) {
            $name = strtolower((string) $p);
            if ($name === $needle) {       // exact match wins
                $match = (string) $p;
                break;
            }
            if ($match === '' && $needle !== '' && str_contains($name, $needle)) {
                $match = (string) $p;      // first fuzzy match, keep looking for exact
            }
        }
        $known = $match !== '';
        $title = $known ? $match : $product;
        return [$title, $known];
    }

    private static function row(string $label, string $value): string
    {
        return sprintf("  %-12s %s\n", $label . ':', $value);
    }

    private static function wrap(string $text, int $width): string
    {
        return str_replace("\n", "\n               ", wordwrap($text, $width, "\n", true));
    }

    /** @param array{ecosystem:?string,name:?string,purl:?string,version:?string} $osv */
    public static function osvInfo(array $osv): string
    {
        $pkg = $osv['purl'] ?? trim(($osv['ecosystem'] ?? '') . ':' . ($osv['name'] ?? ''), ':');
        $out = "\nOSV package query\n" . self::RULE;
        $out .= self::row('Package', $pkg !== '' ? $pkg : '—');
        if (!empty($osv['version'])) {
            $out .= self::row('Version', $osv['version']);
        }
        return $out . self::RULE;
    }

    public static function githubInfo(GitHubRef $gh): string
    {
        $out = "\nGitHub source\n" . self::RULE;
        foreach ($gh->describe() as $label => $value) {
            $out .= self::row($label, $value);
        }
        return $out . self::RULE;
    }

    /** @param array<int,array<string,mixed>> $diag */
    public static function diagnostics(array $diag): string
    {
        $hasNvdKey = ($k = getenv('NVD_API_KEY')) !== false && $k !== '';
        $nvdTrouble = false;
        $out = "\nSources queried:\n";
        foreach ($diag as $d) {
            $note = $d['error'] !== '' ? "ERROR ({$d['error']})" : "HTTP {$d['status']}, {$d['count']} result(s)";
            $out .= sprintf("  • %-20s %s\n", $d['source'], $note);
            if (str_contains($d['source'], 'NVD') && $d['error'] !== '') {
                $nvdTrouble = true;
            }
        }
        if ($nvdTrouble && !$hasNvdKey) {
            $out .= "\n  ! NVD is rate-limited without a key. Set NVD_API_KEY for fast, reliable NVD\n"
                . "    results (free: https://nvd.nist.gov/developers/request-an-api-key).\n";
        }
        return $out;
    }
}

/* -------------------------------------------------------------------------- */
/* Registry + CLI                                                              */
/* -------------------------------------------------------------------------- */

/** @return VulnSource[] */
function gumvulns_sources(): array
{
    return [
        new NvdSource(),
        new CirclSource(),
        new RedHatSource(),
        new ShodanSource(),
        new UbuntuSource(),
        new OsvSource(),
        new GitHubSource(),
        new CisaKevSource(),
        new EpssSource(),
        new EuvdSource(),
        new CveDetailsSource(),
        new VulnersSource(),
        new VulnCheckSource(),
        new SearchVulnsSource(),
    ];
}

/** Resolve a short commit SHA to its full 40-char form via the GitHub API. */
function gumvulns_resolve_commit(string $owner, string $repo, string $sha): string
{
    if (strlen($sha) === 40) {
        return $sha; // already full
    }
    $headers = ['Accept: application/vnd.github+json', 'User-Agent: GumVulns'];
    $token = getenv('GITHUB_TOKEN');
    if ($token !== false && $token !== '') {
        $headers[] = 'Authorization: Bearer ' . $token;
    }
    $url  = sprintf('https://api.github.com/repos/%s/%s/commits/%s',
        rawurlencode($owner), rawurlencode($repo), rawurlencode($sha));
    $resp = Http::parallel(['c' => new HttpRequest($url, 'GET', $headers)], 15)['c'];
    if ($resp->ok()) {
        $data = json_decode($resp->body, true);
        if (is_array($data) && !empty($data['sha'])) {
            return (string) $data['sha'];
        }
    }
    return $sha; // fall back to the short SHA
}

/** Decide the query type from the raw input and flags. */
/**
 * Parse an --osv-package spec into an OSV query descriptor.
 * Accepts "ecosystem:name[@version]" (name may contain ':', e.g. Maven coords)
 * or a Package URL "pkg:type/ns/name[@version]".
 *
 * @return array{ecosystem:?string,name:?string,purl:?string,version:?string}|null
 */
function gumvulns_parse_osv_spec(string $spec, ?string $fallbackVersion): ?array
{
    $spec = trim($spec);
    if ($spec === '') {
        return null;
    }
    if (str_starts_with($spec, 'pkg:')) {
        // A purl can embed its own @version; if so don't also pass version.
        return [
            'ecosystem' => null,
            'name'      => null,
            'purl'      => $spec,
            'version'   => str_contains($spec, '@') ? null : $fallbackVersion,
        ];
    }
    $version = $fallbackVersion;
    if (preg_match('/^(.*)@([^@]+)$/', $spec, $m)) {
        $spec    = $m[1];
        $version = $m[2];
    }
    $pos = strpos($spec, ':');
    if ($pos === false || $pos === 0 || $pos === strlen($spec) - 1) {
        return null; // need both ecosystem and name
    }
    return [
        'ecosystem' => substr($spec, 0, $pos),
        'name'      => substr($spec, $pos + 1),
        'purl'      => null,
        'version'   => $version,
    ];
}

/**
 * Parse a Package URL (purl): pkg:type/namespace.../name@version?quals#sub.
 * The full, unparsed purl is returned under "raw" alongside the components.
 *
 * @return array{raw:string,type:string,namespace:?string,name:string,version:?string}|null
 */
function gumvulns_parse_purl(string $purl): ?array
{
    $purl = trim($purl);
    if (stripos($purl, 'pkg:') !== 0) {
        return null;
    }
    $body = substr($purl, 4);
    $body = explode('#', $body, 2)[0];   // drop subpath
    $body = explode('?', $body, 2)[0];   // drop qualifiers

    $pos = strpos($body, '/');
    if ($pos === false) {
        return null; // need at least type/name
    }
    $type = strtolower(substr($body, 0, $pos));
    $rest = substr($body, $pos + 1);

    $version = null;
    if (($at = strrpos($rest, '@')) !== false) {
        $version = rawurldecode(substr($rest, $at + 1));
        $rest    = substr($rest, 0, $at);
    }
    $segments  = array_values(array_filter(explode('/', $rest), static fn ($s) => $s !== ''));
    if (!$segments) {
        return null;
    }
    $name      = rawurldecode((string) array_pop($segments));
    $namespace = $segments ? rawurldecode(implode('/', $segments)) : null;

    return ['raw' => $purl, 'type' => $type, 'namespace' => $namespace, 'name' => $name, 'version' => $version];
}

/** Fetch NVD CPE-dictionary entries for a keyword (cached 24h). */
function gumvulns_nvd_cpe_dict(string $keyword): array
{
    $file = gumvulns_cache_dir() . '/cpedict_' . sha1(strtolower($keyword)) . '.json';
    if (!gumvulns_cache_fresh($file, 86400)) {
        $headers = ['Accept: application/json'];
        $key = getenv('NVD_API_KEY');
        if ($key !== false && $key !== '') {
            $headers[] = 'apiKey: ' . $key;
        }
        $url  = 'https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch='
            . rawurlencode($keyword) . '&resultsPerPage=50';
        $resp = Http::parallel(['c' => new HttpRequest($url, 'GET', $headers)], 30)['c'];
        if ($resp->ok() && $resp->body !== '') {
            @file_put_contents($file, $resp->body);
        }
    }
    if (!is_file($file)) {
        return [];
    }
    $d = json_decode((string) file_get_contents($file), true);
    return is_array($d) ? ($d['products'] ?? []) : [];
}

/**
 * Resolve a purl package name to a real NVD vendor:product via the CPE
 * dictionary. Tries the name, its base (before -/.), de-suffixed variants and
 * the namespace's last token; picks the most common application CPE whose
 * product relates to the candidate.
 *
 * @return array{vendor:string,product:string}|null
 */
function gumvulns_resolve_cpe_from_name(string $name, ?string $namespace): ?array
{
    $name  = strtolower($name);
    $cands = [$name];
    if (preg_match('/^([a-z0-9]+)[._-]/', $name, $m)) {
        $cands[] = $m[1];
    }
    foreach (['-core', '-api', '-server', '-client', '.js', '-js'] as $suf) {
        if (str_ends_with($name, $suf)) {
            $cands[] = substr($name, 0, -strlen($suf));
        }
    }
    if ($namespace !== null && $namespace !== '') {
        $segs = preg_split('#[/.]#', strtolower($namespace)) ?: [];
        $last = (string) end($segs);
        if ($last !== '') {
            $cands[] = $last;
        }
    }
    foreach (array_values(array_unique(array_filter($cands))) as $kw) {
        $tally = [];
        foreach (gumvulns_nvd_cpe_dict($kw) as $p) {
            if (!empty($p['cpe']['deprecated'])) {
                continue;
            }
            $parts = explode(':', (string) ($p['cpe']['cpeName'] ?? ''));
            if (count($parts) < 6 || $parts[2] !== 'a') {
                continue;
            }
            [$vendor, $product] = [$parts[3], $parts[4]];
            if ($product === $kw || str_contains($product, $kw) || str_contains($kw, $product)) {
                $tally[$vendor . ':' . $product] = ($tally[$vendor . ':' . $product] ?? 0) + 1;
            }
        }
        if ($tally) {
            arsort($tally);
            [$v, $pr] = explode(':', (string) array_key_first($tally), 2);
            return ['vendor' => $v, 'product' => $pr];
        }
    }
    return null;
}

function gumvulns_parse_query(string $raw, bool $forceCpe, bool $resolveCpe = true): Query
{
    // Package URL (purl): OSV queries it natively; derive product/version so the
    // CPE-capable sources, version flag and enrichment apply too.
    if (stripos($raw, 'pkg:') === 0) {
        $p = gumvulns_parse_purl($raw);
        if ($p === null) {
            throw new InvalidArgumentException('Could not parse purl (expected pkg:type/namespace/name@version).');
        }
        $resolved = $resolveCpe ? gumvulns_resolve_cpe_from_name($p['name'], $p['namespace']) : null;
        $cpe = $resolved !== null
            ? Cpe::fromParts($resolved['vendor'], $resolved['product'], $p['version'] ?? '*')
            : Cpe::fromParts('', $p['name'], $p['version'] ?? '*');
        $q = new Query(QueryType::Cpe, $raw, $cpe);
        $q->osv = ['ecosystem' => null, 'name' => null, 'purl' => $raw, 'version' => null];
        $q->cpeResolved = $resolved !== null;
        $q->purl = $p;
        return $q;
    }

    // GitHub download/source link: extract commit (for OSV) and owner/repo/version (for CPE sources).
    if (preg_match('#^https?://#i', $raw)) {
        $gh = GitHubRef::parse($raw);
        if ($gh !== null) {
            if ($gh->refType === 'commit' && $gh->commit !== null) {
                $gh->commit = gumvulns_resolve_commit($gh->owner, $gh->repo, $gh->commit);
            }
            return new Query(QueryType::Cpe, $raw, $gh->toCpe(), $gh->commit, $gh);
        }
        throw new InvalidArgumentException('Unrecognized URL (only GitHub links are supported).');
    }

    if ($forceCpe || stripos($raw, 'cpe:') === 0) {
        $cpe = Cpe::parse($raw);
        if ($cpe === null) {
            throw new InvalidArgumentException('Could not parse a vendor/product from the CPE input.');
        }
        return new Query(QueryType::Cpe, $raw, $cpe);
    }
    if (preg_match('/^CVE-\d{4}-\d{4,}$/i', trim($raw))) {
        return new Query(QueryType::CveId, $raw);
    }
    return new Query(QueryType::Keyword, $raw);
}

/**
 * Library entry point — run a full search and return structured results.
 *
 * @param string $input CVE id, keywords, CPE / CPE-stub, purl, or GitHub URL.
 * @param array{
 *   cpe?:bool, resolve_cpe?:bool, sources?:string[]|null, limit?:?int,
 *   timeout?:int, no_poc?:bool, no_enrich?:bool, no_cache?:bool, osv_package?:?string
 * } $options
 * @return array{
 *   query: Query, results: Vulnerability[], total: int,
 *   diagnostics: array<int,array<string,mixed>>, cpe_meta: ?HttpResponse,
 *   cpe_meta_kind: ?string, eol: ?array
 * }
 * @throws InvalidArgumentException on invalid input or options.
 */
function gumvulns_search(string $input, array $options = []): array
{
    $input = trim($input);
    if ($input === '') {
        throw new InvalidArgumentException('Empty query.');
    }
    $opt = $options + [
        'cpe' => false, 'resolve_cpe' => true, 'sources' => null, 'limit' => null,
        'timeout' => 30, 'no_poc' => false, 'no_enrich' => false, 'no_cache' => false,
        'osv_package' => null, 'circl_url' => null,
    ];

    $prevCache = Http::$cacheEnabled;
    $prevCircl = Config::$circlBase;
    if ($opt['no_cache']) {
        Http::$cacheEnabled = false;
    }
    if ($opt['circl_url'] !== null && $opt['circl_url'] !== '') {
        Config::$circlBase = (string) $opt['circl_url'];
    }
    try {
        $query = gumvulns_parse_query($input, (bool) $opt['cpe'], (bool) $opt['resolve_cpe']);

        if ($opt['osv_package'] !== null && $opt['osv_package'] !== '') {
            $fallbackVersion = ($query->cpe && $query->cpe->hasVersion()) ? $query->cpe->version : null;
            $osv = gumvulns_parse_osv_spec((string) $opt['osv_package'], $fallbackVersion);
            if ($osv === null) {
                throw new InvalidArgumentException('Invalid osv_package (use ecosystem:name[@version] or a purl).');
            }
            $query->osv = $osv;
        }

        $sources = gumvulns_sources();
        if ($opt['sources'] !== null) {
            $only = (array) $opt['sources'];
            $sources = array_values(array_filter($sources, static fn (VulnSource $s) => in_array($s->id(), $only, true)));
            if (!$sources) {
                throw new InvalidArgumentException('No matching sources for the given filter.');
            }
        }

        $limit = $opt['limit'] !== null ? max(1, (int) $opt['limit']) : null;
        $agg   = new Aggregator($sources, max(5, (int) $opt['timeout']));
        $res   = $agg->search($query);
        $results = $res['results'];

        // CPE mode: collapse to one row per CVE and apply a sane default cap.
        if ($query->type === QueryType::Cpe) {
            $results = Merger::mergeByCve($results);
            $limit   = $limit ?? 50;

            // Phase 2: cross-reference discovered CVEs against remaining CVE-keyed sources.
            if (!$opt['no_enrich'] && $results) {
                $top    = array_slice(Merger::orderForCpe($results), 0, $limit);
                $cveIds = array_map(static fn (Vulnerability $v) => $v->cveId, $top);
                $enr    = $agg->enrich($cveIds, $res['ran']);
                if ($enr['results']) {
                    $results = Merger::mergeByCve(array_merge($results, $enr['results']));
                }
                $res['diagnostics'] = array_merge($res['diagnostics'], $enr['diagnostics']);
            }
        }

        // Flag whether the queried version is inside any affected range.
        $targetVersion = ($query->cpe && $query->cpe->hasVersion()) ? $query->cpe->version : null;
        if ($targetVersion !== null) {
            foreach ($results as $v) {
                [$verdict, $matched] = VersionFlag::evaluate($v, $targetVersion, $query->cpe->product);
                $v->versionChecked   = true;
                $v->vulnerable       = $verdict;
                $v->matchedRange     = $matched;
            }
        }

        // Exploit/PoC enrichment from the bulk indexes (cached) + per-CVE PoC-in-GitHub.
        if (!$opt['no_poc']) {
            $indexes  = gumvulns_exploit_indexes();
            $expCount = 0;
            foreach ($results as $v) {
                $cve = strtoupper($v->cveId);
                $ex  = [];
                foreach ($indexes as $srcName => $map) {
                    foreach (array_unique($map[$cve] ?? []) as $url) {
                        $ex[] = ['source' => $srcName, 'url' => $url];
                    }
                }
                if ($query->type === QueryType::CveId) {
                    foreach (gumvulns_poc_in_github($cve) as $url) {
                        $ex[] = ['source' => 'PoC-in-GitHub', 'url' => $url];
                    }
                }
                if ($ex) {
                    $v->exploits = $ex;
                    $expCount++;
                }
            }
            $res['diagnostics'][] = ['source' => 'Exploit indexes', 'status' => 200, 'count' => $expCount, 'error' => ''];
        }

        // Lifecycle (EOL) status for the queried product/version.
        $eol = null;
        if ($query->cpe && $query->cpe->hasVersion()) {
            $eol = gumvulns_eol($query->cpe->product, $query->cpe->version);
        }

        if ($query->type === QueryType::Cpe) {
            $results = Merger::orderForCpe($results);
        }

        $total = count($results);
        if ($limit !== null && $total > $limit) {
            $results = array_slice($results, 0, $limit);
        }

        return [
            'query'         => $query,
            'results'       => $results,
            'total'         => $total,
            'diagnostics'   => $res['diagnostics'],
            'cpe_meta'      => $res['cpe_meta'] ?? null,
            'cpe_meta_kind' => $res['cpe_meta_kind'] ?? null,
            'eol'           => $eol,
        ];
    } finally {
        Http::$cacheEnabled = $prevCache;
        Config::$circlBase  = $prevCircl;
    }
}

/**
 * Convert a gumvulns_search() result into a plain, JSON-ready array.
 *
 * @param array $res result from gumvulns_search()
 * @return array<string,mixed>
 */
function gumvulns_payload(array $res): array
{
    /** @var Query $query */
    $query   = $res['query'];
    $results = $res['results'];

    $payload = [
        'query'       => $query->raw,
        'type'        => $query->type->value,
        'total'       => $res['total'],
        'shown'       => count($results),
        'results'     => array_map(static fn (Vulnerability $v) => $v->toArray(), $results),
        'diagnostics' => $res['diagnostics'],
    ];
    if ($query->cpe) {
        $payload['cpe'] = $query->cpe->components();
        $payload['cpe_resolved_from_purl'] = $query->cpeResolved;
    }
    if ($query->github) {
        $payload['github'] = $query->github->describe();
    }
    if ($query->purl) {
        $payload['purl'] = $query->purl;
    }
    if ($query->osv) {
        $payload['osv'] = $query->osv;
    }
    if ($res['eol'] !== null) {
        $payload['eol'] = $res['eol'];
    }
    return $payload;
}

function gumvulns_main(array $argv): int
{
    $args      = array_slice($argv, 1);
    $asJson    = false;
    $forceCpe  = false;
    $noPoc     = false;
    $noEnrich  = false;
    $only      = null;
    $limit     = null;
    $osvSpec   = null;
    $noCpeResolve = false;
    $noCache   = false;
    $circlUrl  = null;
    $timeout   = 30;
    $queryBits = [];

    foreach ($args as $arg) {
        if ($arg === '--json') {
            $asJson = true;
        } elseif ($arg === '--cpe') {
            $forceCpe = true;
        } elseif ($arg === '--no-poc') {
            $noPoc = true;
        } elseif ($arg === '--no-enrich') {
            $noEnrich = true;
        } elseif (str_starts_with($arg, '--osv-package=')) {
            $osvSpec = substr($arg, 14);
        } elseif ($arg === '--no-cpe-resolve') {
            $noCpeResolve = true;
        } elseif ($arg === '--no-cache') {
            $noCache = true;
        } elseif (str_starts_with($arg, '--circl-url=')) {
            $circlUrl = substr($arg, 12);
        } elseif (str_starts_with($arg, '--timeout=')) {
            $timeout = max(5, (int) substr($arg, 10));
        } elseif ($arg === '--list-sources') {
            foreach (gumvulns_sources() as $s) {
                printf("  %-12s %-22s (%s)\n", $s->id(), $s->name(), $s->isEnabled() ? 'enabled' : 'needs API key');
            }
            return 0;
        } elseif (str_starts_with($arg, '--source=')) {
            $only = array_filter(array_map('trim', explode(',', substr($arg, 9))));
        } elseif (str_starts_with($arg, '--limit=')) {
            $limit = max(1, (int) substr($arg, 8));
        } elseif ($arg === '-h' || $arg === '--help') {
            gumvulns_usage();
            return 0;
        } else {
            $queryBits[] = $arg;
        }
    }

    $raw = trim(implode(' ', $queryBits));
    if ($raw === '') {
        gumvulns_usage();
        return 1;
    }

    try {
        $res = gumvulns_search($raw, [
            'cpe'         => $forceCpe,
            'resolve_cpe' => !$noCpeResolve,
            'sources'     => $only,
            'limit'       => $limit,
            'timeout'     => $timeout,
            'no_poc'      => $noPoc,
            'no_enrich'   => $noEnrich,
            'no_cache'    => $noCache,
            'osv_package' => $osvSpec,
            'circl_url'   => $circlUrl,
        ]);
    } catch (InvalidArgumentException $e) {
        fwrite(STDERR, $e->getMessage() . "\n");
        return 1;
    }

    /** @var Query $query */
    $query   = $res['query'];
    $results = $res['results'];

    if ($asJson) {
        echo json_encode(gumvulns_payload($res), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        return 0;
    }

    echo "\nQuery: {$query->raw}  [{$query->type->value}]\n";
    if ($query->github) {
        echo Renderer::githubInfo($query->github);
    }
    if ($query->osv) {
        echo Renderer::osvInfo($query->osv);
    }
    if ($query->cpe) {
        if ($query->cpeResolved) {
            echo "  (CPE vendor/product resolved from purl via the NVD CPE dictionary)\n";
        }
        echo Renderer::cpeInfo($query->cpe, $res['cpe_meta'], $res['cpe_meta_kind'] ?? null, $res['eol']);
        echo "\nVulnerabilities (" . count($results) . " of {$res['total']})\n";
    }
    echo Renderer::table($results);
    echo Renderer::diagnostics($res['diagnostics']);
    return 0;
}

function gumvulns_usage(): void
{
    echo <<<TXT

GumVulns — multi-source vulnerability search

Usage:
  php gumvulns.php <CVE-ID | keywords | CPE | purl | GitHub-URL> [options]

Options:
  --cpe               Treat input as a CPE / stub (vendor:product[:version]).
  --json              Output JSON instead of a table.
  --source=a,b,c      Only query the named sources (see --list-sources).
  --limit=N           Cap results (default 50 in CPE mode).
  --no-poc            Skip exploit/PoC enrichment (Nuclei, Exploit-DB,
                      Metasploit, PoC-in-GitHub).
  --no-enrich         Skip phase-2 cross-referencing of discovered CVEs against
                      the remaining CVE-keyed sources (CPE/purl/GitHub modes).
  --osv-package=SPEC  Add an OSV package query, merged into the results.
                      SPEC = ecosystem:name[@version] or a purl. Version
                      defaults to the CPE version when one is given.
  --no-cpe-resolve    For purl queries, don't resolve the package name to a
                      vendor:product via the NVD CPE dictionary.
  --timeout=SECONDS   Per-request network timeout (default 30; NVD gets longer).
  --no-cache          Don't use the on-disk response cache (NVD is cached 6h).
  --circl-url=URL     Base URL of a self-hosted vulnerability-lookup API
                      (the software behind cve.circl.lu); also via env
                      VULNERABILITY_LOOKUP_URL or CIRCL_API_URL.
  --list-sources      List sources and whether they are enabled.
  -h, --help          Show this help.

When a version is given (CPE or GitHub tag), each result is flagged VULNERABLE /
not affected / unknown by comparing it against the affected version ranges.

Examples:
  php gumvulns.php CVE-2021-44228
  php gumvulns.php "apache log4j"
  php gumvulns.php "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
  php gumvulns.php --cpe apache:log4j
  php gumvulns.php --cpe a:openbsd:openssh:9.1 --limit=20
  php gumvulns.php --cpe apache:log4j:2.14.1 \
      --osv-package=Maven:org.apache.logging.log4j:log4j-core

Package URL (purl) — queried natively via OSV.dev:
  php gumvulns.php "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
  php gumvulns.php "pkg:npm/lodash@4.17.20"
  php gumvulns.php "pkg:pypi/django@3.2"

GitHub links (commit -> OSV.dev; owner/repo/tag -> CPE sources):
  php gumvulns.php https://github.com/jquery/jquery/archive/refs/tags/3.3.1.zip
  php gumvulns.php https://github.com/owner/repo/archive/<commit-sha>.tar.gz
  php gumvulns.php https://github.com/owner/repo/commit/<sha>

Optional API keys (environment variables):
  NVD_API_KEY, GITHUB_TOKEN, VULNERS_API_KEY, VULNCHECK_API_KEY, SEARCH_VULNS_API_KEY
  CVEDETAILS_COOKIE   browser cookie to get CVE Details past Cloudflare

TXT;
}

// Run as a CLI program, but stay silent when included (e.g. for testing).
if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    exit(gumvulns_main($argv));
}
