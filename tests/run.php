<?php

/**
 * GumVulns test suite — dependency-free, fully offline.
 *
 * Includes gumvulns.php (its entry point is guarded) and exercises the pure
 * logic plus every source's parse() with canned API responses, so CI never
 * touches the network.
 *
 * Run: php tests/run.php
 */

declare(strict_types=1);

require __DIR__ . '/../gumvulns.php';

/* ---- tiny assertion harness ---- */

$GLOBALS['__pass'] = 0;
$GLOBALS['__fail'] = 0;

function eq($actual, $expected, string $label): void
{
    if ($actual === $expected) {
        $GLOBALS['__pass']++;
        return;
    }
    $GLOBALS['__fail']++;
    fwrite(STDERR, sprintf("FAIL: %s\n   expected: %s\n   actual:   %s\n",
        $label, var_export($expected, true), var_export($actual, true)));
}

function ok(bool $cond, string $label): void
{
    eq($cond, true, $label);
}

function section(string $name): void
{
    echo "• {$name}\n";
}

function resp(string $body, int $status = 200): HttpResponse
{
    return new HttpResponse($status, $body);
}

/* -------------------------------------------------------------------------- */
section('Cpe parsing');

$c = Cpe::parse('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*');
eq($c->vendor, 'apache', 'cpe2.3 vendor');
eq($c->product, 'log4j', 'cpe2.3 product');
eq($c->version, '2.14.1', 'cpe2.3 version');
eq($c->part, 'a', 'cpe2.3 part');

$c = Cpe::parse('cpe:/a:apache:log4j:2.14.1');
eq($c->product, 'log4j', 'cpe2.2 uri product');
eq($c->version, '2.14.1', 'cpe2.2 uri version');

$c = Cpe::parse('apache:log4j:2.14.1');
eq([$c->vendor, $c->product, $c->version], ['apache', 'log4j', '2.14.1'], 'stub vendor:product:version');

$c = Cpe::parse('a:apache:log4j');
eq([$c->part, $c->vendor, $c->product], ['a', 'apache', 'log4j'], 'stub part:vendor:product');

$c = Cpe::parse('log4j');
eq($c->product, 'log4j', 'stub single = product');

eq(Cpe::parse(''), null, 'empty cpe -> null');

$c = Cpe::fromParts('', 'lodash', '4.17.20');
eq($c->toCpe23(), 'cpe:2.3:*:*:lodash:4.17.20:*:*:*:*:*:*:*', 'fromParts toCpe23 keeps wildcard part');
eq($c->toQueryCpe23(), 'cpe:2.3:a:*:lodash:4.17.20:*:*:*:*:*:*:*', 'toQueryCpe23 forces part a');

/* -------------------------------------------------------------------------- */
section('CVSS calculator');

eq(Cvss::baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10.0, 'cvss v3.1 = 10.0');
eq(Cvss::baseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8, 'cvss v3.0 = 9.8');
eq(Cvss::baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1, 'cvss v3.1 = 6.1');
eq(Cvss::baseScore('AV:N/AC:L/Au:N/C:P/I:P/A:P'), 7.5, 'cvss v2 = 7.5');
eq(Cvss::baseScore('AV:N/AC:L/Au:N/C:C/I:C/A:C'), 10.0, 'cvss v2 full = 10.0');
eq(Cvss::baseScore('(AV:N/AC:M/Au:N/C:N/I:P/A:N)'), 4.3, 'cvss v2 paren = 4.3');
eq(Cvss::baseScore('CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C'), 7.8, 'cvss v2 prefixed = 7.8');
eq(Cvss::baseScore('not a vector'), null, 'invalid vector -> null');

/* -------------------------------------------------------------------------- */
section('VersionRange');

$r = VersionRange::bounded('log4j', '2.0-beta9', true, '2.15.0', false);
eq($r->contains('2.14.1'), true, 'range contains 2.14.1');
eq($r->contains('2.15.0'), false, 'range excludes end 2.15.0');
eq($r->contains('1.9'), false, 'range excludes below start');
eq($r->format(), 'log4j: >= 2.0-beta9, < 2.15.0', 'range format');

$e = VersionRange::exact('p', '6.3.2.1');
eq($e->contains('6.3.2.1'), true, 'exact match');
eq($e->contains('6.3.2.2'), false, 'exact mismatch');
eq($e->format(), 'p: = 6.3.2.1', 'exact format');

eq(VersionRange::rawText('p', 'whatever')->contains('1.0'), null, 'raw range not evaluable');
ok(VersionRange::bounded('org.apache.logging.log4j:log4j-core', null, true, '1', false)->productMatches('log4j'), 'productMatches coordinate');
ok(!VersionRange::bounded('6bk1602_firmware', null, true, '1', false)->productMatches('log4j'), 'productMatches excludes firmware');

/* -------------------------------------------------------------------------- */
section('VersionFlag');

$v = new Vulnerability('CVE-X', '', 9.0, 'CRITICAL', '', 'src', [
    VersionRange::bounded('log4j', '2.0.1', true, '2.12.2', false),
    VersionRange::bounded('log4j', '2.13.0', true, '2.16.0', false),
    VersionRange::bounded('siemens_firmware', null, true, '2.7.0', false),
]);
eq(VersionFlag::evaluate($v, '2.14.1', 'log4j'), [true, 'log4j: >= 2.13.0, < 2.16.0'], 'flag vulnerable');
eq(VersionFlag::evaluate($v, '2.12.5', 'log4j')[0], false, 'flag not-affected (gap)');
eq(VersionFlag::evaluate($v, '2.14.1', 'openssl')[0], null, 'flag unknown (product mismatch)');

/* -------------------------------------------------------------------------- */
section('GitHubRef');

$g = GitHubRef::parse('https://github.com/jquery/jquery/archive/refs/tags/3.3.1.zip');
eq([$g->owner, $g->repo, $g->refType, $g->version], ['jquery', 'jquery', 'tag', '3.3.1'], 'github tag archive');

$g = GitHubRef::parse('https://github.com/owner/repo/commit/6879efc2c1596d11a6a6ad296f80063b558d5e0f');
eq($g->refType, 'commit', 'github commit type');
eq($g->commit, '6879efc2c1596d11a6a6ad296f80063b558d5e0f', 'github commit sha');

$g = GitHubRef::parse('https://codeload.github.com/owner/repo/tar.gz/abc1234def');
eq($g->refType, 'commit', 'codeload sha -> commit');

$g = GitHubRef::parse('https://github.com/owner/repo/releases/download/v2.1.0/asset.zip');
eq([$g->refType, $g->version], ['tag', '2.1.0'], 'releases/download tag');

$g = GitHubRef::parse('https://github.com/owner/repo');
eq($g->refType, 'none', 'bare repo');
$cpe = $g->toCpe();
eq([$cpe->vendor, $cpe->product], ['owner', 'repo'], 'github toCpe owner/repo');

eq(GitHubRef::parse('https://example.com/foo/bar'), null, 'non-github url -> null');

/* -------------------------------------------------------------------------- */
section('purl parsing');

$p = gumvulns_parse_purl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
eq($p['raw'], 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'purl raw unparsed string');
eq($p['type'], 'maven', 'purl type');
eq($p['namespace'], 'org.apache.logging.log4j', 'purl namespace');
eq($p['name'], 'log4j-core', 'purl name');
eq($p['version'], '2.14.1', 'purl version');

$p = gumvulns_parse_purl('pkg:npm/lodash@4.17.20');
eq([$p['namespace'], $p['name'], $p['version']], [null, 'lodash', '4.17.20'], 'purl npm no namespace');

$p = gumvulns_parse_purl('pkg:pypi/django@3.2?arch=src#sub/path');
eq([$p['name'], $p['version']], ['django', '3.2'], 'purl strips qualifiers/subpath');

eq(gumvulns_parse_purl('not-a-purl'), null, 'invalid purl -> null');

/* -------------------------------------------------------------------------- */
section('OSV spec parsing');

$s = gumvulns_parse_osv_spec('Maven:org.apache.logging.log4j:log4j-core', '2.14.1');
eq([$s['ecosystem'], $s['name'], $s['version']], ['Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1'], 'osv spec eco:name + fallback version');

$s = gumvulns_parse_osv_spec('npm:lodash@4.17.20', null);
eq([$s['ecosystem'], $s['name'], $s['version']], ['npm', 'lodash', '4.17.20'], 'osv spec @version overrides');

$s = gumvulns_parse_osv_spec('pkg:npm/lodash@4.17.20', null);
eq($s['purl'], 'pkg:npm/lodash@4.17.20', 'osv spec purl');

eq(gumvulns_parse_osv_spec('notvalid', null), null, 'osv spec invalid -> null');

/* -------------------------------------------------------------------------- */
section('Query routing (offline)');

$q = gumvulns_parse_query('CVE-2021-44228', false);
eq($q->type, QueryType::CveId, 'route cve');

$q = gumvulns_parse_query('apache log4j', false);
eq($q->type, QueryType::Keyword, 'route keyword');

$q = gumvulns_parse_query('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*', false);
eq($q->type, QueryType::Cpe, 'route cpe');

$q = gumvulns_parse_query('pkg:npm/lodash@4.17.20', false, false); // no network resolve
eq($q->type, QueryType::Cpe, 'route purl -> cpe type');
eq($q->purl['name'], 'lodash', 'route purl parsed');
eq($q->osv['purl'], 'pkg:npm/lodash@4.17.20', 'route purl sets osv');
eq($q->cpe->product, 'lodash', 'route purl fallback product');

/* -------------------------------------------------------------------------- */
section('Source parsers (canned responses)');

// NVD
$nvd = new NvdSource();
$nvdJson = json_encode(['vulnerabilities' => [['cve' => [
    'id' => 'CVE-2021-44228',
    'descriptions' => [['lang' => 'en', 'value' => 'Log4Shell RCE']],
    'metrics' => ['cvssMetricV31' => [['cvssData' => [
        'baseScore' => 10.0, 'baseSeverity' => 'CRITICAL',
        'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    ]]]],
    'configurations' => [['nodes' => [['cpeMatch' => [[
        'vulnerable' => true,
        'criteria' => 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
        'versionStartIncluding' => '2.0', 'versionEndExcluding' => '2.15.0',
    ]]]]]],
]]]]);
$out = $nvd->parse(resp($nvdJson), new Query(QueryType::CveId, 'CVE-2021-44228'));
eq(count($out), 1, 'nvd one result');
eq($out[0]->score, 10.0, 'nvd score');
eq($out[0]->severity, 'CRITICAL', 'nvd severity');
eq($out[0]->versions[0]->format(), 'log4j: >= 2.0, < 2.15.0', 'nvd version range');

// OSV (commit/package query shape with vulns list)
$osv = new OsvSource();
$osvJson = json_encode(['vulns' => [[
    'id' => 'GHSA-jfh8-c2jp-5v3q',
    'aliases' => ['CVE-2021-44228'],
    'summary' => 'Remote code injection in Log4j',
    'severity' => [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H']],
    'affected' => [['package' => ['name' => 'org.apache.logging.log4j:log4j-core'],
        'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '2.0.0'], ['fixed' => '2.15.0']]]]]],
]]]);
$out = $osv->parse(resp($osvJson), new Query(QueryType::Cpe, 'x'));
eq($out[0]->cveId, 'CVE-2021-44228', 'osv prefers CVE alias');
eq($out[0]->score, 10.0, 'osv score from vector');
eq($out[0]->versions[0]->format(), 'org.apache.logging.log4j:log4j-core: >= 2.0.0, < 2.15.0', 'osv ecosystem range');

// GitHub Advisory
$gh = new GitHubSource();
$ghJson = json_encode([[
    'cve_id' => 'CVE-2021-44228', 'summary' => 'RCE', 'severity' => 'critical',
    'cvss' => ['score' => 10.0, 'vector_string' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'],
    'vulnerabilities' => [['package' => ['name' => 'org.apache.logging.log4j:log4j-core'],
        'vulnerable_version_range' => '>= 2.0.0, < 2.15.0']],
]]);
$out = $gh->parse(resp($ghJson), new Query(QueryType::CveId, 'CVE-2021-44228'));
eq($out[0]->score, 10.0, 'github score');
eq($out[0]->versions[0]->format(), 'org.apache.logging.log4j:log4j-core: >= 2.0.0, < 2.15.0', 'github version range');

// Shodan single (KEV flag)
$shodan = new ShodanSource();
$shJson = json_encode(['cve_id' => 'CVE-2021-44228', 'summary' => 'Log4Shell',
    'cvss_v3' => 10.0, 'cvss_v3_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'kev' => true]);
$out = $shodan->parse(resp($shJson), new Query(QueryType::CveId, 'CVE-2021-44228'));
eq($out[0]->score, 10.0, 'shodan score');
ok($out[0]->kev, 'shodan sets KEV flag');

// EUVD (alias filter in CVE mode + raw product range)
$euvd = new EuvdSource();
$euvdJson = json_encode(['items' => [
    ['id' => 'EUVD-2021-1', 'description' => 'Log4Shell', 'baseScore' => 10.0,
     'baseScoreVector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
     'aliases' => "CVE-2021-44228\nGHSA-jfh8",
     'enisaIdProduct' => [['product' => ['name' => 'Apache Log4j2'], 'product_version' => '2.0-beta9 <2.15.0']]],
    ['id' => 'EUVD-9999-9', 'description' => 'unrelated', 'baseScore' => 5.0, 'aliases' => 'CVE-9999-0000'],
]]);
$out = $euvd->parse(resp($euvdJson), new Query(QueryType::CveId, 'CVE-2021-44228'));
eq(count($out), 1, 'euvd alias filter keeps only matching CVE');
eq($out[0]->cveId, 'CVE-2021-44228', 'euvd cve from alias');
eq($out[0]->versions[0]->format(), 'Apache Log4j2: 2.0-beta9 <2.15.0', 'euvd raw product range');

// CISA KEV
$cisa = new CisaKevSource();
$cisaJson = json_encode(['vulnerabilities' => [[
    'cveID' => 'CVE-2021-44228', 'vulnerabilityName' => 'Log4Shell',
    'shortDescription' => 'RCE', 'requiredAction' => 'Patch']]]);
$out = $cisa->parse(resp($cisaJson), new Query(QueryType::CveId, 'CVE-2021-44228'));
eq($out[0]->severity, 'KNOWN EXPLOITED', 'cisa severity');

// EPSS (probability lives in its own field, not score/severity)
$epss = new EpssSource();
$out = $epss->parse(resp(json_encode(['data' => [['cve' => 'CVE-2021-44228', 'epss' => 0.5, 'percentile' => 0.9]]])),
    new Query(QueryType::CveId, 'CVE-2021-44228'));
eq($out[0]->score, null, 'epss does not set a CVSS score');
eq($out[0]->epss, 0.5, 'epss probability field');
eq($out[0]->epssPercentile, 0.9, 'epss percentile field');

// EPSS batch (multiple rows in one response)
$out = $epss->parse(resp(json_encode(['data' => [
    ['cve' => 'CVE-1', 'epss' => 0.1, 'percentile' => 0.2],
    ['cve' => 'CVE-2', 'epss' => 0.3, 'percentile' => 0.4],
]])), new Query(QueryType::CveId, ''));
eq(count($out), 2, 'epss parses multiple rows');
eq($out[1]->cveId, 'CVE-2', 'epss row cve id');

// CIRCL vendor/product search ({ results: { feed: [[id, record], ...] } })
$circl = new CirclSource();
$cq = new Query(QueryType::Cpe, 'x', Cpe::parse('apache:log4j:2.14.1'));
$creq = $circl->buildRequest($cq);
ok($creq !== null && str_contains(rawurldecode($creq->url), '/api/vulnerability/cpesearch/cpe:2.3:a:apache:log4j'),
    'circl builds cpesearch url');
ok(str_contains($creq->url, 'source=fkie_nvd'), 'circl uses fkie_nvd feed (has CVSS)');
// cpesearch returns NVD-shaped records under the feed key.
$nvdRec = ['id' => 'CVE-2021-44228',
    'descriptions' => [['lang' => 'en', 'value' => 'Log4Shell']],
    'metrics' => ['cvssMetricV31' => [['cvssData' => ['baseScore' => 10.0, 'baseSeverity' => 'CRITICAL',
        'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H']]]],
    'configurations' => [['nodes' => [['cpeMatch' => [[
        'vulnerable' => true, 'criteria' => 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
        'versionStartIncluding' => '2.0', 'versionEndExcluding' => '2.15.0']]]]]]];
$out = $circl->parse(resp(json_encode(['fkie_nvd' => [$nvdRec]])), $cq);
eq($out[0]->cveId, 'CVE-2021-44228', 'circl cpesearch cve');
eq($out[0]->score, 10.0, 'circl cpesearch score (vector present)');
eq($out[0]->vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'circl cpesearch vector');
eq($out[0]->versions[0]->format(), 'log4j: >= 2.0, < 2.15.0', 'circl cpesearch version range');
eq($circl->buildRequest(new Query(QueryType::Cpe, 'x', Cpe::parse('log4j'))), null, 'circl skips CPE search without vendor');

// Red Hat product search (list of summary objects)
$rh = new RedHatSource();
$rhJson = json_encode([
    ['CVE' => 'CVE-2021-44228', 'severity' => 'critical', 'bugzilla_description' => 'log4j RCE',
     'cvss3_score' => '10.0', 'cvss3_scoring_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'],
]);
$out = $rh->parse(resp($rhJson), new Query(QueryType::Cpe, 'x', Cpe::parse('apache:log4j')));
eq($out[0]->cveId, 'CVE-2021-44228', 'redhat product result cve');
eq($out[0]->score, 10.0, 'redhat product result score');

// Ubuntu package search ({cves:[...]})
$ub = new UbuntuSource();
$ubJson = json_encode(['cves' => [['id' => 'CVE-2021-44228', 'description' => 'd', 'cvss3' => 10.0, 'priority' => 'critical']]]);
$out = $ub->parse(resp($ubJson), new Query(QueryType::Cpe, 'x', Cpe::parse('apache:log4j')));
eq($out[0]->cveId, 'CVE-2021-44228', 'ubuntu package result cve');

// GitHub affects/ecosystem params from a purl
$ghs = new GitHubSource();
$qp = gumvulns_parse_query('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', false, false);
$req = $ghs->buildRequest($qp);
ok($req !== null && str_contains($req->url, 'ecosystem=maven'), 'github maps purl type -> ecosystem');
ok(str_contains(rawurldecode($req->url), 'org.apache.logging.log4j:log4j-core'), 'github affects = maven coordinate');

// CISA batch (parseBatch over feed for a set)
$kev = new CisaKevSource();
$kevJson = json_encode(['vulnerabilities' => [
    ['cveID' => 'CVE-2021-44228', 'vulnerabilityName' => 'Log4Shell', 'shortDescription' => 'RCE'],
    ['cveID' => 'CVE-0000-0000', 'vulnerabilityName' => 'x', 'shortDescription' => 'y'],
]]);
$out = $kev->parseBatch(resp($kevJson), ['CVE-2021-44228', 'CVE-9999-9999']);
eq(count($out), 1, 'cisa parseBatch filters to wanted set');
ok($out[0]->kev, 'cisa sets kev flag');

// CVE Details HTML scrape + Cloudflare detection
$cd = new CveDetailsSource();
$html = '<meta name="description" content="Log4Shell remote code execution">'
    . '<span>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</span>';
$out = $cd->parse(resp($html), new Query(QueryType::CveId, 'CVE-2021-44228'));
eq($out[0]->score, 10.0, 'cvedetails score from scraped vector');
ok(str_contains($out[0]->description, 'remote code execution'), 'cvedetails meta description');
eq($cd->parse(resp('<title>Just a moment...</title>'), new Query(QueryType::CveId, 'CVE-X')), [], 'cvedetails cloudflare -> empty');

/* -------------------------------------------------------------------------- */
section('Merger');

$a = new Vulnerability('CVE-1', 'short', 9.8, 'CRITICAL', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'NVD (NIST)',
    [VersionRange::bounded('log4j', '2.0', true, '2.15.0', false)]);
$b = new Vulnerability('CVE-1', 'a much longer description for the same cve', 9.8, 'CRITICAL', '', 'OSV.dev',
    [VersionRange::bounded('log4j', '2.13.0', true, '2.16.0', false)]);
$merged = Merger::mergeByCve([$a, $b]);
eq(count($merged), 1, 'merge collapses same CVE');
eq($merged[0]->source, 'NVD (NIST), OSV.dev', 'merge lists both sources');
eq(count($merged[0]->versions), 2, 'merge unions ranges');
ok(str_contains($merged[0]->description, 'longer'), 'merge keeps richest description');

// merge carries EPSS/KEV signals without polluting CVSS score/severity
$cvss = new Vulnerability('CVE-9', '', 9.8, 'CRITICAL', '', 'NVD (NIST)');
$ep = new Vulnerability('CVE-9', '', null, '', '', 'FIRST EPSS'); $ep->epss = 0.97;
$kv = new Vulnerability('CVE-9', '', null, 'KNOWN EXPLOITED', '', 'CISA KEV'); $kv->kev = true;
$m2 = Merger::mergeByCve([$cvss, $ep, $kv]);
eq($m2[0]->score, 9.8, 'merge keeps real CVSS score (not EPSS)');
eq($m2[0]->severity, 'CRITICAL', 'merge keeps real severity (not EPSS/KEV)');
eq($m2[0]->epss, 0.97, 'merge carries EPSS probability');
ok($m2[0]->kev, 'merge carries KEV flag');

// orderForCpe: exploit breaks ties at same score; vulnerable-first when checked
$x = new Vulnerability('CVE-A', '', 7.5, '', '', 's');
$y = new Vulnerability('CVE-B', '', 7.5, '', '', 's');
$y->exploits = [['source' => 'Nuclei', 'url' => 'u']];
$z = new Vulnerability('CVE-C', '', 9.8, '', '', 's');
$ordered = Merger::orderForCpe([$x, $y, $z]);
eq(array_map(fn ($v) => $v->cveId, $ordered), ['CVE-C', 'CVE-B', 'CVE-A'], 'order: score then exploit tiebreak');

$hi = new Vulnerability('CVE-HI', '', 9.8, '', '', 's');
$hi->versionChecked = true; $hi->vulnerable = false;
$lo = new Vulnerability('CVE-LO', '', 5.0, '', '', 's');
$lo->versionChecked = true; $lo->vulnerable = true;
$ordered = Merger::orderForCpe([$hi, $lo]);
eq($ordered[0]->cveId, 'CVE-LO', 'order: confirmed-vulnerable first');

/* -------------------------------------------------------------------------- */
section('Vulnerability helpers');

eq(Vulnerability::severityFromScore(10.0), 'CRITICAL', 'severity 10 -> critical');
eq(Vulnerability::severityFromScore(5.0), 'MEDIUM', 'severity 5 -> medium');
eq(Vulnerability::severityFromScore(null), 'UNKNOWN', 'severity null -> unknown');

$dups = Vulnerability::dedupeRanges([
    VersionRange::bounded('p', '1.0', true, '2.0', false),
    VersionRange::bounded('p', '1.0', true, '2.0', false),
    VersionRange::rawText('p', ''),
]);
eq(count($dups), 1, 'dedupeRanges drops duplicates and empties');

/* -------------------------------------------------------------------------- */

$pass = $GLOBALS['__pass'];
$fail = $GLOBALS['__fail'];
echo "\n" . str_repeat('─', 50) . "\n";
echo $fail === 0
    ? "✓ all {$pass} assertions passed\n"
    : "✗ {$fail} failed, {$pass} passed\n";
exit($fail === 0 ? 0 : 1);
