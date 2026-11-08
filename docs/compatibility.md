# Dialect Compatibility

This matrix records the reference implementations exercised by the required
CI conformance job. It is a tested baseline, not a claim that every construct
from a dialect is implemented.

| Dialect | Reference exercised by CI | Parse | Generate | Format | Lossless | Validate | LSP |
| --- | --- | --- | --- | --- | --- | --- | --- |
| YARA | yara-python/libyara 4.5.4 | Stable | Stable | Stable | Partial | libyara | Stable |
| YARA-X | yara-x 1.23.0 | Beta | Beta | Beta | No | YARA-X | Beta |
| YARA-L | Google documentation snapshot 2026-08 | Experimental | Experimental | Experimental | No | Public corpus | Experimental |

The latest upstream classic YARA release is
[4.6.0](https://github.com/VirusTotal/yara/releases/tag/v4.6.0). Upstream
`yara-python` is at
[4.5.5](https://github.com/VirusTotal/yara-python/releases/tag/v4.5.5), while
the latest package published on PyPI and exercised by CI remains
[4.5.4](https://pypi.org/project/yara-python/). The differential gate therefore
tests libyara 4.5.4 and does not claim a 4.6.0 run. YARA-X CI uses the official
[1.23.0](https://github.com/VirusTotal/yara-x/releases/tag/v1.23.0) Python
binding. YARA-L follows the dated public
[YARA-L 2.0 examples](https://cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples)
rather than a locally installable reference compiler.

The YARA-L conformance corpus covers `re.capture_all` in rule `outcome`
assignments and passes its `ARRAY_STRINGS` result to `arrays.length`. Local
validation checks its two-argument signature and rejects obvious numeric or
boolean literals; Google remains authoritative for field types, capture-group
limits, return types, and regular-expression semantics. This support covers
rule-file syntax only, not the separate multi-stage query syntax used by Search
or Dashboards. See the [YARA-L function reference](https://docs.cloud.google.com/chronicle/docs/yara-l/functions).

YARA-X accepts positive integer literals through `2^64 - 1` and the
`int64`/`uint64` little- and big-endian integer readers. The classic YARA parser
remains limited to signed 64-bit literals. Protobuf serialization stores larger
values in the additive `unsigned_value` field while retaining the existing
signed `value` field for older serialized ASTs.

The required
[differential conformance job](https://github.com/seifreed/yaraast/actions/workflows/ci.yml)
installs the exact versions above and rejects acceptance or match drift for the
vendored corpus. Automatic dialect detection is best effort; callers that need
a deterministic grammar should pass `dialect=` explicitly.

## Compatibility Policy

- The documented root API, accepted Python versions, serialized schema versions,
  and stable classic-YARA behavior follow semantic versioning.
- YARA-X beta and YARA-L experimental behavior may change in a minor release;
  such changes are called out in the changelog and migration guide.
- A reference engine upgrade is a compatibility change and must pass its pinned
  conformance job before this matrix is updated.

## Deprecation Policy

Deprecated stable APIs remain available until the next major release unless a
security or correctness defect makes that unsafe. Deprecations are announced in
the changelog with the replacement and planned removal version. The project does
not add silent aliases or compatibility shims: callers must migrate to the new
contract before removal.
