# Dialect Compatibility

This matrix records the reference implementations exercised by the required
CI conformance job. It is a tested baseline, not a claim that every construct
from a dialect is implemented.

| Dialect | Reference exercised by CI | Parse | Generate | Format | Lossless | Validate | LSP |
| --- | --- | --- | --- | --- | --- | --- | --- |
| YARA | yara-python/libyara 4.5.4 | Stable | Stable | Stable | Partial | libyara | Stable |
| YARA-X | yara-x 1.19.0 | Beta | Beta | Beta | No | YARA-X | Beta |
| YARA-L | Google documentation snapshot 2026-08 | Experimental | Experimental | Experimental | No | Public corpus | Experimental |

The current upstream classic YARA release is
[4.5.8](https://github.com/VirusTotal/yara/releases/tag/v4.5.8). Its syntax is
the parser target, but the latest published `yara-python` binding is 4.5.4, so
the differential CI gate cannot honestly claim a 4.5.8 libyara run yet.
YARA-X is fixed to the official
[1.19.0](https://github.com/VirusTotal/yara-x/releases/tag/v1.19.0) Python
binding. YARA-L follows the dated public
[YARA-L 2.0 examples](https://cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples)
rather than a locally installable reference compiler.

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
