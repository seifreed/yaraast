# OSS-Fuzz

YARAAST keeps an OSS-Fuzz submission candidate under [`oss-fuzz/`](https://github.com/seifreed/yaraast/tree/main/oss-fuzz).
It follows the Python integration contract: the Dockerfile uses
`base-builder-python`, and `build.sh` installs the package and emits standalone
wrappers for the parser and accepted-input round-trip Atheris targets.

The candidate is not an OSS-Fuzz acceptance claim. Submitting it requires an
OSS-Fuzz pull request, project contacts, and review under the
[Python integration guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang/).

## Local checks

```bash
bash -n oss-fuzz/build.sh
python scripts/validate_oss_fuzz.py
```

The existing nightly workflow remains the fast project-owned signal. OSS-Fuzz
would add continuously managed libFuzzer infrastructure and issue triage after
acceptance.
