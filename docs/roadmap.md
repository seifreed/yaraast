# Roadmap

The roadmap keeps YaraAST focused on a local Python library and CLI for
developing, validating, testing, transforming, and maintaining YARA rule
repositories.

## 2.2: Detection CI

Validate a complete repository with one deterministic command:

- unified diagnostic schema with stable IDs, source ranges, fingerprints, and
  structured fixes;
- `yaraast.toml` project configuration and policy-as-code;
- `yaraast check` with text, JSON, NDJSON, SARIF, and JUnit reporters;
- baseline and auditable suppressions;
- compatibility profiles for YARA, YARA-X, and Livehunt;
- documented local fixtures and CI examples.

## 2.3: Rule Testing

Test detection behavior against local positive and negative fixtures:

- test manifest schema v1;
- expected matches and engine matrices;
- compile, scan, and memory budgets;
- per-rule detection coverage;
- `yaraast test` with JSON and JUnit output;
- changed-file selection and local result caching.

## 2.4: Safe Refactoring

Transform rulesets without changing unrelated source or behavior:

- lossless source ranges and trivia;
- rename rules, strings, and references;
- remove unused strings and imports;
- normalize metadata and sort imports;
- diff preview, transactional writes, reparse, recompile, and retest;
- YARA to YARA-X migration checks.

## 2.5: Extensibility and Scale

Support internal policies and large repositories without adding a service layer:

- plugin SDK v1 for diagnostics, policies, targets, reporters, transforms, and
  fixture providers;
- high-level `Project` API;
- incremental workspace analysis and persistent dependency graphs;
- robust caching and configurable parallelism;
- measured performance profiles for 1,000, 10,000, and 100,000 rules.

## 3.0

Freeze the public AST, diagnostic, project configuration, test manifest,
plugin, refactoring, and serialization contracts only after the 2.x APIs have
seen real repository use.

## Out of scope

YaraAST will remain a library and local CLI. REST APIs, databases, web
dashboards, RBAC, SSO, multi-tenancy, remote agents, deployment control
planes, and SaaS are outside this roadmap.
