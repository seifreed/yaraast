# Static analysis baseline (2026-03-16)

## Ruff
- Command: `ruff check`
- Issues: import ordering and unused-import warnings in
  - `tests/test_cli_metrics_helpers.py` (docstring misplaced `from __future__` block),
  - `yaraast/cli/commands/metrics.py` (unsorted import block plus two unused helpers),
  - `yaraast/lexer/lexer.py` (import order plus unused `LexerError`).
- Fixability: all six reported warnings are fixable with `ruff --fix`, so the transition cluster is the CLI/lexer import layout.

## Mypy
- Command: `mypy --config-file mypy.ini yaraast`
- Issues (11 total):
  - `yaraast/visitor/transformer_impl.py`: `_transform_node` assigns `list[ASTNode | Any]` to `ASTNode`, and `replace` call receives keyword dicts that do not match the expected `Location`/`Comment` types.
  - `yaraast/visitor/base_expressions.py`: `Condition` is missing `.expression`, and `_visit_if` is invoked with a `str | Expression` where `VisitorHelperProtocol` expects `ASTNode | None`.
  - `yaraast/visitor/base.py`: `BaseVisitorHelpersMixin` is missing its generic parameters.
  - `yaraast/shared/ast_analysis.py`: `_get_condition_structure` mixes `dict[str, Any]` into fields typed as `str`/`list`.
- Hotspot guidance: visitor mixins and AST utilities generate the majority of mypy noise; focus on those clusters in the next wave.

## Coverage
- Baseline coverage data lives in `coverage.xml` and `htmlcov/`; reuse those artifacts when re-running `pytest` and `coverage` later.

## Constraints
- Continue resolving issues without introducing mocks or monkeypatches.

## Watchlist
- **Visitor/AST mixins (transformer_impl.py, base_expressions.py, base.py, shared/ast_analysis.py)** – verified clean on 2026-03-16 after typed kwargs, tightened `_visit_if`, and annotated `_get_condition_structure`. Re-run `mypy --config-file mypy.ini yaraast` after future visitor or AST analyzer touch-ups.
- **Metrics helpers (tests/test_cli_metrics_helpers.py, yaraast/cli/commands/metrics.py)** – last `ruff check` on 2026-03-16; keep the import blocks sorted and drop unused helpers when refactoring to prevent new I001/F401 noise.
- **Lexer entry points (yaraast/lexer/lexer.py)** – last `ruff check` on 2026-03-16 once unused imports were removed. Validate `ruff check` again if lexer initialization or helper imports change.

## Next inspection plan
- Target: Visitor/AST mixins (transformer_impl.py, base_expressions.py, base.py, shared/ast_analysis.py)
- Validation steps:
  1. Run `mypy --config-file mypy.ini yaraast` after touching any visitor mixin or AST analyzer file to confirm no regression.
  2. If new issues arise, fix them while keeping to the "no mocks/monkeypatches" constraint and document the changes and results in this file.
  3. After a successful rerun, update the Watchlist entry with the new verification date and any specific notes about the cluster’s state.

## Latest status
- `ruff check` – clean after reordering the metrics imports and removing unused helpers.
- `mypy --config-file mypy.ini yaraast` – clean after annotating the transformer helper, tightening visitor mixins, and typing `_get_condition_structure`. Keep an eye on visitor/AST analyzer clusters for future regressions.
