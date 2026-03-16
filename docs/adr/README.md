# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records documenting key architectural decisions made in the yaraast project.

## What are ADRs?

Architecture Decision Records capture important architectural decisions along with their context and consequences. Each ADR describes:

- **Title**: The architectural decision being addressed
- **Status**: Current state (Proposed, Accepted, Deprecated, Superseded)
- **Context**: The issue motivating this decision and alternative approaches considered
- **Decision**: The specific architectural decision made and how it was implemented
- **Consequences**: The positive and negative impacts of the decision, along with mitigation strategies

## Index of ADRs

### Core Architecture Patterns

- [ADR-001: Visitor Pattern for AST Traversal](ADR-001-visitor-pattern.md)
  - Why the Visitor pattern is used for AST traversal
  - Benefits: Extensibility, type safety, separation of concerns
  - Trade-offs: Learning curve, indirection

- [ADR-007: BaseVisitor with Default Implementations](ADR-007-base-visitor.md)
  - Base visitor class with automatic child node traversal
  - Eliminates boilerplate in concrete visitor implementations
  - 1,020 lines of default implementations for 40+ node types

### Dependency Management

- [ADR-002: ILexer Interface for Dependency Injection](ADR-002-dependency-injection.md)
  - Protocol-based dependency injection for lexer implementations
  - Enables testing with mock lexers
  - Zero runtime overhead using Python structural subtyping

### Language Support

- [ADR-003: Multi-Dialect Support (YARA, YARA-L, YARA-X)](ADR-003-multi-dialect-support.md)
  - Automatic dialect detection with context-aware pattern matching
  - Unified parser interface for all dialects
  - Tested with 273,683 YARA rules and 891 YARA-L rules

### Type Safety

- [ADR-004: Gradual Typing Strategy with MyPy](ADR-004-gradual-typing.md)
  - Pragmatic MyPy configuration for parser domain
  - 80%+ type coverage target
  - Balances type safety with development velocity

### Performance Optimization

- [ADR-005: Streaming Parser vs Traditional Parser](ADR-005-streaming-parser.md)
  - Empirical comparison: Traditional parser 70% faster
  - Streaming parser uses 31% less memory
  - Default: Traditional parser for files <100 MB

### Developer Experience

- [ADR-006: Builder Pattern with Fluent API](ADR-006-builder-pattern.md)
  - Fluent API for programmatic rule construction
  - 70% less code compared to direct AST construction
  - Type-safe method chaining with IDE autocomplete

- [ADR-008: Semantic Type System](ADR-008-type-system.md)
  - Static type checking for YARA expressions
  - Complete module type definitions (pe, elf, math, hash, vt)
  - Rich error messages with location and suggestions

- [ADR-009: Error Handling Strategy](ADR-009-error-handling.md)
  - Hybrid approach: Exceptions + error collection
  - Lenient parsing mode for mixed YARA/ClamAV files
  - Actionable error messages with fix suggestions

### Quality Assurance

- [ADR-010: Testing Strategy Without Mocks](ADR-010-testing-strategy.md)
  - Minimalist testing with real data, no mocking
  - 337 tests with 90%+ coverage
  - Roundtrip testing and production data validation

## ADR Lifecycle

ADRs follow this lifecycle:

1. **Proposed**: Initial proposal under discussion
2. **Accepted**: Decision approved and implemented
3. **Deprecated**: Decision no longer recommended (with explanation)
4. **Superseded**: Replaced by newer decision (with reference to replacement)

## Creating New ADRs

When creating a new ADR:

1. Use the template structure (Title, Status, Context, Decision, Consequences)
2. Include concrete code examples demonstrating the decision
3. Document alternatives considered and why they were rejected
4. Describe both positive and negative consequences
5. Provide mitigation strategies for negative consequences
6. Reference relevant source files and tests
7. Include the GPLv3 license notice

## References

- [Architecture Decision Records (ADR) Pattern](https://adr.github.io/)
- [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)

## License

Copyright (C) 2026 Marc Rivero López

This documentation is licensed under the GNU General Public License v3.0.
You may copy, distribute and modify the software as long as you track changes/dates in source files.
Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions.

See [LICENSE](../../LICENSE) for full details.
