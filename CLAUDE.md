# YABB - Yet Another BTRFS Backup

Nim 2.2+ incremental BTRFS backup utility with retention policies, chain recovery, and storage optimisation. Follows functional core / imperative shell architecture.

## Development Environment

This project uses a devcontainer for consistent development.

## Commands (via just)
- `just` - Show all available commands
- `just build` - Debug build
- `just build-release` - Optimised release build
- `just build-static` - Production static binary (musl)
- `just test` - Run test suite
- `just fmt` - Format all source files with nph
- `just fmt-check` - Verify formatting (CI-friendly)
- `just lint` - Run lint checks
- `just ci` - Run full CI pipeline (fmt-check + lint + test)
- `just clean` - Remove build artifacts
- `just docs` - Generate HTML documentation
- `just versions` - Show tool versions

### Direct nimble commands (alternative)
- `nimble build` - Debug build
- `nimble release` - Production static binary (musl)
- `nimble test` - Run test suite
- `nimble clean` - Remove build artifacts

## Project Structure
- `src/yabb.nim` - Entry point
- `src/cli.nim` - CLI shell (I/O, orchestration)
- `src/config.nim` - TOML configuration loading
- `src/types.nim` - Domain types, enums, Result/Option aliases
- `src/btrfs/` - BTRFS operations (snapshot, properties, storage)
- `src/chain/` - Snapshot chain management and recovery
- `src/retention/` - Retention policy engine (pure logic in policy.nim)
- `src/utils/` - Utilities (lock, paths, retry, shutdown, functional)
- `tests/` - Test modules (config, types, paths, retention, btrfs, shutdown)

## Functional Programming Conventions
- Follow "Functional Core, Imperative Shell" patterns consistently
- Use `func` for pure functions, `proc` only for side effects, use them minimally and at the edge
- Use `let` bindings; `var` only for necessary stateful operations only at the shell, and only when it absolutely cannot be avoided using another FP technique
- Return `YabbResult[T]` for fallible operations, never raise exceptions
- Use `Opt[T]` for optional values with `.isSome`/`.isNone`
- Use object variants (ADTs) with exhaustive case pattern matching
- Prefer expression-oriented style: if/case/block as expressions
- Chain operations with UFCS: `.filterIt().mapIt().foldl()`
- Create new objects instead of mutating (`.withOverrides()` pattern)

## Type Safety
- Use distinct path types: `SourcePath`, `DestPath`, `SnapshotDirPath`
- Check `checkShutdown()` in long-running operations

## Language
- Comments and docstrings: British English spelling
- Variable names and code identifiers: US English spelling

## Workflow
- Run `just ci` before committing (runs fmt-check + lint + test)
- Use nph for formatting (devcontainer auto-configured, format-on-save enabled)
- Run `just fmt-check` in CI to verify formatting
- Run `just versions` to verify tool versions
