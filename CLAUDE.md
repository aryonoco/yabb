# YABB - Yet Another BTRFS Backup

Nim 2.2+ incremental BTRFS backup utility with retention policies, chain recovery, and storage optimization. Follows functional core / imperative shell architecture.

## Commands
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
- Use `func` for pure functions, `proc` for side effects
- Use `let` bindings; `var` only for necessary stateful operations
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
- Run `nimble test` before committing
- Use nimpretty for formatting (VSCode auto-configured)
