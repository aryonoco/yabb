# SPDX-License-Identifier: 0BSD
# Copyright (c) 2023-2026 Aryan Ameri
#
# Fish completion for yabb
# Install: copy to ~/.config/fish/completions/yabb.fish

# Disable file completion by default
complete -c yabb -f

# Subcommands
complete -c yabb -n "__fish_use_subcommand" -a "run" -d "Run BTRFS backup with optional incremental detection"
complete -c yabb -n "__fish_use_subcommand" -a "validate" -d "Validate configuration without running backup"
complete -c yabb -n "__fish_use_subcommand" -a "status" -d "Show current snapshot status and disk usage"
complete -c yabb -n "__fish_use_subcommand" -a "optimize" -d "Manually run storage optimization operations"
complete -c yabb -n "__fish_use_subcommand" -a "health" -d "Check snapshot chain health and optionally repair issues"
complete -c yabb -n "__fish_use_subcommand" -a "help" -d "Show help for a command"

# Options for run
complete -c yabb -n "__fish_seen_subcommand_from run" -l configPath -s c -d "Path to TOML configuration file" -r -F
complete -c yabb -n "__fish_seen_subcommand_from run" -l debug -s d -d "Enable debug logging"
complete -c yabb -n "__fish_seen_subcommand_from run" -l dryRun -s n -d "Show what would be done without changes"
complete -c yabb -n "__fish_seen_subcommand_from run" -l forceFull -s f -d "Force full snapshot instead of incremental"
complete -c yabb -n "__fish_seen_subcommand_from run" -l json -s j -d "Output in JSON format"
complete -c yabb -n "__fish_seen_subcommand_from run" -l help -s h -d "Show help"

# Options for validate
complete -c yabb -n "__fish_seen_subcommand_from validate" -l configPath -s c -d "Path to TOML configuration file" -r -F
complete -c yabb -n "__fish_seen_subcommand_from validate" -l json -s j -d "Output in JSON format"
complete -c yabb -n "__fish_seen_subcommand_from validate" -l help -s h -d "Show help"

# Options for status
complete -c yabb -n "__fish_seen_subcommand_from status" -l configPath -s c -d "Path to TOML configuration file" -r -F
complete -c yabb -n "__fish_seen_subcommand_from status" -l json -s j -d "Output in JSON format"
complete -c yabb -n "__fish_seen_subcommand_from status" -l help -s h -d "Show help"

# Options for optimize
complete -c yabb -n "__fish_seen_subcommand_from optimize" -l configPath -s c -d "Path to TOML configuration file" -r -F
complete -c yabb -n "__fish_seen_subcommand_from optimize" -l dryRun -s n -d "Show what would be done without changes"
complete -c yabb -n "__fish_seen_subcommand_from optimize" -l defrag -d "Run defragmentation (default: true)"
complete -c yabb -n "__fish_seen_subcommand_from optimize" -l balance -d "Run balance operation (default: true)"
complete -c yabb -n "__fish_seen_subcommand_from optimize" -l scrub -d "Run scrub operation (default: false)"
complete -c yabb -n "__fish_seen_subcommand_from optimize" -l json -s j -d "Output in JSON format"
complete -c yabb -n "__fish_seen_subcommand_from optimize" -l help -s h -d "Show help"

# Options for health
complete -c yabb -n "__fish_seen_subcommand_from health" -l configPath -s c -d "Path to TOML configuration file" -r -F
complete -c yabb -n "__fish_seen_subcommand_from health" -l repair -s r -d "Attempt to repair chain issues"
complete -c yabb -n "__fish_seen_subcommand_from health" -l json -s j -d "Output in JSON format"
complete -c yabb -n "__fish_seen_subcommand_from health" -l help -s h -d "Show help"

# Help subcommand completion
complete -c yabb -n "__fish_seen_subcommand_from help" -a "run validate status optimize health" -d "Command"
