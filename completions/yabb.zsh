#compdef yabb
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Zsh completion for yabb
# Install: copy to a directory in $fpath (e.g., ~/.zsh/completions/)

_yabb() {
    local -a commands
    commands=(
        'run:Run BTRFS backup with optional incremental detection'
        'validate:Validate configuration without running backup'
        'status:Show current snapshot status and disk usage'
        'optimize:Manually run storage optimization operations'
        'health:Check snapshot chain health and optionally repair issues'
        'help:Show help for a command'
    )

    _arguments -C \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[2] in
                run)
                    _arguments \
                        '(-c --configPath)'{-c,--configPath}'[Path to TOML configuration file]:file:_files' \
                        '(-d --debug)'{-d,--debug}'[Enable debug logging]' \
                        '(-n --dryRun)'{-n,--dryRun}'[Show what would be done without changes]' \
                        '(-f --forceFull)'{-f,--forceFull}'[Force full snapshot instead of incremental]' \
                        '(-j --json)'{-j,--json}'[Output in JSON format]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                validate)
                    _arguments \
                        '(-c --configPath)'{-c,--configPath}'[Path to TOML configuration file]:file:_files' \
                        '(-j --json)'{-j,--json}'[Output in JSON format]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                status)
                    _arguments \
                        '(-c --configPath)'{-c,--configPath}'[Path to TOML configuration file]:file:_files' \
                        '(-j --json)'{-j,--json}'[Output in JSON format]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                optimize)
                    _arguments \
                        '(-c --configPath)'{-c,--configPath}'[Path to TOML configuration file]:file:_files' \
                        '(-n --dryRun)'{-n,--dryRun}'[Show what would be done without changes]' \
                        '--defrag[Run defragmentation (default: true)]' \
                        '--balance[Run balance operation (default: true)]' \
                        '--scrub[Run scrub operation (default: false)]' \
                        '(-j --json)'{-j,--json}'[Output in JSON format]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                health)
                    _arguments \
                        '(-c --configPath)'{-c,--configPath}'[Path to TOML configuration file]:file:_files' \
                        '(-r --repair)'{-r,--repair}'[Attempt to repair chain issues]' \
                        '(-j --json)'{-j,--json}'[Output in JSON format]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                help)
                    _describe 'command' commands
                    ;;
            esac
            ;;
    esac
}

_yabb "$@"
