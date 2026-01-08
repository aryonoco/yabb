# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Bash completion for yabb
# Install: source this file or copy to /etc/bash_completion.d/yabb

_yabb() {
    local cur prev opts subcommands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Subcommands
    subcommands="run validate status optimize health help"

    # Complete subcommand at position 1
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${subcommands}" -- ${cur}) )
        return 0
    fi

    # Get the subcommand
    local subcmd="${COMP_WORDS[1]}"

    # Options for each subcommand
    case "${subcmd}" in
        run)
            opts="--configPath -c --debug -d --dryRun -n --forceFull -f --json -j --help -h"
            ;;
        validate)
            opts="--configPath -c --json -j --help -h"
            ;;
        status)
            opts="--configPath -c --json -j --help -h"
            ;;
        optimize)
            opts="--configPath -c --dryRun -n --defrag --balance --scrub --json -j --help -h"
            ;;
        health)
            opts="--configPath -c --repair -r --json -j --help -h"
            ;;
        help)
            COMPREPLY=( $(compgen -W "${subcommands}" -- ${cur}) )
            return 0
            ;;
        *)
            return 0
            ;;
    esac

    # Complete file path after --configPath or -c
    case "${prev}" in
        --configPath|-c)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}

complete -F _yabb yabb
