#!/bin/bash

# CybS3 Bash Completion Script
# Install by adding 'source /path/to/cybs3-completion.bash' to your ~/.bashrc

_cybs3() {
    local cur prev words cword
    _init_completion || return

    # Available commands
    local commands="login vaults keys ls cp rm sync mkdir help version"

    # Vault subcommands
    local vault_commands="add list select delete"

    # Key subcommands
    local key_commands="create show"

    case $prev in
        cybs3)
            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
            return 0
            ;;
        vaults)
            COMPREPLY=( $(compgen -W "$vault_commands" -- "$cur") )
            return 0
            ;;
        keys)
            COMPREPLY=( $(compgen -W "$key_commands" -- "$cur") )
            return 0
            ;;
        --vault|-v)
            # Complete with available vaults (if we can get them)
            # For now, just provide basic completion
            return 0
            ;;
        --bucket|-b)
            # Complete with available buckets (if we can get them)
            return 0
            ;;
    esac

    # File/directory completion for relevant commands
    case ${words[1]} in
        cp|sync)
            # Complete files and directories
            _filedir
            return 0
            ;;
        ls)
            # Complete directories and S3 paths
            _filedir
            COMPREPLY+=( $(compgen -W "s3://" -- "$cur") )
            return 0
            ;;
    esac

    # Option completion
    case $cur in
        -*)
            local options="--help --verbose --vault --bucket --endpoint --access-key --secret-key --region --ssl"
            COMPREPLY=( $(compgen -W "$options" -- "$cur") )
            return 0
            ;;
        s3://*)
            # S3 path completion (basic)
            return 0
            ;;
    esac
}

complete -F _cybs3 cybs3