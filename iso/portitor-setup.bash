# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Bash completion of portitor-setup.
_portitor_setup() {
    COMPREPLY=($(compgen -W "--join --show-join -h --help" -- "${COMP_WORDS[COMP_CWORD]}"))
}
complete -F _portitor_setup portitor-setup
