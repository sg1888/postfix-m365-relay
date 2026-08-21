#!/usr/bin/env bash
# Pure text validation/escaping helpers shared by render-config.sh and
# cert-action.sh, and unit-tested in isolation by tests/unit/text.bats.
#
# Contract: every function here is pure -- input to stdout/exit status, with no
# globals, no environment reads, no file or network I/O, and no `exit`. Keep it
# that way so the helpers stay safe to source anywhere and testable on the host
# with no container. Anything that touches state belongs in the calling script.

# True if $1 looks like a full email address: no spaces or '@' inside the local
# or domain part, and at least one dot in the domain.
valid_email() { [[ $1 =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; }

# Escape $1 so it is matched literally by a Postfix regexp-map / PCRE pattern.
regex_escape() { sed 's/[][(){}.^$*+?|\\]/\\&/g' <<<"$1"; }

# Escape a display name for the two parsers that run after Bash: Postfix's
# regexp-map replacement parser, then the RFC 5322 quoted-string parser used by
# recipients. Order matters. Doubling '$' is a correctness requirement, not
# cosmetic: Postfix treats $N as a (here missing) capture group and would skip
# the rule -- '$$' emits one literal dollar.
display_name_escape() {
  local value=$1
  value=${value//\\/\\\\}  # RFC quoted-string: preserve a literal backslash.
  value=${value//\"/\\\"}  # RFC quoted-string: preserve a literal quote.
  value=${value//\$/\$\$}    # Postfix regexp maps: $$ emits one literal dollar.
  printf '%s' "$value"
}

# True if $1 is a controlled lowercase slug (1-64 chars, [a-z0-9] then
# [a-z0-9-]). Keeps the KEY=VALUE cert-action state file trivially parseable and
# stops any caller detail from smuggling a newline or shell metacharacter in.
valid_reason() { [[ $1 =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; }
