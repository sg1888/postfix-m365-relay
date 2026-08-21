#!/usr/bin/env bats
# Unit tests for the pure shell helpers in
# build/postfix-m365-relay/lib/text.sh. These run on the host (no image, no
# network): the functions are pure input->output/exit with no globals or I/O.

setup() {
  LIB="$BATS_TEST_DIRNAME/../../build/postfix-m365-relay/lib/text.sh"
  # shellcheck source=/dev/null
  source "$LIB"
}

# --- valid_email -----------------------------------------------------------

@test "valid_email accepts a plain address" {
  run valid_email "user@example.com"
  [ "$status" -eq 0 ]
}

@test "valid_email accepts subdomains and plus tags" {
  run valid_email "user.name+tag@sub.example.co.uk"
  [ "$status" -eq 0 ]
}

@test "valid_email rejects an empty string" {
  run valid_email ""
  [ "$status" -ne 0 ]
}

@test "valid_email rejects a bare local part with no @" {
  run valid_email "not-an-email"
  [ "$status" -ne 0 ]
}

@test "valid_email rejects a domain with no dot" {
  run valid_email "user@localhost"
  [ "$status" -ne 0 ]
}

@test "valid_email rejects a domain that starts with a dot" {
  run valid_email "user@.com"
  [ "$status" -ne 0 ]
}

@test "valid_email rejects an address containing a space" {
  run valid_email "user name@example.com"
  [ "$status" -ne 0 ]
}

# --- regex_escape ----------------------------------------------------------

@test "regex_escape escapes regexp metacharacters" {
  run regex_escape "a.b*c"
  [ "$status" -eq 0 ]
  [ "$output" = 'a\.b\*c' ]
}

@test "regex_escape escapes brackets and parens" {
  run regex_escape "[x](y)"
  [ "$output" = '\[x\]\(y\)' ]
}

@test "regex_escape leaves a plain word untouched" {
  run regex_escape "plainword"
  [ "$output" = "plainword" ]
}

# --- display_name_escape ---------------------------------------------------

@test "display_name_escape doubles a dollar sign (Postfix regexp map)" {
  run display_name_escape 'Price $5'
  [ "$output" = 'Price $$5' ]
}

@test "display_name_escape backslash-escapes a double quote" {
  run display_name_escape 'a"b'
  [ "$output" = 'a\"b' ]
}

@test "display_name_escape doubles a literal backslash" {
  run display_name_escape 'a\b'
  [ "$output" = 'a\\b' ]
}

@test "display_name_escape leaves an ordinary name untouched" {
  run display_name_escape 'Jane Doe'
  [ "$output" = 'Jane Doe' ]
}

# --- valid_reason ----------------------------------------------------------

@test "valid_reason accepts a lowercase slug" {
  run valid_reason "cert-expired"
  [ "$status" -eq 0 ]
}

@test "valid_reason accepts digits and a single char" {
  run valid_reason "a"
  [ "$status" -eq 0 ]
  run valid_reason "abc123"
  [ "$status" -eq 0 ]
}

@test "valid_reason rejects an empty string" {
  run valid_reason ""
  [ "$status" -ne 0 ]
}

@test "valid_reason rejects a leading hyphen" {
  run valid_reason "-bad"
  [ "$status" -ne 0 ]
}

@test "valid_reason rejects uppercase" {
  run valid_reason "Cert"
  [ "$status" -ne 0 ]
}

@test "valid_reason rejects whitespace" {
  run valid_reason "has space"
  [ "$status" -ne 0 ]
}

@test "valid_reason rejects an underscore" {
  run valid_reason "a_b"
  [ "$status" -ne 0 ]
}

@test "valid_reason rejects more than 64 characters" {
  run valid_reason "$(printf 'a%.0s' $(seq 1 65))"
  [ "$status" -ne 0 ]
}
