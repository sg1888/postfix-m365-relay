#!/usr/bin/env bash
# Safely load a Docker-style env file without evaluating shell expressions.
# This file is intended to be sourced: `. scripts/load-env.sh .env`.

relay_env_file=${1:-.env}
[[ -r "$relay_env_file" ]] || { echo "Cannot read env file: $relay_env_file" >&2; return 1; }

while IFS= read -r relay_env_line || [[ -n "$relay_env_line" ]]; do
  relay_env_line=${relay_env_line%$'\r'}
  [[ -z "$relay_env_line" || "$relay_env_line" =~ ^[[:space:]]*# ]] && continue
  if [[ "$relay_env_line" == *=* ]]; then
    relay_env_key=${relay_env_line%%=*}
    relay_env_value=${relay_env_line#*=}
  elif [[ "$relay_env_line" =~ ^[A-Za-z_][A-Za-z0-9_]*:[[:space:]]* ]]; then
    relay_env_key=${relay_env_line%%:*}
    relay_env_value=${relay_env_line#*:}
    relay_env_value=${relay_env_value#"${relay_env_value%%[![:space:]]*}"}
  else
    echo "Invalid environment entry for an unknown key" >&2
    return 1
  fi
  [[ "$relay_env_key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || {
    echo "Invalid env key: $relay_env_key" >&2
    return 1
  }
  if [[ ${#relay_env_value} -ge 2 ]]; then
    if [[ "$relay_env_value" == \"*\" && "$relay_env_value" == *\" ]]; then
      relay_env_value=${relay_env_value:1:${#relay_env_value}-2}
    elif [[ "$relay_env_value" == \'*\' && "$relay_env_value" == *\' ]]; then
      relay_env_value=${relay_env_value:1:${#relay_env_value}-2}
    fi
  fi
  printf -v "$relay_env_key" '%s' "$relay_env_value"
  export "$relay_env_key"
done < "$relay_env_file"

unset relay_env_file relay_env_line relay_env_key relay_env_value
