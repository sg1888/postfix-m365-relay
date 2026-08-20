#!/usr/bin/env bash
# Fast, network-free checks run before the comparatively expensive image build.
# Keep the file lists explicit enough that new runtime scripts are visible in a
# review. File enumeration uses POSIX find because hosted CI does not guarantee
# ripgrep; policy/documentation assertions therefore use POSIX grep as well.
set -euo pipefail

repo_files() {
  find "$@" -type f -print
}

# Keep this runner compatible with Bash 3.2, which has arrays but not `mapfile`.
# Paths in this repository contain no whitespace, so word-splitting the file
# result is safe across supported development and CI toolchains.
shell_files=($(repo_files build/postfix-m365-relay scripts tests | awk '/\.sh$|\/relay-users$|\/relay-admin$/' | sort -u))
bash -n "${shell_files[@]}"
python3 -m py_compile scripts/refresh-smtp-token.py scripts/rotate-smtp-relay-cert.py \
  $(repo_files tests | awk '/\.py$/')

# Hosted CI runners include PowerShell; local systems may not. Parse both
# tenant-configuration scripts whenever pwsh is available. This catches syntax
# damage without connecting to Exchange or changing external state.
if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoProfile -Command '
    $failed = $false
    foreach ($path in @("powershell/setup-exchange.ps1", "powershell/undo-exchange.ps1")) {
      $tokens = $null; $errors = $null
      [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path $path), [ref]$tokens, [ref]$errors) | Out-Null
      if ($errors.Count) {
        $errors | ForEach-Object { Write-Error "${path}: $_" }
        $failed = $true
      }
    }
    if ($failed) { exit 1 }
  '
fi

# The mailbox authorization model is security-sensitive documentation-as-code.
# These assertions guard the live-proven claims-less App RBAC design against an
# accidental return to the older licensed-user + FullAccess instructions.
grep -Eq "RecipientTypeDetails = SharedMailbox \(recommended\)" powershell/setup-exchange.ps1
grep -Eq "New-ManagementScope" powershell/setup-exchange.ps1
grep -Eq "Application SMTP.SendAsApp" powershell/setup-exchange.ps1
grep -Eq "Test-ServicePrincipalAuthorization" powershell/setup-exchange.ps1
if grep -Eq "Add-MailboxPermission" powershell/setup-exchange.ps1; then
  echo 'setup script must not grant FullAccess in claims-less App RBAC' >&2
  exit 1
fi
grep -Eq "dedicated shared mailbox" README.md docs/MICROSOFT-SETUP.md
grep -Eq "smtp-app-rbac-onboarding" docs/MICROSOFT-SETUP.md
grep -Eq "application-rbac" docs/MICROSOFT-SETUP.md

# The existing toolchains include Ruby's YAML parser. Parsing catches
# indentation damage without downloading another Python dependency.
ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path) }' \
  .github/workflows/publish-image.yml .github/workflows/test.yml \
  compose.yaml examples/compose.yaml examples/compose-with-apps.yaml \
  examples/compose.device-relay.yaml examples/compose.letsencrypt.yaml \
  examples/authelia.compose.yaml examples/alertmanager.yml \
  examples/cross-project/relay.compose.yaml \
  examples/cross-project/application.compose.yaml examples/service-block.yaml

# A source archive and the pre-`git init` public staging tree have no index, so
# `git diff --check` alone is both noisy there and blind to untracked files in a
# newly initialized repository. Audit every shipped text source directly, then
# retain Git's additional patch-context check whenever an index exists.
ruby -e '
  bad = []
  ARGV.each do |path|
    next unless File.file?(path)
    File.foreach(path).with_index(1) do |line, number|
      bad << "#{path}:#{number}: trailing whitespace" if line.match?(/[ \t]+(?:\r?\n)?\z/)
      bad << "#{path}:#{number}: conflict marker" if line.match?(/\A(?:<<<<<<<|=======|>>>>>>>)/)
    end
  rescue ArgumentError
    # Ignore a non-text file if a maintainer later adds an image fixture.
  end
  abort bad.join("\n") unless bad.empty?
' $(repo_files . | sort)
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --check
fi
echo "ok static syntax, YAML parsing, Python compilation, and whitespace audit"
