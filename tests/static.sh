#!/usr/bin/env bash
# Fast, network-free checks run before the comparatively expensive image build.
# Keep the file lists explicit enough that new runtime scripts are visible in a
# review. GitHub's hosted runner does not guarantee ripgrep, so use POSIX find
# here; developers can still use rg for interactive discovery.
set -euo pipefail

repo_files() {
  find "$@" -type f -print
}

# Keep this runner compatible with Bash 3.2, which has arrays but not `mapfile`.
# Paths in this repository contain no whitespace, so word-splitting the rg
# result is safe across supported development and CI toolchains.
shell_files=($(repo_files build/postfix-m365-relay scripts tests | awk '/\.sh$|\/relay-users$|\/relay-admin$/' | sort -u))
bash -n "${shell_files[@]}"
python3 -m py_compile $(repo_files scripts tests | awk '/\.py$/')

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
