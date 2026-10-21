#!/usr/bin/env bash
# Decide whether the scheduled package refresh releases today.
#
# Purpose:   Keep automatic releases few. A refresh releases only for a serious
#            vulnerability it can actually fix; every other pending update waits
#            and ships with that release (a rebuild installs all of them).
#              urgent   a CRITICAL or HIGH CVE with a fixed version (Trivy) in a
#                       package that has a pending update in the same image, so
#                       rebuilding fixes it
#              backstop anything pending, and the newest release (of any kind)
#                       is at least 60 days old. The relay alerts when
#                       its image packages and CA bundle are 90 days old
#                       (MAIL_CA_BUNDLE_MAX_AGE_DAYS); this releases before that,
#                       and carries CA bundle changes, which are never CVEs
#              force    a manual run with force=true
#            A CVE whose package has no pending update is reported but does not
#            release: a rebuild would not fix it (for example a Python package
#            or a distro fix not yet published), and releasing would repeat
#            every day.
# Called by: .github/workflows/publish-image.yml (job "plan").
# Created:   2026-10-21
# Usage:     .github/scripts/refresh-decision.sh UPDATES RELEASE_EPOCH NOW_EPOCH [FORCE]
#              UPDATES     file of sections, one per published image:
#                            ## <tag>
#                            <package> <installed> -> <available> [key] [security]
#                            cve <id> <severity> <package> <installed> -> <fixed>
#                          (package lines from pending-updates.sh, cve lines from Trivy)
#              RELEASE_EPOCH  when the newest release was created (Unix time)
#              NOW_EPOCH      now (Unix time)
#              FORCE          true to release regardless
#            Prints "publish=true|false" and "reason=<one line>", then one
#            "note=<line>" per CVE that no rebuild can fix.
set -euo pipefail

updates=${1:?usage: refresh-decision.sh UPDATES RELEASE_EPOCH NOW_EPOCH [FORCE]}
release_epoch=${2:?newest release time (Unix) required}
now_epoch=${3:?current time (Unix) required}
force=${4:-false}
backstop_days=60
age_days=$(( (now_epoch - release_epoch) / 86400 ))

# One pass: per section, remember which packages have a pending update, then
# sort each CVE into fixable (urgent) or not.
analysis=$(awk '
  /^## / { section = $2; next }
  /^cve / { cves[++n] = section " " $0; next }
  NF >= 4 && $3 == "->" { pending[section " " $1] = 1; count++ }
  END {
    print "count " count + 0
    for (i = 1; i <= n; i++) {
      split(cves[i], f, " ")   # section cve id severity package installed -> fixed
      kind = ((f[1] " " f[5]) in pending) ? "urgent" : "unfixable"
      print kind " " f[3] " " f[4] " " f[5] " " f[6] " -> " f[8] " in " f[1]
    }
  }' "$updates")

count=$(awk '$1 == "count" { print $2 }' <<< "$analysis")
urgent=$(grep '^urgent ' <<< "$analysis" | cut -d' ' -f2- || true)
unfixable=$(grep '^unfixable ' <<< "$analysis" | cut -d' ' -f2- || true)

if [ -n "$urgent" ]; then
  echo "publish=true"
  echo "reason=urgent: $(head -n1 <<< "$urgent")$( [ "$(wc -l <<< "$urgent")" -gt 1 ] && echo " and $(( $(wc -l <<< "$urgent") - 1 )) more")"
elif [ "$force" = true ]; then
  echo "publish=true"
  echo "reason=forced by a manual run ($count pending updates)"
elif [ "$count" -gt 0 ] && [ "$age_days" -ge "$backstop_days" ]; then
  echo "publish=true"
  echo "reason=backstop: $count pending updates and the newest release is $age_days days old"
elif [ "$count" -gt 0 ]; then
  echo "publish=false"
  echo "reason=$count pending updates held: no fixable CRITICAL or HIGH CVE, newest release $age_days days old (backstop at $backstop_days)"
else
  echo "publish=false"
  echo "reason=nothing pending"
fi
if [ -n "$unfixable" ]; then
  while IFS= read -r line; do echo "note=not fixable by a rebuild: $line"; done <<< "$unfixable"
fi
