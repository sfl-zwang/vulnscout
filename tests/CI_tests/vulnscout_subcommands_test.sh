#!/bin/bash
set -euo pipefail

ROOT_DIR=$(readlink -f "$(dirname "$0")/../..")
SCRIPT="$ROOT_DIR/vulnscout"

# Load only normalize_args so no container engine is needed.
# shellcheck disable=SC1090
source <(sed -n '/^NORMALIZED_ARGS=()/,/^parse_and_run()/p' "$SCRIPT" | sed '$d')

FAILED=0
export VULNSCOUT_NO_DEPRECATION_WARNINGS=1

expect() {
    local expected="$1"
    shift
    normalize_args "$@"
    local actual="${NORMALIZED_ARGS[*]}"
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: '$*' => '$actual' (expected '$expected')" >&2
        FAILED=1
    fi
}

expect_error() {
    local out
    if out=$( (normalize_args "$@") 2>&1 ); then
        echo "FAIL: '$*' should have failed" >&2
        FAILED=1
    elif [ -z "$out" ]; then
        echo "FAIL: '$*' failed without a message" >&2
        FAILED=1
    fi
}

# add / asset
for fmt in spdx cdx grype openvex cve-check yocto-vex; do
    expect "add-$fmt f.json" add "$fmt" f.json
done
expect "--project p --variant v add-spdx a add-cdx b" --project p --variant v add spdx a add cdx b
expect "add-asset logo.png" asset add logo.png

# scan
expect "--perform-scans all" scan
expect "--perform-scans nvd,osv" scan nvd,osv
expect "--perform-scans all serve" scan serve
expect "--perform-scans grype export-spdx" scan grype export spdx

# export / import
expect "export-spdx" export spdx
expect "export-cdx" export cdx
expect "export-openvex" export openvex
expect "export-context" export context
expect "export-custom-openvex-assessments" export assessments-openvex
expect "export-custom-vulnscout-data --amend" export data --amend
expect "import-custom-vulnscout-data f.json --use-current-timestamps" import data f.json --timestamps current
expect "import-custom-openvex-assessments f.json --use-original-timestamps" import assessments-openvex f.json --timestamps original
expect "import-context c.json" import context c.json

# delete / list
expect "delete-scan 3" delete scan 3
expect "delete-outdated" delete outdated
expect "delete-empty-scans" delete empty-scans
expect "delete-orphaned-vulns" delete orphaned-vulns
expect "list-projects" list projects
expect "list-scans --json" list scans --format json
expect "list-scans" list scans --format text

# config / container / misc
expect "config K V" config set K V
expect "config-get K" config get K
expect "config-list" config list
expect "config-clear K" config unset K
expect "config K V" config K V
expect "start" container start
expect "stop" container stop
expect "restart" container restart
expect "update" container update
expect "--refresh-vulnerability-data" refresh
expect "--match-condition cvss >= 9" check "cvss >= 9"

# legacy forms pass through untouched
expect "--add-spdx a --serve" --add-spdx a --serve
expect "export-spdx" export-spdx
expect "--perform-scans nvd --export-cdx" --perform-scans nvd --export-cdx
expect "--project scan --variant add serve" --project scan --variant add serve

# legacy values are not re-read as subcommands
expect "--report scan" --report scan
expect "--add-spdx export" --add-spdx export
expect "--config K V" --config K V

# errors
expect_error add foo
expect_error add spdx
expect_error asset
expect_error export
expect_error export nope
expect_error import data
expect_error import nope f
expect_error delete
expect_error delete scan
expect_error list
expect_error list nope
expect_error config get
expect_error config set K
expect_error config unset
expect_error container
expect_error check
expect_error --timestamps bad
expect_error --format yaml

expect_warning() {
    local pattern="$1"
    shift
    local err
    err=$( (unset VULNSCOUT_NO_DEPRECATION_WARNINGS; normalize_args "$@") 2>&1 >/dev/null )
    if ! grep -q -- "$pattern" <<<"$err"; then
        echo "FAIL: '$*' should warn with '$pattern', got '$err'" >&2
        FAILED=1
    fi
}

expect_silent() {
    local err
    err=$( (unset VULNSCOUT_NO_DEPRECATION_WARNINGS; normalize_args "$@") 2>&1 >/dev/null )
    if [ -n "$err" ]; then
        echo "FAIL: '$*' should not warn, got '$err'" >&2
        FAILED=1
    fi
}

expect_warning "'--add-spdx' is deprecated; use 'vulnscout add spdx <path>'" --add-spdx a
expect_warning "'--perform-nvd-scan' is deprecated; use 'vulnscout scan nvd'" --perform-nvd-scan
expect_warning "'--export-custom-vulnscout-data' is deprecated; use 'vulnscout export data'" --export-custom-vulnscout-data
expect_warning "'--match-condition' is deprecated; use 'vulnscout check" --match-condition "x"
expect_warning "'--json' is deprecated; use 'vulnscout --format json'" --json
expect_warning "'--config' is deprecated" --config K V
expect_warning "'config' is deprecated" config K V
expect_warning "'--start' is deprecated; use 'vulnscout container start'" --start
expect_warning "no effect on 'config-list'" --project p config list
expect_warning "no effect on 'delete-outdated'" --variant v delete outdated
expect_warning "no effect on 'list-scans'" --project p list scans
expect_silent add spdx a export cdx scan nvd
expect_silent --project p --variant v add spdx a refresh
expect_silent --project p export context
expect_silent --project p --serve
err=$( (VULNSCOUT_NO_DEPRECATION_WARNINGS=1 normalize_args --add-spdx a --project p config list) 2>&1 )
[ -z "$err" ] || { echo "FAIL: env var should silence warnings" >&2; FAILED=1; }

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Subcommand rewrite tests passed."
