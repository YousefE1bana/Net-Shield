#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "$(id -u)" = 0 ]; then printf '%s\n' 'Use an unprivileged account for observe/replay installation.' >&2; exit 1; fi
repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$repository"
environment="${1:-.venv}"
if [ -e "$environment" ]; then printf '%s\n' 'Choose a new environment; existing environments are preserved.' >&2; exit 1; fi
python3 -m venv "$environment"
"$environment/bin/python" -m pip install .
"$environment/bin/python" -m netshield init
printf '%s\n' "Installed observe-only. Bootstrap: $environment/bin/python -m netshield operator-add yousef"
