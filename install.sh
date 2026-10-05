#!/usr/bin/env bash
# Canonical Linux installation entry point. No traffic generation or firewall tests.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
trap 'printf "NetShield installation stopped (line %s). See the preceding error; no firewall cleanup was attempted.\n" "$LINENO" >&2' ERR

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    cat <<'HELP'
NetShield Linux installer (Ubuntu 22.04 / 24.04, systemd, root)
  sudo bash install.sh                  Interactive installation / managed rerun
  sudo bash install.sh --verify-only    Read-only deployment checks
  sudo bash install.sh --dry-run        Read-only discovery and proposed configuration

Options:
  --capture-interface NAME   Explicit observed interface
  --management-ip IP         Local literal address for HTTPS (never wildcard)
  --management-client CIDR   Allowed client; repeat for multiple clients
  --sensor-id NAME           Sensor identifier
  --hostname DNS            Optional certificate / trusted-host name
  --python PATH             Existing Python >= 3.11 with venv support
  --allow-deadsnakes         Explicitly permit third-party Jammy Python 3.12 PPA
  --enable-response         Opt in to manual bounded helper (default: observe only)
  --response-network CIDR    Private allowed response scope; repeat
  --cert PATH --key PATH     Supply TLS certificate / private key (first install)
  --skip-operator            Create operator later with the secure local CLI
  --non-interactive          Require network flags and --skip-operator on first install

Reruns preserve configuration, credentials, certificate and database. Changed
managed files or foreign resources are refused. No uninstall / purge is provided.
The runtime is installed from a wheel; no editable installation, default password,
automatic blocking, scan, networking change or wildcard management listener.
HELP
    exit 0
fi

[[ $(uname -s) == Linux ]] || { printf 'Linux is required.\n' >&2; exit 1; }
[[ $EUID -eq 0 ]] || { printf 'Run with sudo/root.\n' >&2; exit 1; }
[[ -x /usr/bin/python3 ]] || { printf 'Ubuntu system Python 3 is required.\n' >&2; exit 1; }
installer_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
/usr/bin/python3 -I "$installer_root/scripts/linux_install.py" "$@"
