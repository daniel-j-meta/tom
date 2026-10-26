#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
tom_source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tom_install_dir="${TOM_ROOT:-/opt/tom}"
tom_reconfigure=()
tom_restore=""
tom_identity=""
tom_skip_live=0
while (( $# )); do
  case "$1" in
    --reconfigure) tom_reconfigure=(--reconfigure); shift ;;
    --restore) tom_restore="${2:?Archive path required}"; shift 2 ;;
    --identity) tom_identity="${2:?age identity file required}"; shift 2 ;;
    --skip-live-checks) tom_skip_live=1; shift ;;
    --help) echo 'Usage: sudo ./setup.sh [--reconfigure] [--restore BACKUP.age --identity KEYFILE] [--skip-live-checks]'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
if [[ "$EUID" != 0 ]]; then
  echo 'Run this setup script with sudo.' >&2; exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 && "$VERSION_ID" != 26.04 ]]; then
  echo 'This package targets Ubuntu Server 24.04 or 26.04. No changes made.' >&2; exit 1
fi
if [[ ! "$tom_install_dir" =~ ^/[a-zA-Z0-9_/-]+$ || "$tom_install_dir" == / ]]; then
  echo 'TOM_ROOT must be a safe absolute installation path without spaces.' >&2; exit 1
fi
tom_available_mb="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
if (( tom_available_mb < 7000 )); then
  echo 'At least 7 GB total RAM is required for the default 8 GB server configuration.' >&2; exit 1
fi
echo 'Installing Ubuntu prerequisites…'
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg python3-venv python3-pip age rsync apparmor-utils iptables iproute2
if ! command -v docker >/dev/null 2>&1; then
  install -d -m 0755 /etc/apt/keyrings
  tom_key_temp="$(mktemp)"
  trap 'rm -f -- "${tom_key_temp:-}"' EXIT
  curl --proto '=https' --tlsv1.2 -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$tom_key_temp"
  tom_fingerprint="$(gpg --batch --show-keys --with-colons "$tom_key_temp" | awk -F: '$1=="fpr" {print $10; exit}')"
  tom_public_key_count="$(gpg --batch --show-keys --with-colons "$tom_key_temp" | awk -F: '$1=="pub" {n++} END {print n+0}')"
  if [[ "$tom_public_key_count" != 1 || "$tom_fingerprint" != 9DC858229FC7DD38854AE2D88D81803C0EBFCD88 ]]; then
    echo 'Docker signing-key fingerprint did not match; refusing installation.' >&2; exit 1
  fi
  install -m 0644 "$tom_key_temp" /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/tom-docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
docker compose version >/dev/null
systemctl enable --now docker
install -d -m 0700 "$tom_install_dir" "$tom_install_dir/data" "$tom_install_dir/secrets" /run/tom
tom_free_mb="$(df -Pm "$tom_install_dir" | awk 'NR==2 {print $4}')"
if (( tom_free_mb < 20480 )); then
  echo 'At least 20 GB free disk is required for the initial images and runtime data.' >&2; exit 1
fi
if [[ "$tom_source_dir" != "$tom_install_dir" ]]; then
  rsync -a --exclude .git --exclude .venv --exclude data --exclude secrets --exclude backups --exclude dist \
    --exclude .env --exclude config.json --exclude test-results "$tom_source_dir/" "$tom_install_dir/"
fi
python3 -m venv "$tom_install_dir/venv"
"$tom_install_dir/venv/bin/pip" install --disable-pip-version-check "$tom_install_dir"
"$tom_install_dir/venv/bin/python" "$tom_install_dir/scripts/preflight.py" "$tom_install_dir"
cat > /usr/local/bin/tom <<EOF
#!/usr/bin/env bash
exec "$tom_install_dir/venv/bin/python" -m tom.cli --root "$tom_install_dir" "\$@"
EOF
chmod 0755 /usr/local/bin/tom
echo 'Installing scoped container permissions…'
install -m 0644 "$tom_install_dir/security/apparmor" /etc/apparmor.d/tom-guest
apparmor_parser -r /etc/apparmor.d/tom-guest
# Isolated Docker networks have no internet route, but their bridge can reach the host.
# This narrow INPUT rule blocks those guest source addresses from host services.
cat > "$tom_install_dir/install-host-rule.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
iptables -C INPUT -s 172.30.0.0/16 -m comment --comment tom-guests -j DROP 2>/dev/null || \
  iptables -I INPUT 1 -s 172.30.0.0/16 -m comment --comment tom-guests -j DROP
install -d -m 0700 /run/tom
touch /run/tom/network-ready
EOF
chmod 0700 "$tom_install_dir/install-host-rule.sh"
"$tom_install_dir/install-host-rule.sh"
cat > /etc/systemd/system/tom-network-guard.service <<EOF
[Unit]
Description=Block Tom guest networks from host services
After=network-pre.target docker.service
Before=tom.service
[Service]
Type=oneshot
ExecStart=$tom_install_dir/install-host-rule.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
echo 'Building the small management image and the shared OpenClaw/browser image…'
docker build -t tom-openclaw:2026.10.7 -f "$tom_install_dir/containers/Dockerfile" "$tom_install_dir"
TOM_ROOT="$tom_install_dir" docker compose -f "$tom_install_dir/compose.yaml" --project-directory "$tom_install_dir" build app
echo 'Checking Chromium sandbox support…'
docker run --rm --cap-drop ALL --security-opt no-new-privileges:true \
  --security-opt apparmor=tom-guest --security-opt "seccomp=$tom_install_dir/security/seccomp.json" \
  --entrypoint node tom-openclaw:2026.10.7 -e \
  'const{chromium}=require("/app/node_modules/playwright-core");(async()=>{const b=await chromium.launch({channel:"chromium",headless:true,chromiumSandbox:true});await b.close();console.log("Chromium sandbox verified")})().catch(()=>process.exit(1))'
if [[ -n "$tom_restore" ]]; then
  [[ -n "$tom_identity" ]] || { echo '--identity is required with --restore' >&2; exit 2; }
  tom restore --identity "$tom_identity" --archive "$tom_restore"
fi
tom configure "${tom_reconfigure[@]}"
cat > /etc/systemd/system/tom.service <<EOF
[Unit]
Description=Tom home assistant server
Requires=docker.service tom-network-guard.service
After=docker.service tom-network-guard.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$tom_install_dir
Environment=TOM_ROOT=$tom_install_dir
ExecStart=/usr/bin/docker compose -f $tom_install_dir/compose.yaml up -d --wait --wait-timeout 120
ExecStop=/usr/local/bin/tom down
TimeoutStartSec=180
TimeoutStopSec=120
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable tom-network-guard.service tom.service
systemctl restart tom.service
tom doctor
if (( tom_skip_live )); then
  echo 'Installed; live verification was explicitly skipped. Run sudo tom verify before using the server.'
else
  echo 'Running live deployment verification; the model check uses a small amount of API credit…'
  tom verify
  echo 'Setup and live checks complete. Open your configured HTTPS hostname and sign in through Cloudflare Access.'
fi
