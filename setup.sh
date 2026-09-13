#!/usr/bin/env bash
# =============================================================================
#  HUGINN :: setup.sh
#  Odin's Raven — Environment Bootstrap & Toolchain Provisioner
# -----------------------------------------------------------------------------
#  Usage:
#     ./setup.sh                 # collect specs + install everything missing
#     ./setup.sh --specs-only    # only write pc_specs.json, don't touch tools
#     ./setup.sh --install-only  # skip specs collection
#     ./setup.sh --check         # report what's missing, install nothing
#     ./setup.sh --no-public-ip  # skip the outbound public-IP lookup
# =============================================================================
set -uo pipefail

# ------------------------------ flags ---------------------------------------
SPECS_ONLY=0
INSTALL_ONLY=0
CHECK_ONLY=0
FETCH_PUBLIC_IP=1
for arg in "$@"; do
  case "$arg" in
    --specs-only)   SPECS_ONLY=1 ;;
    --install-only) INSTALL_ONLY=1 ;;
    --check)        CHECK_ONLY=1 ;;
    --no-public-ip) FETCH_PUBLIC_IP=0 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^#//' | head -n 20
      exit 0 ;;
  esac
done

# ------------------------------ colors / ui ----------------------------------
if [[ -t 1 ]]; then
  R="\033[0m"; B="\033[1m"; D="\033[2m"
  CY="\033[38;5;51m"; GR="\033[38;5;46m"; YE="\033[38;5;226m"
  RE="\033[38;5;196m"; MA="\033[38;5;201m"; GY="\033[38;5;240m"
else
  R=""; B=""; D=""; CY=""; GR=""; YE=""; RE=""; MA=""; GY=""
fi

log()  { printf "${GY}%s${R} ${CY}[*]${R} %s\n" "$(date +%H:%M:%S)" "$*"; }
ok()   { printf "${GY}%s${R} ${GR}[+]${R} %s\n" "$(date +%H:%M:%S)" "$*"; }
warn() { printf "${GY}%s${R} ${YE}[!]${R} %s\n" "$(date +%H:%M:%S)" "$*"; }
err()  { printf "${GY}%s${R} ${RE}[-]${R} %s\n" "$(date +%H:%M:%S)" "$*"; }
hit()  { printf "${GY}%s${R} ${GR}[✓]${R} %s\n" "$(date +%H:%M:%S)" "$*"; }
section() {
  printf "\n${CY}┌────────────────────────────────────────────────────────────┐${R}\n"
  printf "${CY}│${R} ${B}%s${R}\n" "$*"
  printf "${CY}└────────────────────────────────────────────────────────────┘${R}\n\n"
}
banner() {
  printf "${CY}"
  cat <<'EOF'
╔══════════════════════════════════════════════════════════════╗
║   ██╗  ██╗██╗   ██╗ ██████╗ ██╗███╗   ██╗███╗   ██╗          ║
║   ██║  ██║██║   ██║██╔════╝ ██║████╗  ██║████╗  ██║          ║
║   ███████║██║   ██║██║  ███╗██║██╔██╗ ██║██╔██╗ ██║          ║
║   ██╔══██║██║   ██║██║   ██║██║██║╚██╗██║██║╚██╗██║          ║
║   ██║  ██║╚██████╔╝╚██████╔╝██║██║ ╚████║██║ ╚████║          ║
║   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝          ║
║                                                              ║
║                  O D I N ' S   R A V E N                     ║
║            Environment Bootstrap & Toolchain Setup           ║
╚══════════════════════════════════════════════════════════════╝
EOF
  printf "${R}\n"
}

# ------------------------------ helpers --------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

version_of() {
  local cmd="$1"
  have "$cmd" || { echo ""; return; }
  case "$cmd" in
    go)     go version 2>/dev/null | awk '{print $3}' ;;
    python3) python3 --version 2>&1 | awk '{print $2}' ;;
    ruby)   ruby --version 2>/dev/null | awk '{print $2}' ;;
    gem)    gem --version 2>/dev/null ;;
    pip3)   pip3 --version 2>/dev/null | awk '{print $2}' ;;
    cargo)  cargo --version 2>/dev/null | awk '{print $2}' ;;
    node)   node --version 2>/dev/null ;;
    jq)     jq --version 2>/dev/null ;;
    *)      "$cmd" --version 2>/dev/null | head -n1 ;;
  esac
}

# Track outcomes
REPORT_FILE="$(mktemp -t huginn_setup_XXXXXX)"
report() { printf '%s|%s\n' "$1" "$2" >> "$REPORT_FILE"; }

# SUDO helper (avoid prompting repeatedly on non-root)
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then SUDO=""; else SUDO="sudo"; fi
SUDO_KEEPALIVE() { $SUDO -v >/dev/null 2>&1 || true; }

# ------------------------------ 1. OS DETECT ---------------------------------
banner
section "PHASE 0 :: HOST FINGERPRINT"

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
KERNEL="$(uname -r)"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
USER_NAME="${USER:-$(id -un)}"
HOME_DIR="$HOME"
OS_NAME="unknown"; OS_VERSION="unknown"; OS_ID="unknown"; OS_LIKE="unknown"
DISTRO_PRETTY="unknown"

case "$UNAME_S" in
  Linux)
    if [[ -f /etc/os-release ]]; then
      # shellcheck disable=SC1091
      . /etc/os-release
      OS_NAME="${NAME:-Linux}"
      OS_VERSION="${VERSION_ID:-unknown}"
      OS_ID="${ID:-unknown}"
      OS_LIKE="${ID_LIKE:-unknown}"
      DISTRO_PRETTY="${PRETTY_NAME:-$OS_NAME $OS_VERSION}"
    fi
    ;;
  Darwin)
    OS_NAME="macOS"
    OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
    OS_ID="macos"
    OS_LIKE="bsd"
    DISTRO_PRETTY="macOS $(sw_vers -productVersion 2>/dev/null || echo) ($(sw_vers -buildVersion 2>/dev/null || echo))"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    OS_NAME="Windows (POSIX layer)"
    OS_ID="windows"
    OS_LIKE="windows"
    DISTRO_PRETTY="$UNAME_S"
    ;;
esac

ok "OS       : $DISTRO_PRETTY"
ok "Kernel   : $KERNEL"
ok "Arch     : $UNAME_M"
ok "Hostname : $HOSTNAME_FQDN"
ok "User     : $USER_NAME"

# ------------------------------ 2. PKG MANAGER -------------------------------
PKG_MGR="none"
if   have apt-get; then PKG_MGR="apt"
elif have dnf;     then PKG_MGR="dnf"
elif have yum;     then PKG_MGR="yum"
elif have pacman;  then PKG_MGR="pacman"
elif have brew;    then PKG_MGR="brew"
fi
ok "Pkg mgr  : $PKG_MGR"

# pkg_install: install a system package via the detected manager
pkg_install() {
  local pkg="$1"
  case "$PKG_MGR" in
    apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y -qq "$pkg" ;;
    dnf)    $SUDO dnf install -y -q "$pkg" ;;
    yum)    $SUDO yum install -y -q "$pkg" ;;
    pacman) $SUDO pacman -Sy --noconfirm --needed "$pkg" ;;
    brew)   brew install "$pkg" ;;
    *)      return 1 ;;
  esac
}

# ------------------------------ 3. CORE PREREQS ------------------------------
section "PHASE 1 :: CORE PREREQUISITES"

CORE_PKGS=(curl wget git unzip jq make gcc)
[[ "$UNAME_S" == "Linux" ]] && CORE_PKGS+=(python3 python3-pip)
[[ "$UNAME_S" == "Darwin" ]] && CORE_PKGS+=(python3)

for p in "${CORE_PKGS[@]}"; do
  # some distros ship python3-pip as "python3-pip", brew ships as "python3"
  bin="$p"
  [[ "$p" == "python3-pip" ]] && bin="pip3"
  if have "$bin"; then
    hit "$p already present ($(version_of "$bin"))"
    report "core:$p" "skipped"
  else
    log "installing $p via $PKG_MGR…"
    if pkg_install "$p"; then
      hit "$p installed"
      report "core:$p" "installed"
    else
      warn "failed to install $p"
      report "core:$p" "failed"
    fi
  fi
done

# Go (needed for the ProjectDiscovery stack) — install if absent
if ! have go; then
  log "Go toolchain not found — installing…"
  case "$PKG_MGR" in
    brew) brew install go && report "core:go" "installed" ;;
    apt)  pkg_install golang-go && report "core:go" "installed" ;;
    dnf|yum) pkg_install golang && report "core:go" "installed" ;;
    pacman) pkg_install go && report "core:go" "installed" ;;
    *)    warn "cannot auto-install Go — install manually from https://go.dev/dl/"; report "core:go" "failed" ;;
  esac
else
  hit "go present ($(version_of go))"
  report "core:go" "skipped"
fi

# Add Go bin dirs to PATH (current session + persisted)
GO_BIN="$(go env GOPATH 2>/dev/null)/bin"
PDTM_BIN="$HOME/.pdtm/go/bin"
for d in "$GO_BIN" "$PDTM_BIN"; do
  [[ -d "$d" ]] || mkdir -p "$d" 2>/dev/null || true
  case ":$PATH:" in *":$d:"*) ;; *) export PATH="$d:$PATH" ;; esac
done

# Persist PATH additions to shell rc (idempotent)
RC_FILE=""
case "${SHELL:-}" in
  */zsh)  RC_FILE="$HOME/.zshrc" ;;
  */bash) RC_FILE="$HOME/.bashrc" ;;
  *)      RC_FILE="$HOME/.profile" ;;
esac
if [[ -n "$RC_FILE" ]]; then
  for d in "$GO_BIN" "$PDTM_BIN"; do
    line="export PATH=\"$d:\$PATH\""
    grep -Fxq "$line" "$RC_FILE" 2>/dev/null || echo "$line" >> "$RC_FILE"
  done
fi
ok "PATH prepared: $GO_BIN, $PDTM_BIN"

# ------------------------------ 4. COLLECT SPECS -----------------------------
section "PHASE 2 :: HARDWARE / NETWORK FINGERPRINT"

# -- CPU ----------------------------------------------------------------------
CPU_MODEL="unknown"; CPU_CORES="unknown"; CPU_THREADS="unknown"
case "$UNAME_S" in
  Linux)
    CPU_MODEL="$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null | sed 's/^ *//')"
    CPU_THREADS="$(nproc --all 2>/dev/null || echo unknown)"
    CPU_CORES="$(lscpu 2>/dev/null | awk -F: '/^CPU\(s\)/{print $2; exit}' | tr -d ' ')"
    ;;
  Darwin)
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model 2>/dev/null)"
    CPU_THREADS="$(sysctl -n hw.logicalcpu 2>/dev/null)"
    CPU_CORES="$(sysctl -n hw.physicalcpu 2>/dev/null)"
    ;;
esac
[[ -z "$CPU_MODEL"   || "$CPU_MODEL" == " " ]]   && CPU_MODEL="unknown"
[[ -z "$CPU_THREADS" ]] && CPU_THREADS="unknown"
[[ -z "$CPU_CORES"   ]] && CPU_CORES="unknown"

# -- RAM ----------------------------------------------------------------------
RAM_TOTAL="unknown"
case "$UNAME_S" in
  Linux)
    if have free; then
      RAM_TOTAL="$(free -h 2>/dev/null | awk '/^Mem:/{print $2}')"
    fi
    ;;
  Darwin)
    RAM_BYTES="$(sysctl -n hw.memsize 2>/dev/null)"
    [[ -n "$RAM_BYTES" ]] && RAM_TOTAL="$((RAM_BYTES / 1024 / 1024 / 1024)) GiB"
    ;;
esac

# -- DISK ---------------------------------------------------------------------
DISK_INFO="$(df -h / 2>/dev/null | awk 'NR==2{print $2" total, "$4" free ("$5" used)"}')"
[[ -z "$DISK_INFO" ]] && DISK_INFO="unknown"

# -- GPU (best effort) --------------------------------------------------------
GPU_INFO="unknown"
if have nvidia-smi; then
  GPU_INFO="$(nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null | head -n1)"
elif [[ "$UNAME_S" == "Darwin" ]]; then
  GPU_INFO="$(system_profiler SPDisplaysDataType 2>/dev/null | awk -F: '/Chipset Model/{print $2; exit}' | sed 's/^ *//')"
elif have lspci; then
  GPU_INFO="$(lspci 2>/dev/null | grep -iE 'vga|3d|display' | head -n1 | cut -d: -f3- | sed 's/^ *//')"
fi
[[ -z "$GPU_INFO" ]] && GPU_INFO="unknown"

ok "CPU      : $CPU_MODEL ($CPU_CORES cores / $CPU_THREADS threads)"
ok "RAM      : $RAM_TOTAL"
ok "Disk     : $DISK_INFO"
ok "GPU      : $GPU_INFO"

# -- NETWORK ------------------------------------------------------------------
# Interfaces: name -> {mac, ipv4, ipv6}
declare -a IFACE_NAMES=()
declare -a IFACE_MACS=()
declare -a IFACE_IPV4=()
declare -a IFACE_IPV6=()

if [[ "$UNAME_S" == "Linux" ]]; then
  while IFS= read -r iface; do
    [[ -z "$iface" ]] && continue
    [[ "$iface" == "lo" ]] && continue
    IFACE_NAMES+=("$iface")
    IFACE_MACS+=("$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo "")")
    IFACE_IPV4+=("$(ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | head -n1)")
    IFACE_IPV6+=("$(ip -6 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | head -n1)")
  done < <(ls /sys/class/net 2>/dev/null)
elif [[ "$UNAME_S" == "Darwin" ]]; then
  while IFS= read -r iface; do
    [[ -z "$iface" ]] && continue
    IFACE_NAMES+=("$iface")
    IFACE_MACS+=("$(ifconfig "$iface" 2>/dev/null | awk '/ether/{print $2; exit}')")
    IFACE_IPV4+=("$(ipconfig getifaddr "$iface" 2>/dev/null || echo "")")
    IFACE_IPV6+=("$(ifconfig "$iface" 2>/dev/null | awk '/inet6/{print $2; exit}' | cut -d% -f1)")
  done < <(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -v '^lo0$')
fi

# Gateway / DNS
GATEWAY="unknown"; DNS_SERVERS=""
case "$UNAME_S" in
  Linux)
    GATEWAY="$(ip route 2>/dev/null | awk '/^default/{print $3; exit}')"
    if [[ -f /etc/resolv.conf ]]; then
      DNS_SERVERS="$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | paste -sd, -)"
    fi
    ;;
  Darwin)
    GATEWAY="$(netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}')"
    DNS_SERVERS="$(scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | sort -u | paste -sd, -)"
    ;;
esac
[[ -z "$GATEWAY" ]] && GATEWAY="unknown"

# Public IP (best effort, capped)
PUBLIC_IP=""
if [[ "$FETCH_PUBLIC_IP" -eq 1 ]] && have curl; then
  PUBLIC_IP="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
fi
[[ -z "$PUBLIC_IP" ]] && PUBLIC_IP="(unavailable)"

ok "Interfaces: ${#IFACE_NAMES[@]}"
for i in "${!IFACE_NAMES[@]}"; do
  printf "     ${D}· ${IFACE_NAMES[$i]}  mac=${IFACE_MACS[$i]:-n/a}  v4=${IFACE_IPV4[$i]:-n/a}${R}\n"
done
ok "Gateway  : $GATEWAY"
ok "DNS      : ${DNS_SERVERS:-unknown}"
ok "Public IP: $PUBLIC_IP"

# ------------------------------ 5. WRITE pc_specs.json -----------------------
section "PHASE 3 :: WRITING pc_specs.json"

SPECS_FILE="$(pwd)/pc_specs.json"

# Build the interfaces array as JSON using jq
IFACES_JSON="[]"
if [[ "${#IFACE_NAMES[@]}" -gt 0 ]]; then
  for i in "${!IFACE_NAMES[@]}"; do
    IFACES_JSON="$(jq -c \
      --arg n "${IFACE_NAMES[$i]}" \
      --arg m "${IFACE_MACS[$i]}" \
      --arg v4 "${IFACE_IPV4[$i]}" \
      --arg v6 "${IFACE_IPV6[$i]}" \
      '. + [{name:$n, mac:$m, ipv4:$v4, ipv6:$v6}]' <<<"$IFACES_JSON")"
  done
fi

# Toolchain versions
TOOLCHAIN_JSON="$(jq -nc \
  --arg go     "$(version_of go)" \
  --arg python "$(version_of python3)" \
  --arg ruby   "$(version_of ruby)" \
  --arg gem    "$(version_of gem)" \
  --arg pip    "$(version_of pip3)" \
  --arg cargo  "$(version_of cargo)" \
  --arg node   "$(version_of node)" \
  --arg bash   "$(bash --version 2>/dev/null | head -n1 | awk '{print $4}')" \
  --arg shell  "${SHELL:-unknown}" \
  '{go:$go, python:$python, ruby:$ruby, gem:$gem, pip:$pip, cargo:$cargo, node:$node, bash:$bash, shell:$shell}')"

jq -n \
  --arg ts        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg os_name   "$OS_NAME" \
  --arg os_ver    "$OS_VERSION" \
  --arg os_id     "$OS_ID" \
  --arg os_like   "$OS_LIKE" \
  --arg distro    "$DISTRO_PRETTY" \
  --arg kernel    "$KERNEL" \
  --arg arch      "$UNAME_M" \
  --arg hostname  "$HOSTNAME_FQDN" \
  --arg user      "$USER_NAME" \
  --arg home      "$HOME_DIR" \
  --arg pkg_mgr   "$PKG_MGR" \
  --arg cpu_model "$CPU_MODEL" \
  --arg cpu_cores "$CPU_CORES" \
  --arg cpu_thr   "$CPU_THREADS" \
  --arg ram       "$RAM_TOTAL" \
  --arg disk      "$DISK_INFO" \
  --arg gpu       "$GPU_INFO" \
  --arg gateway   "$GATEWAY" \
  --arg dns       "$DNS_SERVERS" \
  --arg public_ip "$PUBLIC_IP" \
  --argjson ifaces "$IFACES_JSON" \
  --argjson tools  "$TOOLCHAIN_JSON" \
  '{
     schema:      "huginn/pc_specs/v1",
     timestamp:   $ts,
     system: {
       os_name:      $os_name,
       os_version:   $os_ver,
       os_id:        $os_id,
       os_like:      $os_like,
       distro:       $distro,
       kernel:       $kernel,
       arch:         $arch,
       hostname:     $hostname,
       user:         $user,
       home:         $home,
       package_mgr:  $pkg_mgr
     },
     hardware: {
       cpu_model:    $cpu_model,
       cpu_cores:    $cpu_cores,
       cpu_threads:  $cpu_thr,
       ram_total:    $ram,
       disk_root:    $disk,
       gpu:          $gpu
     },
     network: {
       interfaces:   $ifaces,
       gateway:      $gateway,
       dns_servers:  $dns,
       public_ip:    $public_ip
     },
     toolchain: $tools
   }' > "$SPECS_FILE"

if [[ -s "$SPECS_FILE" ]]; then
  ok "wrote $SPECS_FILE"
  report "specs:pc_specs.json" "written"
else
  err "failed to write pc_specs.json"
  report "specs:pc_specs.json" "failed"
fi

[[ "$SPECS_ONLY" -eq 1 ]] && { section "DONE (specs-only)"; cat "$SPECS_FILE"; rm -f "$REPORT_FILE"; exit 0; }

# =============================================================================
#                       TOOL REGISTRY & INSTALLATION
# =============================================================================
section "PHASE 4 :: TOOLCHAIN PROVISIONING"

# -------- install helpers ----------------------------------------------------
install_go_tool() {
  # $1 = binary name, $2 = go package path
  local bin="$1" pkg="$2"
  if have "$bin"; then
    hit "$bin already present"
    report "tool:$bin" "skipped"
    return 0
  fi
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    warn "$bin MISSING (would install via: go install $pkg)"
    report "tool:$bin" "missing"
    return 0
  fi
  log "installing $bin via go install…"
  if go install -v "$pkg" 2>&1 | tail -n 2; then
    if have "$bin" || [[ -x "$GO_BIN/$bin" ]]; then
      hit "$bin installed"
      report "tool:$bin" "installed"
    else
      warn "$bin built but not on PATH yet (add $GO_BIN to PATH)"
      report "tool:$bin" "installed"
    fi
  else
    err "$bin install failed"
    report "tool:$bin" "failed"
  fi
}

install_gem_tool() {
  local bin="$1" gemname="${2:-$1}"
  if have "$bin"; then hit "$bin present"; report "tool:$bin" "skipped"; return 0; fi
  [[ "$CHECK_ONLY" -eq 1 ]] && { warn "$bin MISSING"; report "tool:$bin" "missing"; return 0; }
  have gem || { warn "gem not available — skipping $bin"; report "tool:$bin" "failed"; return 1; }
  log "installing $bin via gem…"
  if $SUDO gem install --no-document "$gemname"; then
    hit "$bin installed"; report "tool:$bin" "installed"
  else
    err "$bin install failed"; report "tool:$bin" "failed"
  fi
}

install_pip_tool() {
  local bin="$1" pkg="${2:-$1}"
  if have "$bin"; then hit "$bin present"; report "tool:$bin" "skipped"; return 0; fi
  [[ "$CHECK_ONLY" -eq 1 ]] && { warn "$bin MISSING"; report "tool:$bin" "missing"; return 0; }
  have pip3 || { warn "pip3 not available — skipping $bin"; report "tool:$bin" "failed"; return 1; }
  log "installing $bin via pip3…"
  if pip3 install --user --quiet "$pkg"; then
    hit "$bin installed"; report "tool:$bin" "installed"
  else
    err "$bin install failed"; report "tool:$bin" "failed"
  fi
}

install_cargo_tool() {
  local bin="$1" pkg="${2:-$1}"
  if have "$bin"; then hit "$bin present"; report "tool:$bin" "skipped"; return 0; fi
  [[ "$CHECK_ONLY" -eq 1 ]] && { warn "$bin MISSING"; report "tool:$bin" "missing"; return 0; }
  have cargo || { warn "cargo not available — skipping $bin"; report "tool:$bin" "failed"; return 1; }
  log "installing $bin via cargo…"
  if cargo install --quiet "$pkg"; then
    hit "$bin installed"; report "tool:$bin" "installed"
  else
    err "$bin install failed"; report "tool:$bin" "failed"
  fi
}

install_pkg_tool() {
  # generic system-package tool
  local bin="$1" pkg="${2:-$1}"
  if have "$bin"; then hit "$bin present"; report "tool:$bin" "skipped"; return 0; fi
  [[ "$CHECK_ONLY" -eq 1 ]] && { warn "$bin MISSING"; report "tool:$bin" "missing"; return 0; }
  log "installing $bin via $PKG_MGR…"
  if pkg_install "$pkg"; then
    hit "$bin installed"; report "tool:$bin" "installed"
  else
    err "$bin install failed"; report "tool:$bin" "failed"
  fi
}

# -----------------------------------------------------------------------------
# A. Core ProjectDiscovery stack (via go install — the canonical method)
#    Alternative: install pdtm once and let it manage them all.
# -----------------------------------------------------------------------------
section "PHASE 4a :: ProjectDiscovery Stack"

# pdtm — ProjectDiscovery's own tool manager (simplifies future updates)
if ! have pdtm; then
  [[ "$CHECK_ONLY" -eq 0 ]] && {
    log "installing pdtm (ProjectDiscovery Tool Manager)…"
    go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest 2>&1 | tail -n 2 \
      && report "tool:pdtm" "installed" \
      || report "tool:pdtm" "failed"
  }
else
  hit "pdtm present"
  report "tool:pdtm" "skipped"
fi

# Individual tools — go install keeps them independently versioned
install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool katana    "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool nuclei    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool dnsx      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool naabu     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

# nuclei templates (useful even if you don't run nuclei manually)
if have nuclei && [[ "$CHECK_ONLY" -eq 0 ]]; then
  log "updating nuclei templates…"
  nuclei -update-templates -silent 2>/dev/null && hit "nuclei templates updated" \
    || warn "nuclei template update failed (non-fatal)"
fi

# -----------------------------------------------------------------------------
# B. Subdomain / DNS recon
# -----------------------------------------------------------------------------
section "PHASE 4b :: Subdomain & DNS Recon"

install_go_tool amass       "github.com/owasp-amass/amass/v4/...@master"
install_go_tool assetfinder "github.com/tomnomnom/assetfinder@latest"
install_go_tool shuffledns  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
install_go_tool dnsgen      "github.com/ProjectAnte/dnsgen@latest"

# massdns — the exception: not a go install, classic git clone + make
if ! have massdns; then
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    warn "massdns MISSING"
    report "tool:massdns" "missing"
  else
    log "installing massdns via git clone + make…"
    TMPD="$(mktemp -d)"
    if git clone --depth 1 https://github.com/blechschmidt/massdns.git "$TMPD/massdns" \
       && (cd "$TMPD/massdns" && make -j"$(nproc 2>/dev/null || echo 2)" >/dev/null 2>&1 && $SUDO make install >/dev/null 2>&1); then
      hit "massdns installed"
      report "tool:massdns" "installed"
    else
      err "massdns install failed"
      report "tool:massdns" "failed"
    fi
    rm -rf "$TMPD"
  fi
else
  hit "massdns present"; report "tool:massdns" "skipped"
fi

# -----------------------------------------------------------------------------
# C. Web / content discovery
# -----------------------------------------------------------------------------
section "PHASE 4c :: Web & Content Discovery"

install_go_tool gau       "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool gowitness "github.com/sensepost/gowitness@latest"
install_go_tool hakrawler "github.com/hakluke/hakrawler@latest"
install_go_tool waybackurls "github.com/tomnomnom/waybackurls@latest"
install_go_tool ffuf      "github.com/ffuf/ffuf/v2@latest"
install_go_tool gobuster  "github.com/OJ/gobuster/v3@latest"
install_go_tool dirsearch "github.com/maurosoria/dirsearch@latest"  # go port; the python one is separate
install_go_tool subzy     "github.com/LukaSikic/subzy@latest"
install_go_tool crlfuzz   "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
install_go_tool nomore403 "github.com/devploit/nomore403@latest"
install_go_tool dalfox    "github.com/hahwul/dalfox/v2@latest"
install_go_tool gf        "github.com/tomnomnom/gf@latest"

# Amass config (optional but useful)
if have amass && [[ "$CHECK_ONLY" -eq 0 ]]; then
  mkdir -p "$HOME/.config/amass"
  [[ -f "$HOME/.config/amass/config.ini" ]] || \
    amass config -config "$HOME/.config/amass/config.ini" >/dev/null 2>&1 || true
fi

# -----------------------------------------------------------------------------
# D. Vulnerable-tooling extensions
# -----------------------------------------------------------------------------
section "PHASE 4d :: Vuln-Hunting Extras"

# sqlmap — classic SQLi automation
install_pkg_tool sqlmap sqlmap 2>/dev/null || install_pip_tool sqlmap sqlmap

# commix — command injection
if [[ "$CHECK_ONLY" -eq 0 ]]; then
  if [[ ! -d /opt/commix ]]; then
    log "cloning commix → /opt/commix"
    $SUDO git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix >/dev/null 2>&1 \
      && { $SUDO ln -sf /opt/commix/commix.py /usr/local/bin/commix; hit "commix installed"; report "tool:commix" "installed"; } \
      || { err "commix failed"; report "tool:commix" "failed"; }
  else
    hit "commix present"; report "tool:commix" "skipped"
  fi
fi

# jwt_tool
if [[ "$CHECK_ONLY" -eq 0 ]]; then
  if [[ ! -d /opt/jwt_tool ]]; then
    log "cloning jwt_tool → /opt/jwt_tool"
    $SUDO git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool >/dev/null 2>&1 \
      && { pip3 install --user -q -r /opt/jwt_tool/requirements.txt 2>/dev/null; $SUDO ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool; hit "jwt_tool installed"; report "tool:jwt_tool" "installed"; } \
      || { err "jwt_tool failed"; report "tool:jwt_tool" "failed"; }
  else
    hit "jwt_tool present"; report "tool:jwt_tool" "skipped"
  fi
fi

# graphql-cop
install_pip_tool graphql-cop graphql-cop

# ghauri — advanced SQLi (sqlmap-like)
install_pip_tool ghauri ghauri

# arjun — parameter discovery
install_pip_tool arjun arjun

# git-dumper
install_pip_tool git-dumper git-dumper

# semgrep — SAST for local source audits
install_pip_tool semgrep semgrep

# -----------------------------------------------------------------------------
# E. Optional: wordlists / seclists
# -----------------------------------------------------------------------------
section "PHASE 4e :: Wordlists"

if [[ "$CHECK_ONLY" -eq 0 ]]; then
  if [[ ! -d /usr/share/seclists ]]; then
    log "fetching SecLists → /usr/share/seclists…"
    $SUDO git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists >/dev/null 2>&1 \
      && { hit "SecLists installed"; report "wordlist:seclists" "installed"; } \
      || { warn "SecLists clone failed"; report "wordlist:seclists" "failed"; }
  else
    hit "SecLists present"
    report "wordlist:seclists" "skipped"
  fi
fi

# -----------------------------------------------------------------------------
# F. Final: shell integration + summary
# -----------------------------------------------------------------------------
section "PHASE 5 :: SUMMARY"

if [[ -s "$REPORT_FILE" ]]; then
  printf "${B}%-30s %s${R}\n" "COMPONENT" "STATUS"
  printf "${D}%s${R}\n" "──────────────────────────────────────────────"
  # section grouping
  while IFS='|' read -r k v; do
    color="$GY"
    case "$v" in
      installed|written) color="$GR" ;;
      skipped)           color="$CY" ;;
      failed)            color="$RE" ;;
      missing)           color="$YE" ;;
    esac
    printf "%-30s ${color}%s${R}\n" "$k" "$v"
  done < "$REPORT_FILE"
fi

rm -f "$REPORT_FILE"

# Hint user to source rc if PATH was edited
if [[ -n "$RC_FILE" ]]; then
  printf "\n${D}(PATH additions persisted to %s — run 'source %s' or open a new shell)${R}\n" "$RC_FILE" "$RC_FILE"
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  section "CHECK COMPLETE — nothing installed"
else
  section "SETUP COMPLETE"
  printf "${GR}▸${R} specs  : ${B}pc_specs.json${R}\n"
  printf "${GR}▸${R} go bin : ${B}%s${R}\n" "$GO_BIN"
  printf "${GR}▸${R} next   : ${B}python3 HUGINN.py${R}\n\n"
fi

exit 0
