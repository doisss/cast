#!/usr/bin/env bash
#
# sarbar installer.
#
#   ONE COMMAND, from GitHub:
#
#       curl -sfL https://raw.githubusercontent.com/doisss/cast/main/install.sh \
#           | sudo bash -s --
#
#   FROM A CLONE:
#
#       sudo bash install.sh
#
# What it installs, when run as root:
#
#   /usr/bin/sarbar, /usr/bin/cast       the program and its short name
#   /usr/bin/trivy                        vulnerability / secret / Dockerfile scanner
#   /usr/bin/falco, /usr/bin/falcoctl     runtime behaviour scanner + driver manager
#   /usr/share/falco/plugins/             the container plugin falco needs
#   /etc/falco/, /etc/falcoctl/           their configuration
#   the falco eBPF driver                  loaded into the kernel, once
#
# That is the layout Debian, Fedora and Arch use, so afterwards `trivy` and
# `falco` are ordinary commands with no wrappers, no PATH tricks and no
# per-user fallbacks.
#
# Without root everything still works, but in a per-user layout
# (~/.sarbar/bin with symlinks in ~/.local/bin) and without the falco driver.
#
# Options (append to the one-liner after `--`):
#   --no-driver     skip the eBPF driver; sarbar will report that falco observed
#                   nothing rather than calling a container clean
#   --no-scanners   install sarbar only, no trivy/falco download
#   --ref TAG       install a tag instead of the branch (default: main)
#
set -euo pipefail

# ----------------------------------------------------------------- arguments
REF="${SARBAR_REF:-main}"
REPO="${SARBAR_REPO:-doisss/cast}"
WANT_DRIVER=1
WANT_SCANNERS=1
for arg in "$@"; do
    case "$arg" in
        --no-driver)   WANT_DRIVER=0 ;;
        --no-scanners) WANT_SCANNERS=0 ;;
        --ref)         shift; REF="${1:?--ref needs a value}" ;;
        --ref=*)       REF="${arg#--ref=}" ;;
        -h|--help)     sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)             echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

SYSTEM=0
[ "$(id -u)" -eq 0 ] && SYSTEM=1

# Where the sources are. If this script was piped from a URL there is no checkout
# next to it, so the sources are fetched; if it runs from a clone, they are used
# as they are.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)"

die() { echo ""; echo "  ! $*" >&2; echo ""; exit 1; }

# ----------------------------------------------------------------- banner
echo "=========================================================================="
echo "  sarbar — Container Automated Security Testing"
echo "=========================================================================="
echo ""
echo "  mode     : $([ "$SYSTEM" -eq 1 ] && echo 'system-wide (root)' || echo 'per-user (no root)')"

# ------------------------------------------------------- 1. fetch the sources
fetch_sources() {
    local repo="$REPO" ref="$REF"
    if ! printf '%s' "$repo" | grep -Eq '^[^/[:space:]]+/[^/[:space:]]+$'; then
        die "REPO must look like owner/name, got: '$repo'
   Set it at the top of this script, or override it:
       SARBAR_REPO=owner/name bash install.sh"
    fi
    local tarball tmp
    tarball="https://codeload.github.com/${repo}/tar.gz/${ref}"
    echo "  source  : ${repo}@${ref}"
    echo ""
    echo "[0/5] Fetching the sources"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    if ! command -v curl >/dev/null 2>&1; then
        die "curl is required to fetch the sources"
    fi
    curl -fsSL --retry 3 --max-time 180 "$tarball" -o "$tmp/src.tar.gz" \
        || die "could not download $tarball
   Check the repository name and that the ref '$ref' exists."
    # The archive has one top-level directory (cast-main/); strip it.
    mkdir -p "$tmp/src"
    tar -xzf "$tmp/src.tar.gz" -C "$tmp/src" --strip-components=1 \
        || die "could not unpack the downloaded archive"
    [ -f "$tmp/src/pyproject.toml" ] \
        || die "the downloaded archive contains no pyproject.toml, so it is not sarbar"
    SRC="$tmp/src"
}

SRC="$HERE"
if [ -f "$HERE/pyproject.toml" ]; then
    echo "  source  : $HERE (local checkout)"
else
    fetch_sources
fi

# ----------------------------------------------------------------- 2. Python
echo ""
echo "[1/5] Python"
need_python=1
if command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        need_python=0
        echo "  -> $(python3 --version), ok"
    fi
fi
if [ "$need_python" -eq 1 ]; then
    echo "  -> installing"
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-pip
    elif command -v dnf >/dev/null 2>&1; then dnf install -y python3 python3-pip
    elif command -v yum >/dev/null 2>&1; then yum install -y python3 python3-pip
    elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm python python-pip
    else die "no supported package manager. Install Python 3.10 or newer and re-run."
    fi
    python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
        || die "Python 3.10+ is required and could not be installed"
fi

# ----------------------------------------------------------------- 3. sarbar
#
# Debian and derivatives mark the system Python as "externally managed"
# (PEP 668), so a plain `pip install` is refused. Strategies are tried in order
# and the first that works wins.
echo ""
echo "[2/5] sarbar"
if command -v pip3 >/dev/null 2>&1; then PIP=pip3
elif command -v pip  >/dev/null 2>&1; then PIP=pip
else die "pip not found. Install it with your package manager (python3-pip)."
fi

SARBAR_BIN=""
if [ "$SYSTEM" -eq 1 ]; then
    if "$PIP" install --break-system-packages "$SRC" >/dev/null 2>&1; then
        SARBAR_BIN="$(command -v sarbar || echo /usr/bin/sarbar)"
    elif command -v pipx >/dev/null 2>&1 && pipx install "$SRC" >/dev/null 2>&1; then
        SARBAR_BIN="$(command -v sarbar)"
    fi
else
    if "$PIP" install --user --break-system-packages "$SRC" >/dev/null 2>&1; then
        SARBAR_BIN="$HOME/.local/bin/sarbar"
    elif command -v pipx >/dev/null 2>&1 && pipx install "$SRC" >/dev/null 2>&1; then
        SARBAR_BIN="$(command -v sarbar)"
    else
        VENV="$HOME/.local/share/sarbar-venv"
        if python3 -m venv "$VENV" >/dev/null 2>&1 &&
           "$VENV/bin/pip" install "$SRC" >/dev/null 2>&1; then
            mkdir -p "$HOME/.local/bin"
            ln -sf "$VENV/bin/sarbar" "$HOME/.local/bin/sarbar"
            ln -sf "$VENV/bin/cast" "$HOME/.local/bin/cast" 2>/dev/null || true
            SARBAR_BIN="$HOME/.local/bin/sarbar"
        fi
    fi
fi

if ! command -v sarbar >/dev/null 2>&1 && [ -z "$SARBAR_BIN" ]; then
    die "could not install sarbar. Try by hand:
       python3 -m pip install --user --break-system-packages $SRC
       pipx install $SRC
       python3 -m venv ~/.venvs/sarbar && ~/.venvs/sarbar/bin/pip install $SRC"
fi
SARBAR_CMD="$(command -v sarbar 2>/dev/null || echo "${SARBAR_BIN:-sarbar}")"
echo "  -> $(command -v sarbar 2>/dev/null || echo "$SARBAR_CMD")"

# ----------------------------------------------------------------- 4. scanners
echo ""
if [ "$WANT_SCANNERS" -eq 1 ]; then
    echo "[3/5] The scanners sarbar wraps (trivy, falco, falcoctl, plugin)"
    SETUP_ARGS="setup --system"
    [ "$SYSTEM" -eq 0 ] && SETUP_ARGS="setup"
    # A root install loads the driver as well; a non-root one cannot.
    [ "$WANT_DRIVER" -eq 0 ] && SETUP_ARGS="$SETUP_ARGS --no-driver"
    if ! "$SARBAR_CMD" $SETUP_ARGS; then
        echo "  ! setup reported a problem; the details are above."
        echo "    sarbar itself is installed and works without the scanners."
    fi
else
    echo "[3/5] Scanners: skipped (--no-scanners)"
fi

# ----------------------------------------------------------------- 5. Docker
#
# Docker access is not granted here on purpose. `docker.sock` is equivalent to
# root on the host, so adding an account to the docker group is the user's
# decision, not the installer's.
echo ""
echo "[4/5] Docker access"
if "$SARBAR_CMD" setup --check 2>/dev/null | grep -q '^docker *ready'; then
    echo "  -> this account can already talk to Docker"
else
    cat <<'DOCKER'
  -> not usable by this account. Running containers cannot be inspected yet.
     `sarbar scan <image>` and `sarbar scan .` work regardless.

     To enable container targets:
         sudo usermod -aG docker $USER
     then log out and back in (or: newgrp docker)
DOCKER
fi

# ----------------------------------------------------------------- 6. verify
echo ""
echo "[5/5] Verification"
echo ""
"$SARBAR_CMD" setup --check 2>&1 | sed 's/^/  /' || true
echo ""

# ----------------------------------------------------------------- wrap up
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$(dirname "$SARBAR_CMD")"; then
    cat <<PATHEOF
  ! $(dirname "$SARBAR_CMD") is not on PATH in this shell. Add it:
      export PATH="$(dirname "$SARBAR_CMD"):\$PATH"

PATHEOF
fi

cat <<'EOF'

--------------------------------------------------------------------------
  Done. Try:

    sarbar scan .                # your own code
    sarbar scan alpine:3.19      # an image
    sarbar offline alpine:3.19   # fetch the DB once, then work with no network
    sarbar -v                    # version

  Checking a running container needs falco, which reads kernel events from the
  kernel and so needs root. sarbar asks for your sudo password at that moment
  and reuses it for the rest of the session, so you are not asked every time.

  To never be asked, grant the capability once:

    sudo setcap cap_sys_admin,cap_perfmon,cap_sys_ptrace,cap_sys_resource+ep \
        /usr/bin/falco

  Remove everything:

    sudo bash uninstall.sh
--------------------------------------------------------------------------
EOF