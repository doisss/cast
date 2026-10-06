#!/usr/bin/env bash
#
# sarbar uninstaller.
#
#   sudo bash uninstall.sh    remove the system-wide install
#                              /usr/bin/{sarbar,cast,trivy,falco}
#                              /etc/falco/
#                              /var/lib/sarbar/
#   bash uninstall.sh         remove the per-user install
#                              ~/.local/bin/{sarbar,cast}
#                              ~/.sarbar/
#
# Asks separately about the Python package and about the scanner binaries, so
# you can keep trivy or falco if something else on the machine uses them.
#
set -euo pipefail

SYSTEM=0
[ "$(id -u)" -eq 0 ] && SYSTEM=1
BIN_DIR="/usr/bin"
SARBAR_HOME="/var/lib/sarbar"
[ "$SYSTEM" -eq 0 ] && BIN_DIR="$HOME/.local/bin"
[ "$SYSTEM" -eq 0 ] && SARBAR_HOME="$HOME/.sarbar"

echo "=========================================================================="
echo "  sarbar — Uninstaller"
echo "=========================================================================="
echo ""
echo "  mode : $([ "$SYSTEM" -eq 1 ] && echo 'system-wide (root)' || echo 'per-user')"
echo ""

# --------------------------------------------------------------------------
# 1. the Python package
# --------------------------------------------------------------------------
echo "[1/3] Python package"
read -r -p "    Remove the sarbar Python package? [y/N]: " a
if [ "${a:-n}" = "y" ] || [ "${a:-n}" = "Y" ]; then
    pip3 uninstall sarbar -y --break-system-packages 2>/dev/null \
        || pip3 uninstall sarbar -y 2>/dev/null \
        || "$BIN_DIR/sarbar" --version >/dev/null 2>&1 && echo "    removed"
    echo "    done"
else
    echo "    kept"
fi

# --------------------------------------------------------------------------
# 2. the scanner symlinks
# --------------------------------------------------------------------------
echo ""
echo "[2/3] Scanner commands in $BIN_DIR"
echo "    [1] remove both trivy and falco"
echo "    [2] remove only trivy"
echo "    [3] remove only falco"
echo "    [4] keep both"
read -r -p "    choice [1-4]: " choice
case "${choice:-4}" in
    1) rm -fv "$BIN_DIR/trivy" "$BIN_DIR/falco" "$BIN_DIR/falcoctl" ;;
    2) rm -fv "$BIN_DIR/trivy" ;;
    3) rm -fv "$BIN_DIR/falco" "$BIN_DIR/falcoctl" ;;
    *) echo "    kept both" ;;
esac

if [ "$SYSTEM" -eq 1 ]; then
    # the system layout keeps falco's configuration where a distro package does,
    # and the container plugin in /usr/share, which falco needs to see containers
    for d in /etc/falco /etc/falcoctl /usr/share/falco; do
        [ -d "$d" ] || continue
        read -r -p "    Remove $d ? [y/N]: " c
        if [ "${c:-n}" = "y" ] || [ "${c:-n}" = "Y" ]; then
            rm -rf "$d" && echo "    removed $d"
        else
            echo "    kept $d"
        fi
    done
    if [ -d /var/lib/sarbar ]; then
        read -r -p "    Remove /var/lib/sarbar (scan history)? [y/N]: " h
        if [ "${h:-n}" = "y" ] || [ "${h:-n}" = "Y" ]; then
            rm -rf /var/lib/sarbar && echo "    removed /var/lib/sarbar"
        else
            echo "    kept /var/lib/sarbar (history stays in \`sarbar history\`)"
        fi
    fi
fi

# --------------------------------------------------------------------------
# 3. sarbar's own data
# --------------------------------------------------------------------------
echo ""
echo "[3/3] sarbar data in $SARBAR_HOME"
echo "    binaries and falco configuration live there in per-user mode."
echo "    Run history is separate, in the XDG state directory:"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/sarbar"
echo "      $STATE_DIR"
read -r -p "    Remove it? [y/N]: " d
if [ "${d:-n}" = "y" ] || [ "${d:-n}" = "Y" ]; then
    rm -rf "$SARBAR_HOME"
    echo "    removed $SARBAR_HOME"
fi
if [ -d "$STATE_DIR" ]; then
    read -r -p "    Remove $STATE_DIR (scan history)? [y/N]: " h
    if [ "${h:-n}" = "y" ] || [ "${h:-n}" = "Y" ]; then
        rm -rf "$STATE_DIR" && echo "    removed $STATE_DIR"
    else
        echo "    kept (history stays available to `sarbar history`)"
    fi
fi

echo ""
echo "=========================================================================="
echo "  Uninstallation complete"
echo "=========================================================================="
echo ""
echo "  The falco eBPF driver is deliberately left installed. It lives in the"
echo "  kernel, it costs nothing while idle, and other tools may be using it."
echo "  Nothing sarbar installed needs it to be removed for a clean system."
echo ""