#!/usr/bin/env bash
#
# Убрать то, что сделал realtests/setup.sh.
#
#   bash realtests/teardown.sh           удалить кластер cast-test и вернуть
#                                        прежний ~/.kube/config
#   bash realtests/teardown.sh --all     то же, а ещё удалить kind и kubectl из
#                                        ~/.cache/cast-realtests и образы
#                                        kindest/node, alpine:3.19, nginx:alpine
#
# Базу Trivy и сам cast скрипт не трогает.

set -uo pipefail

BIN="${CAST_REALTESTS_BIN:-$HOME/.cache/cast-realtests/bin}"
CLUSTER=cast-test
ALL=0
for arg in "$@"; do
    case "$arg" in
        --all)     ALL=1 ;;
        -h|--help) sed -n '2,/^[^#]/{/^#/p}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)         echo "неизвестный параметр: $arg (см. --help)" >&2; exit 2 ;;
    esac
done

SUDO=()
[ "$(id -u)" -eq 0 ] || SUDO=(sudo)
if docker info >/dev/null 2>&1; then DOCKER=(docker); else DOCKER=("${SUDO[@]}" docker); fi
KIND=("$BIN/kind"); [ "${DOCKER[0]}" = docker ] || KIND=("${SUDO[@]}" "$BIN/kind")

echo "диск до: $(df -h / | awk 'NR==2{print $4}') свободно"
if [ -x "$BIN/kind" ] && "${KIND[@]}" get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    "${KIND[@]}" delete cluster --name "$CLUSTER"
    if [ -f "$HOME/.kube/config.cast-backup" ]; then
        mv "$HOME/.kube/config.cast-backup" "$HOME/.kube/config"
        echo "~/.kube/config восстановлен из резервной копии"
    else
        rm -f "$HOME/.kube/config"
        echo "~/.kube/config удалён (до кластера его не было)"
    fi
else
    echo "кластера $CLUSTER нет"
fi
"${DOCKER[@]}" rm -f cast-demo-web >/dev/null 2>&1 || true   # если demo.sh прервали

if [ "$ALL" -eq 1 ]; then
    rm -rf "$BIN" && echo "удалено: $BIN"
    # shellcheck disable=SC2046
    "${DOCKER[@]}" rmi $("${DOCKER[@]}" images -q kindest/node) alpine:3.19 nginx:alpine 2>/dev/null || true
    echo "образы kindest/node, alpine:3.19, nginx:alpine удалены (если были)"
fi
echo "диск после: $(df -h / | awk 'NR==2{print $4}') свободно"
