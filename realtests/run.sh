#!/usr/bin/env bash
#
# Реальная проверка cast: запускает demo/demo.sh на настоящих целях и проверяет,
# что каждая команда выполнилась (код выхода 0 или 1, а не 2).
#
#   bash realtests/run.sh              основные и средние команды (все)
#   bash realtests/run.sh basic        только основные: образ, контейнер,
#                                      Dockerfile, папка, хост, движки
#   bash realtests/run.sh medium       только средние: архив, Kubernetes,
#                                      Terraform, Helm, compose, rootfs,
#                                      репозиторий, SBOM, диск ВМ, кластер
#   bash realtests/run.sh -h           эта справка
#
# Остальные параметры передаются demo.sh как есть (--top N, --skip-repo, --pause).
# Если кластера нет (не запускали setup.sh --cluster), его проверка пропускается.
#
# Сначала один раз: bash realtests/setup.sh [--cluster]
#
# Почему проверяется только код 2: коды 0 и 1 зависят от базы уязвимостей
# (завтра у alpine:3.19 может появиться critical), а код 2 значит, что проверка
# не выполнена — это ошибка всегда.
#
# Переменные: CAST — какую команду проверять (по умолчанию cast из PATH).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${CAST_REALTESTS_BIN:-$HOME/.cache/cast-realtests/bin}"
ARGS=()
for arg in "$@"; do
    case "$arg" in
        -h|--help) sed -n '2,/^[^#]/{/^#/p}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)         ARGS+=("$arg") ;;
    esac
done

if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; Z=$'\033[0m'
else G=""; R=""; Y=""; B=""; Z=""; fi

KUBECTL="$(command -v kubectl || echo "$BIN/kubectl")"
if [[ " ${ARGS[*]-} " != *" --skip-cluster "* && " ${ARGS[*]-} " != *" basic "* ]]; then
    if ! [ -x "$KUBECTL" ] || ! "$KUBECTL" cluster-info >/dev/null 2>&1; then
        printf '%s!%s кластер Kubernetes недоступен — его проверку пропускаю (поднять: bash realtests/setup.sh --cluster)\n' "$Y" "$Z"
        ARGS+=(--skip-cluster)
    fi
fi

RESULTS="$(mktemp)"
trap 'rm -f "$RESULTS"' EXIT
DEMO_RESULTS="$RESULTS" bash "$HERE/../demo/demo.sh" ${ARGS[@]+"${ARGS[@]}"}
demo_rc=$?

echo
total=0; failed=()
while IFS='|' read -r cmd rc secs; do
    [ -n "$cmd" ] || continue
    total=$((total + 1))
    [ "$rc" = 0 ] || [ "$rc" = 1 ] || failed+=("$cmd (код $rc)")
done <"$RESULTS"

if [ "$total" -eq 0 ]; then
    printf '%s%s✗ realtests: demo.sh не дошёл до проверок (код %s), см. вывод выше%s\n' "$B" "$R" "$demo_rc" "$Z"
    exit 2
fi
if [ "${#failed[@]}" -eq 0 ]; then
    printf '%s%s✓ realtests: все %s команд выполнены%s\n' "$B" "$G" "$total" "$Z"
    exit 0
fi
printf '%s%s✗ realtests: не выполнено %s из %s:%s\n' "$B" "$R" "${#failed[@]}" "$total" "$Z"
printf '  %s\n' "${failed[@]}"
exit 1
