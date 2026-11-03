#!/usr/bin/env bash
#
# Подготовка машины к реальным проверкам cast (realtests/run.sh и demo/demo.sh).
#
#   bash realtests/setup.sh              проверить cast, движки и Docker, скачать
#                                        образы и базу Trivy
#   bash realtests/setup.sh --cluster    то же и поднять тестовый кластер Kubernetes
#                                        (kind, один узел, ~1 ГБ образ, нужно 4 ГБ памяти)
#   bash realtests/setup.sh -h           эта справка
#
# Что делает:
#   1. проверяет, что есть cast, Trivy, Docker Bench, Docker и доступ к нему;
#   2. скачивает образы, которые нужны проверкам: alpine:3.19 и nginx:alpine;
#   3. скачивает базу уязвимостей Trivy заранее, чтобы первая проверка не ждала;
#   4. с --cluster: скачивает kind v0.24.0 и kubectl v1.31.0 (официальные адреса,
#      сверка sha256) в ~/.cache/cast-realtests/bin, создаёт кластер cast-test,
#      кладёт его kubeconfig в ~/.kube/config (прежний сохраняется в
#      ~/.kube/config.cast-backup) и разворачивает одну намеренно небезопасную
#      нагрузку (k8s/insecure-workload.yaml), чтобы скану было что найти.
#
# Убрать всё, что сделал этот скрипт: bash realtests/teardown.sh
#
# Переменные: CAST — какую команду проверять (по умолчанию cast из PATH).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${CAST_REALTESTS_BIN:-$HOME/.cache/cast-realtests/bin}"
KIND_VERSION=v0.24.0
KUBECTL_VERSION=v1.31.0
CLUSTER=cast-test
WANT_CLUSTER=0

for arg in "$@"; do
    case "$arg" in
        --cluster) WANT_CLUSTER=1 ;;
        -h|--help) sed -n '2,/^[^#]/{/^#/p}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)         echo "неизвестный параметр: $arg (см. --help)" >&2; exit 2 ;;
    esac
done

if [ -t 1 ]; then G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[1m'; Z=$'\033[0m'
else G=""; Y=""; R=""; B=""; Z=""; fi
ok()   { printf '%s✓%s %s\n' "$G" "$Z" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$Z" "$*"; }
die()  { printf '%s✗ Ошибка:%s %s\n' "$R" "$Z" "$*"; exit 2; }
step() { printf '\n%s== %s%s\n' "$B" "$*" "$Z"; }

SUDO=()
[ "$(id -u)" -eq 0 ] || SUDO=(sudo)

step "cast и движки"
CAST_CMD="${CAST:-cast}"
CAST_BIN="$(command -v "$CAST_CMD" || true)"
[ -n "$CAST_BIN" ] || die "не найдена команда $CAST_CMD. Установите cast (install.sh) или укажите CAST=/путь/к/cast"
ok "$("$CAST_BIN" -v) — $CAST_BIN"
"$CAST_BIN" engines | grep -E '^(✓|✗)|также установлен' || true
"$CAST_BIN" engines | grep -q '^✗' && die "не все движки установлены (см. выше): sudo bash install.sh"

step "Docker"
if docker info >/dev/null 2>&1; then DOCKER=(docker); ok "Docker доступен без sudo"
elif "${SUDO[@]}" docker info >/dev/null 2>&1; then DOCKER=("${SUDO[@]}" docker); ok "Docker доступен через sudo"
else die "нет доступа к Docker: запущен ли он (systemctl status docker)?"; fi

step "Образы для проверок"
for image in alpine:3.19 nginx:alpine; do
    "${DOCKER[@]}" pull -q "$image" >/dev/null || die "не удалось скачать $image (нет интернета?)"
    ok "$image"
done

step "База уязвимостей Trivy"
TRIVY="$(command -v trivy || true)"
if [ -n "$TRIVY" ]; then
    # тот же кэш, что у cast без sudo; под sudo cast держит свой кэш в /var/cache/cast/trivy
    "$TRIVY" image --download-db-only --quiet && ok "база скачана или уже свежая"
else
    warn "trivy не найден в PATH, базу пропускаю (cast скачает её при первой проверке)"
fi

if [ "$WANT_CLUSTER" -eq 0 ]; then
    step "Кластер Kubernetes"
    warn "не поднимаю (нужен --cluster). run.sh тогда пропустит проверку кластера."
    printf '\nГотово. Запуск проверок: bash realtests/run.sh\n'
    exit 0
fi

step "Кластер Kubernetes ($CLUSTER)"
avail_kb=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
printf 'памяти всего %s, свободно %s; диска свободно %s\n' \
    "$(free -h | awk '/Mem/{print $2}')" "$(free -h | awk '/Mem/{print $7}')" "$(df -h / | awk 'NR==2{print $4}')"
if [ "$avail_kb" -lt 1200000 ]; then
    warn "свободной памяти меньше 1,2 ГБ: кластер может подниматься очень долго или упасть."
    printf 'Закройте тяжёлые программы. Продолжить? [y/N] '; read -r ans
    [ "$ans" = y ] || exit 1
fi

mkdir -p "$BIN" "$HOME/.kube"
if [ ! -x "$BIN/kind" ]; then
    echo "скачиваю kind $KIND_VERSION"
    curl -fsSLo "$BIN/kind" "https://kind.sigs.k8s.io/dl/$KIND_VERSION/kind-linux-amd64"
    sum="$(curl -fsSL "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64.sha256sum" | cut -d' ' -f1)"
    echo "$sum  $BIN/kind" | sha256sum -c --quiet || { rm -f "$BIN/kind"; die "kind: не сошлась sha256"; }
    chmod +x "$BIN/kind"
fi
if [ ! -x "$BIN/kubectl" ]; then
    echo "скачиваю kubectl $KUBECTL_VERSION"
    curl -fsSLo "$BIN/kubectl" "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl"
    sum="$(curl -fsSL "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl.sha256")"
    echo "$sum  $BIN/kubectl" | sha256sum -c --quiet || { rm -f "$BIN/kubectl"; die "kubectl: не сошлась sha256"; }
    chmod +x "$BIN/kubectl"
fi
ok "kind и kubectl в $BIN"

# kind работает с Docker: от имени того, у кого есть к нему доступ
KIND=("$BIN/kind"); [ "${DOCKER[0]}" = docker ] || KIND=("${SUDO[@]}" "$BIN/kind")
if ! "${KIND[@]}" get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "создаю кластер: 1 узел (первый раз качается образ узла ~1 ГБ, несколько минут)"
    "${KIND[@]}" create cluster --name "$CLUSTER" --config "$HERE/k8s/kind-minimal.yaml" --wait 5m
fi
if [ -f "$HOME/.kube/config" ] && [ ! -f "$HOME/.kube/config.cast-backup" ]; then
    cp "$HOME/.kube/config" "$HOME/.kube/config.cast-backup"
    ok "прежний ~/.kube/config сохранён в ~/.kube/config.cast-backup"
fi
"${KIND[@]}" get kubeconfig --name "$CLUSTER" >"$HOME/.kube/config"
chmod 600 "$HOME/.kube/config"
"$BIN/kubectl" get nodes
"$BIN/kubectl" apply -f "$HERE/k8s/insecure-workload.yaml"
"$BIN/kubectl" -n cast-demo rollout status deploy/insecure-web --timeout=5m || \
    warn "под ещё не запустился (медленная сеть или мало памяти); скан всё равно увидит его настройки"
ok "кластер $CLUSTER готов"

printf '\nГотово. Запуск проверок: bash realtests/run.sh\nУбрать кластер: bash realtests/teardown.sh\n'
