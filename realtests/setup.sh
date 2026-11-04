#!/usr/bin/env bash
#
# Подготовка машины к реальным проверкам cast: после него bash realtests/run.sh.
# Рассчитан на чистый Debian/Ubuntu/Kali: чего нет — ставит сам (спросит пароль sudo).
#
#   bash realtests/setup.sh               подготовить всё, вместе с кластером Kubernetes
#   bash realtests/setup.sh --no-cluster  всё, кроме кластера (run.sh его пропустит)
#   bash realtests/setup.sh -h            эта справка
#
# Что делает:
#   1. ставит curl, если его нет;
#   2. если cast нет — ставит его из этой папки репозитория вместе с Trivy,
#      Docker Bench и Docker (sudo bash install.sh --local --with-docker);
#   3. если Docker нет или он не запущен — ставит пакет docker.io и запускает службу;
#   4. скачивает образы, которые нужны проверкам: alpine:3.19 и nginx:alpine;
#   5. скачивает базу уязвимостей Trivy заранее, чтобы первая проверка не ждала;
#   6. скачивает kind v0.24.0 и kubectl v1.31.0 (официальные адреса, сверка sha256)
#      в ~/.cache/cast-realtests/bin, создаёт кластер cast-test из одного узла,
#      кладёт его kubeconfig в ~/.kube/config (прежний сохраняется в
#      ~/.kube/config.cast-backup) и разворачивает одну намеренно небезопасную
#      нагрузку (k8s/insecure-workload.yaml), чтобы скану было что найти.
#      Кластеру нужно ~1,2 ГБ свободной памяти и ~2 ГБ диска.
#
# Повторный запуск ничего не ломает: что уже есть, пропускается.
# Убрать всё, что сделал этот скрипт: bash realtests/teardown.sh
#
# Переменные: CAST — какую команду проверять (по умолчанию cast из PATH).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${CAST_REALTESTS_BIN:-$HOME/.cache/cast-realtests/bin}"
KIND_VERSION=v0.24.0
KUBECTL_VERSION=v1.31.0
CLUSTER=cast-test
WANT_CLUSTER=1

for arg in "$@"; do
    case "$arg" in
        --no-cluster) WANT_CLUSTER=0 ;;
        --cluster)    WANT_CLUSTER=1 ;;   # прежний ключ: теперь кластер и так по умолчанию
        -h|--help)    sed -n '2,/^[^#]/{/^#/p}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            echo "неизвестный параметр: $arg (см. --help)" >&2; exit 2 ;;
    esac
done

if [ -t 1 ]; then G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[1m'; Z=$'\033[0m'
else G=""; Y=""; R=""; B=""; Z=""; fi
ok()   { printf '%s✓%s %s\n' "$G" "$Z" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$Z" "$*"; }
die()  { printf '%s✗ Ошибка:%s %s\n' "$R" "$Z" "$*"; exit 2; }
step() { printf '\n%s== %s%s\n' "$B" "$*" "$Z"; }

SUDO=()
if [ "$(id -u)" -ne 0 ]; then
    # на Debian, где при установке задали пароль root, sudo может не быть
    command -v sudo >/dev/null 2>&1 || die "нет sudo. Поставьте его от root (apt-get install sudo, usermod -aG sudo $USER) или запустите скрипт от root"
    SUDO=(sudo)
fi
apt_install() {
    command -v apt-get >/dev/null 2>&1 || die "нет apt-get: поставьте $* вручную"
    "${SUDO[@]}" apt-get update -qq
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
}

case "$(uname -m)" in
    x86_64)  ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *)       die "архитектура $(uname -m) не поддерживается (нужна amd64 или arm64)" ;;
esac

step "Нужные программы"
command -v curl >/dev/null 2>&1 || apt_install curl ca-certificates
ok "curl"

step "cast и движки"
CAST_CMD="${CAST:-cast}"
CAST_BIN="$(command -v "$CAST_CMD" || true)"
if [ -z "$CAST_BIN" ]; then
    [ -z "${CAST:-}" ] || die "не найдена команда $CAST (переменная CAST)"
    echo "cast не установлен — ставлю из этой папки: sudo bash install.sh --local --with-docker"
    "${SUDO[@]}" bash "$HERE/../install.sh" --local --with-docker
    hash -r
    CAST_BIN="$(command -v cast || true)"
    [ -n "$CAST_BIN" ] || die "install.sh отработал, но команды cast нет в PATH"
fi
ok "$("$CAST_BIN" -v) — $CAST_BIN"
"$CAST_BIN" engines | grep -E '^(✓|✗)|также установлен' || true
"$CAST_BIN" engines | grep -q '^✗' && die "не все движки установлены (см. выше): sudo bash install.sh --local"

step "Docker"
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker не установлен — ставлю пакет docker.io"
    apt_install docker.io
fi
if ! "${SUDO[@]}" docker info >/dev/null 2>&1; then
    echo "служба Docker не запущена — запускаю"
    "${SUDO[@]}" systemctl enable --now docker >/dev/null 2>&1 || true
    "${SUDO[@]}" docker info >/dev/null 2>&1 || die "Docker не запускается: sudo systemctl status docker"
fi
if docker info >/dev/null 2>&1; then DOCKER=(docker); ok "Docker доступен без sudo"
else DOCKER=("${SUDO[@]}" docker); ok "Docker доступен через sudo (вас нет в группе docker — так и задумано)"; fi

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
    warn "не поднимаю (--no-cluster). run.sh пропустит проверку кластера."
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
    curl -fsSLo "$BIN/kind" "https://kind.sigs.k8s.io/dl/$KIND_VERSION/kind-linux-$ARCH"
    sum="$(curl -fsSL "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-$ARCH.sha256sum" | cut -d' ' -f1)"
    echo "$sum  $BIN/kind" | sha256sum -c --quiet || { rm -f "$BIN/kind"; die "kind: не сошлась sha256"; }
    chmod +x "$BIN/kind"
fi
if [ ! -x "$BIN/kubectl" ]; then
    echo "скачиваю kubectl $KUBECTL_VERSION"
    curl -fsSLo "$BIN/kubectl" "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$ARCH/kubectl"
    sum="$(curl -fsSL "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$ARCH/kubectl.sha256")"
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
