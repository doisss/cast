#!/usr/bin/env bash
#
# cast — показ всех возможностей одной командой (для защиты и для проверки
# после установки). Скрипт сам готовит цели, печатает каждую команду cast,
# её вывод, код выхода и время, а в конце — сводную таблицу.
#
#   bash demo/demo.sh                все команды
#   bash demo/demo.sh basic          только обычные (образ, контейнер, Dockerfile,
#                                    папка, хост, движки)
#   bash demo/demo.sh medium         только новые виды целей
#   bash demo/demo.sh all --pause    пауза перед каждой командой (Enter — дальше)
#
# Опции:
#   --pause            ждать Enter перед каждой командой
#   --top N            передать cast --top N (по умолчанию таблицы целиком;
#                      у кластера всегда --top 20: там тысячи строк)
#   --skip-cluster     не сканировать кластер Kubernetes
#   --skip-repo        не сканировать git-репозиторий (нужен интернет)
#   -h, --help         эта справка
#
# Переменные: CAST — какую команду запускать (по умолчанию cast из PATH),
#             DEMO_LOG — куда писать журнал (по умолчанию ./cast-demo-ДАТА.log).
#
# Что нужно: установленный cast (install.sh ставит и Trivy, и Docker Bench),
# Docker, sudo (Docker Bench проверяет хост от root), интернет (образы, база
# Trivy, репозиторий). Для кластера — kubeconfig с доступом к кластеру.
# Сканирование корня «/» не показывается: оно идёт до 30 минут.
#
# Скрипт создаёт только своё: временную папку с целями и контейнер
# cast-demo-web (nginx:alpine). При выходе удаляет и то и другое.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=all PAUSE=0 TOP=0 SKIP_CLUSTER=0 SKIP_REPO=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        basic|medium|all) MODE="$1" ;;
        --pause)          PAUSE=1 ;;
        --top)            [ "$#" -ge 2 ] || { echo "--top требует число" >&2; exit 2; }; TOP="$2"; shift ;;
        --skip-cluster)   SKIP_CLUSTER=1 ;;
        --skip-repo)      SKIP_REPO=1 ;;
        -h|--help)        sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)                echo "неизвестный параметр: $1 (см. --help)" >&2; exit 2 ;;
    esac
    shift
done

# ------------------------------------------------------------------ вывод
if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; Z=$'\033[0m'
else B=""; D=""; G=""; Y=""; R=""; C=""; Z=""; fi
LOG="${DEMO_LOG:-$PWD/cast-demo-$(date +%Y%m%d-%H%M).log}"
# Вывод идёт через tee (в журнал), и cast видит не терминал, а трубу: без цветов и
# шириной 80. Поэтому ширину и цвет передаём ему явно, пока знаем, что это терминал.
CAST_ENV=()
if [ -t 1 ]; then CAST_ENV=(COLUMNS="$(tput cols 2>/dev/null || echo 120)" FORCE_COLOR=1); fi
exec > >(tee -a "$LOG") 2>&1

say()  { printf '%s\n' "$*"; }
die()  { printf '%sОшибка:%s %s\n' "$R" "$Z" "$*"; exit 2; }

CAST_CMD="${CAST:-cast}"
CAST_BIN="$(command -v "$CAST_CMD" || true)"
[ -n "$CAST_BIN" ] || die "не найдена команда $CAST_CMD. Установите cast (install.sh) или укажите CAST=/путь/к/cast"

SUDO=()
[ "$(id -u)" -eq 0 ] || SUDO=(sudo)
# Docker: без sudo, если пользователь в группе docker; иначе через sudo
if docker info >/dev/null 2>&1; then DOCKER=(docker); else DOCKER=("${SUDO[@]}" docker); fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cast-demo.XXXXXX")"
CONTAINER=""
cleanup() {
    if [ -n "$CONTAINER" ]; then "${DOCKER[@]}" rm -f cast-demo-web >/dev/null 2>&1 || true; fi
    # rootfs распакован с правами текущего пользователя, удаляется без sudo
    rm -rf "$WORK" 2>/dev/null || "${SUDO[@]}" rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
trap 'echo; echo "Прервано."; exit 130' INT

# ------------------------------------------------------------ подготовка
prep() {   # показать и выполнить подготовительную команду
    printf '%s  $ %s%s\n' "$D" "$*" "$Z"
    "$@" >/dev/null 2>"$WORK/prep.err" || { cat "$WORK/prep.err"; return 1; }
}

say "${B}cast — показ возможностей${Z}"
say "${D}$(date '+%d.%m.%Y %H:%M') · $("$CAST_BIN" -v 2>/dev/null) · $CAST_BIN · журнал: $LOG${Z}"
say ""
say "${B}Подготовка целей${Z} ${D}(в $WORK)${Z}"
cp -r "$HERE/files/." "$WORK/"

NEED_DOCKER=0
[ "$MODE" != medium ] && NEED_DOCKER=1   # контейнер для обычных команд
[ "$MODE" != basic ] && NEED_DOCKER=1    # архив образа, rootfs, диск ВМ делаются из alpine:3.19
if [ "$NEED_DOCKER" -eq 1 ]; then
    "${DOCKER[@]}" info >/dev/null 2>&1 || die "нет доступа к Docker (запущен ли он? есть ли sudo?)"
    prep "${DOCKER[@]}" pull -q alpine:3.19 || die "не удалось скачать alpine:3.19"
fi
if [ "$MODE" != medium ]; then
    prep "${DOCKER[@]}" pull -q nginx:alpine || die "не удалось скачать nginx:alpine"
    "${DOCKER[@]}" rm -f cast-demo-web >/dev/null 2>&1 || true
    prep "${DOCKER[@]}" run -d --name cast-demo-web nginx:alpine || die "не удалось запустить контейнер"
    CONTAINER="$("${DOCKER[@]}" ps -q --filter name='^cast-demo-web$')"
    [ -n "$CONTAINER" ] || die "контейнер cast-demo-web не запустился"
    say "${D}  контейнер cast-demo-web запущен, ID $CONTAINER${Z}"
fi
if [ "$MODE" != basic ]; then
    prep "${DOCKER[@]}" save -o "$WORK/alpine.tar" alpine:3.19 || die "docker save не удался"
    [ -r "$WORK/alpine.tar" ] || "${SUDO[@]}" chown "$(id -u):$(id -g)" "$WORK/alpine.tar"
    "${DOCKER[@]}" rm -f cast-demo-rootfs >/dev/null 2>&1 || true
    prep "${DOCKER[@]}" create --name cast-demo-rootfs alpine:3.19 || die "docker create не удался"
    mkdir -p "$WORK/rootfs"
    printf '%s  $ %s%s\n' "$D" "docker export cast-demo-rootfs | tar -x -C rootfs" "$Z"
    "${DOCKER[@]}" export cast-demo-rootfs | tar -x -C "$WORK/rootfs" --no-same-owner --exclude='dev/*' 2>/dev/null
    "${DOCKER[@]}" rm -f cast-demo-rootfs >/dev/null 2>&1 || true
    [ -f "$WORK/rootfs/etc/os-release" ] || die "не получилось распаковать корневую ФС alpine"
    MKFS="$(command -v mkfs.ext4 || echo /sbin/mkfs.ext4)"
    if [ -x "$MKFS" ]; then
        prep truncate -s 64M "$WORK/disk.img"
        prep "$MKFS" -q -F -d "$WORK/rootfs" "$WORK/disk.img" || rm -f "$WORK/disk.img"
    fi
fi
say "${G}  готово${Z}"

# ------------------------------------------------------------ показ
N=0; TOTAL=0
RESULTS=()   # "команда|код|секунды"
STEPS=()     # "заголовок|права|аргументы cast через \x1f"

add() { STEPS+=("$1|$2|$3"); }
US=$'\x1f'

if [ "$MODE" != medium ]; then
    add "Образ Docker по имени: уязвимые пакеты" user "scan${US}alpine:3.19"
    add "Запущенный контейнер по ID: как он запущен (Docker Bench)" root "scan${US}$CONTAINER"
    add "Dockerfile: ошибки в инструкциях сборки" user "scan${US}Dockerfile"
    add "Папка проекта: уязвимые зависимости (requirements.txt)" user "scan${US}./myapp"
    add "Docker-хост, то есть эта машина (Docker Bench, CIS)" root "scan${US}host"
    add "Какие движки установлены и что умеют" user "engines"
fi
if [ "$MODE" != basic ]; then
    add "Архив образа (docker save), Trivy: image --input" user "scan${US}alpine.tar"
    add "Манифест Kubernetes, Trivy: config" user "scan${US}deploy.yaml"
    add "Terraform, Trivy: config" user "scan${US}main.tf"
    add "Helm-чарт по файлу Chart.yaml, Trivy: config" user "scan${US}helm-chart/Chart.yaml"
    add "docker-compose, Trivy: config (проверок для compose у Trivy нет)" user "scan${US}docker-compose.yml"
    add "Корневая ФС (распакованная ОС), Trivy: rootfs" user "scan${US}./rootfs"
    [ "$SKIP_REPO" -eq 1 ] || add "Git-репозиторий по ссылке, Trivy: repository" user "scan${US}https://github.com/aquasecurity/trivy-ci-test"
    add "SBOM (список пакетов CycloneDX), Trivy: sbom" user "scan${US}sbom.cdx.json"
    [ -f "$WORK/disk.img" ] && add "Образ диска виртуальной машины, Trivy: vm (экспериментально)" user "scan${US}disk.img"
    [ "$SKIP_CLUSTER" -eq 1 ] || add "Кластер Kubernetes из kubeconfig, Trivy: kubernetes (экспериментально, несколько минут)" user "scan${US}cluster${US}--top${US}20"
fi
TOTAL=${#STEPS[@]}

cd "$WORK" || die "нет папки $WORK"
for step in "${STEPS[@]}"; do
    N=$((N + 1))
    title="${step%%|*}"; rest="${step#*|}"; who="${rest%%|*}"; argstr="${rest#*|}"
    IFS="$US" read -r -a args <<<"$argstr"
    if [ "$TOP" != 0 ] && [ "${args[0]}" = scan ] && [[ " ${args[*]} " != *" --top "* ]]; then
        args+=(--top "$TOP")
    fi
    prefix=(); shown="cast"
    if [ "$who" = root ] && [ "${#SUDO[@]}" -gt 0 ]; then prefix=(sudo); shown="sudo cast"; fi
    say ""
    say "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Z}"
    say "${C}${B} $N/$TOTAL  $title${Z}"
    if [ "$PAUSE" -eq 1 ]; then printf '%s(Enter — выполнить)%s' "$D" "$Z"; read -r _ </dev/tty; fi
    say "${B}\$ $shown ${args[*]}${Z}"
    start=$(date +%s)
    # env — потому что sudo сбрасывает переменные окружения
    "${prefix[@]}" env ${CAST_ENV[@]+"${CAST_ENV[@]}"} "$CAST_BIN" "${args[@]}"
    rc=$?
    secs=$(( $(date +%s) - start ))
    case $rc in
        0) meaning="${G}0 — проверка выполнена, critical нет${Z}" ;;
        1) meaning="${Y}1 — найдены critical${Z}" ;;
        2) meaning="${R}2 — проверка не выполнена${Z}" ;;
        130) meaning="${R}130 — прервано${Z}" ;;
        *) meaning="$rc" ;;
    esac
    say "${D}[код выхода${Z} $meaning${D} · ${secs} с]${Z}"
    RESULTS+=("$shown ${args[*]}|$rc|$secs")
done

# ------------------------------------------------------------ итог
say ""
say "${B}Итог${Z}"
printf '%-4s %-62s %5s %7s\n' "№" "Команда" "Код" "Время"
i=0
for r in "${RESULTS[@]}"; do
    i=$((i + 1))
    cmd="${r%%|*}"; rest="${r#*|}"; rc="${rest%%|*}"; secs="${rest#*|}"
    color="$G"; [ "$rc" = 1 ] && color="$Y"; [ "$rc" -ge 2 ] && color="$R"
    printf '%-4s %-62s %s%5s%s %6sс\n' "$i" "${cmd:0:62}" "$color" "$rc" "$Z" "$secs"
done
say ""
say "${D}Коды: 0 — critical нет, 1 — есть critical, 2 — проверка не выполнена.${Z}"
say "${D}Журнал: $LOG (с цветами; открыть: less -R $LOG)${Z}"
