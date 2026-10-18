#!/usr/bin/env bash
#
# cast — установщик. Одна команда ставит саму утилиту и сканеры, которыми она
# пользуется под капотом.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/doisss/cast/main/install.sh)
#
# (Для форка: CAST_REPO=аккаунт/репозиторий.)
#
# Из локальной копии репозитория (удобно проверять до публикации):
#
#   bash install.sh --local
#
# Что и куда ставится (раскладка, принятая в Linux):
#
#   /opt/cast/venv/               отдельное виртуальное окружение Python с cast
#   /usr/local/bin/cast           команда cast  (основное имя)
#   /usr/local/bin/sarbar         команда sarbar (алиас)
#   Trivy                         пакетом из официального apt-репозитория Aqua Security
#                                 (обновляется обычным `apt upgrade`)
#   /opt/docker-bench-security/   Docker Bench for Security, зафиксированная версия
#
# Чего скрипт НЕ делает: не ставит Docker (только проверяет и подсказывает), не
# добавляет вас в группу docker (она равна root-доступу — решать вам), не трогает
# ядро и не загружает драйверов.
#
# Опции: см. `bash install.sh --help`.
#
set -euo pipefail

REPO="${CAST_REPO:-doisss/cast}"
REF="${CAST_REF:-main}"
DB_REF="${DOCKER_BENCH_REF:-v1.6.1}"
ARCHIVE_URL="${CAST_ARCHIVE_URL:-}"

CAST_HOME="/opt/cast"
BENCH_HOME="/opt/docker-bench-security"
BIN_DIR="/usr/local/bin"

LOCAL=0 DRY=0 FORCE=0 WANT_TRIVY=1 WANT_BENCH=1 WANT_DOCKER=0

# ------------------------------------------------------------------ вывод
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; Z=$'\033[0m'; else B=""; G=""; Y=""; R=""; Z=""; fi
step() { printf '\n%s==> %s%s\n' "$B" "$*" "$Z"; }
ok()   { printf '    %s✓%s %s\n' "$G" "$Z" "$*"; }
warn() { printf '    %s!%s %s\n' "$Y" "$Z" "$*" >&2; }
die()  { printf '%sОшибка:%s %s\n' "$R" "$Z" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
cast — установщик (cast + Trivy + Docker Bench).

  bash <(curl -fsSL https://raw.githubusercontent.com/doisss/cast/main/install.sh)
  bash install.sh --local          из локальной копии репозитория

Опции:
  --local              ставить cast из папки, где лежит этот скрипт
  --ref REF            ветка или тег репозитория (по умолчанию main)
  --skip-trivy         не ставить Trivy
  --skip-docker-bench  не ставить Docker Bench
  --with-docker        поставить Docker (пакет docker.io), если его нет
  --force              перезаписать чужие команды cast/sarbar в /usr/local/bin
  --dry-run            ничего не менять, только показать, что было бы сделано
  -h, --help           эта справка

Переменные: CAST_REPO (аккаунт/репозиторий, по умолчанию doisss/cast), CAST_REF, CAST_ARCHIVE_URL, DOCKER_BENCH_REF, DOCKER_BENCH_URL.
EOF
}

# ---------------------------------------------------------------- аргументы
# Именно while + shift: в for-цикле список аргументов фиксируется заранее.
while [ "$#" -gt 0 ]; do
    case "$1" in
        --local)             LOCAL=1 ;;
        --ref)               [ "$#" -ge 2 ] || die "--ref требует значение"; REF="$2"; shift ;;
        --skip-trivy)        WANT_TRIVY=0 ;;
        --skip-docker-bench) WANT_BENCH=0 ;;
        --with-docker)       WANT_DOCKER=1 ;;
        --force)             FORCE=1 ;;
        --dry-run)           DRY=1 ;;
        -h|--help)           usage; exit 0 ;;
        *)                   die "неизвестная опция: $1 (см. --help)" ;;
    esac
    shift
done

# ------------------------------------------------------------ привилегии
SUDO=()
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then SUDO=(sudo)
    elif [ "$DRY" -eq 0 ]; then die "нужен root или sudo"; fi
fi

# run: выполнить команду (или только показать её при --dry-run)
run() {
    if [ "$DRY" -eq 1 ]; then printf '    [dry-run] %s\n' "$*"; else "$@"; fi
}
# priv: то же, но с правами root
priv() { run ${SUDO[@]+"${SUDO[@]}"} "$@"; }

TMP=""
cleanup() {
    [ -n "$TMP" ] || return 0
    # pip под sudo мог создать в папке сборки файлы root — тогда удаляем тоже от root
    rm -rf "$TMP" 2>/dev/null || "${SUDO[@]}" rm -rf "$TMP" 2>/dev/null || true
    return 0
}
trap cleanup EXIT
TMP="$(mktemp -d)"

# ------------------------------------------------------------ проверки
step "Проверка системы"
[ "$(uname -s)" = "Linux" ] || die "установщик рассчитан на Linux (у вас: $(uname -s))"

HAVE_APT=0; command -v apt-get >/dev/null 2>&1 && HAVE_APT=1
command -v curl >/dev/null 2>&1 || die "нужен curl"
command -v tar  >/dev/null 2>&1 || die "нужен tar"

PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "не найден python3"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "нужен Python 3.11 или новее (у вас: $("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])'))"
ok "Python $("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])'), apt: $([ "$HAVE_APT" -eq 1 ] && echo да || echo нет)"

if ! "$PY" -c 'import venv, ensurepip' >/dev/null 2>&1; then
    if [ "$HAVE_APT" -eq 1 ]; then
        warn "не хватает python3-venv — ставлю"
        priv apt-get install -y python3-venv
    else
        die "в вашем Python нет модуля venv; поставьте его средствами дистрибутива"
    fi
fi

# ------------------------------------------------------------ Docker
step "Docker"
if command -v docker >/dev/null 2>&1; then
    ok "найден: $(docker --version 2>/dev/null || echo docker)"
elif [ "$WANT_DOCKER" -eq 1 ] && [ "$HAVE_APT" -eq 1 ]; then
    priv apt-get install -y docker.io
    priv systemctl enable --now docker || warn "не удалось включить службу docker"
else
    warn "Docker не найден. cast сканирует образы Docker, поэтому он нужен."
    warn "Поставить: sudo apt-get install -y docker.io   (или перезапустите установщик с --with-docker)"
fi

# ------------------------------------------------------------ Trivy
install_trivy() {
    if command -v trivy >/dev/null 2>&1; then
        ok "уже установлен: $(trivy --version 2>/dev/null | head -1)"
        return
    fi
    if [ "$HAVE_APT" -ne 1 ]; then
        warn "Автоустановка Trivy поддерживает Debian/Ubuntu/Kali (apt)."
        warn "Установите вручную: https://trivy.dev/latest/getting-started/installation/ — cast найдёт его в PATH."
        return
    fi
    if [ "$DRY" -eq 1 ]; then
        printf '    [dry-run] добавить ключ и репозиторий aquasecurity/trivy-repo (suite "generic"), apt-get install trivy\n'
        return
    fi
    # Репозиторий Trivy публикует единый suite "generic": `lsb_release -sc` на Kali
    # вернул бы kali-rolling, которого в репозитории нет.
    priv apt-get install -y wget apt-transport-https gnupg ca-certificates
    curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor | "${SUDO[@]+"${SUDO[@]}"}" tee /usr/share/keyrings/trivy.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        | "${SUDO[@]+"${SUDO[@]}"}" tee /etc/apt/sources.list.d/trivy.list >/dev/null
    priv apt-get update
    priv apt-get install -y trivy
    ok "установлен: $(trivy --version 2>/dev/null | head -1)"
}

setup_cache() {
    # один кэш базы уязвимостей на всех пользователей (иначе у root и у вас по ~1 ГБ)
    local dir=/var/cache/cast/trivy
    if [ "$DRY" -eq 1 ]; then
        printf '    [dry-run] создать %s (группа docker, права 2775)\n' "$dir"; return
    fi
    priv mkdir -p "$dir"
    if getent group docker >/dev/null 2>&1; then
        priv chgrp -R docker /var/cache/cast; priv chmod -R g+rwX /var/cache/cast; priv chmod 2775 /var/cache/cast "$dir"
    else
        priv chmod 755 /var/cache/cast "$dir"
    fi
    ok "общий кэш Trivy: $dir"
    # чтобы и обычный `trivy` (вне cast) брал тот же кэш, а не качал свою копию базы;
    # при удалении cast этот файл удаляется, и trivy возвращается к ~/.cache/trivy
    priv sh -c "printf '%s\n' '# cast: общий кэш базы уязвимостей Trivy' '[ -w /var/cache/cast/trivy ] && export TRIVY_CACHE_DIR=/var/cache/cast/trivy' > /etc/profile.d/cast.sh"
    ok "переменная TRIVY_CACHE_DIR: /etc/profile.d/cast.sh (действует после нового входа в систему)"
}
step "Trivy (поиск уязвимостей в образе)"
if [ "$WANT_TRIVY" -eq 1 ]; then install_trivy; setup_cache; else ok "пропущено (--skip-trivy)"; fi

# ------------------------------------------------------------ Docker Bench
install_docker_bench() {
    local marker="$BENCH_HOME/.cast-ref"
    if [ -f "$BENCH_HOME/docker-bench-security.sh" ] && [ "$(cat "$marker" 2>/dev/null || true)" = "$DB_REF" ]; then
        ok "уже установлен ($DB_REF) в $BENCH_HOME"
        return
    fi
    if [ "$DRY" -eq 1 ]; then
        printf '    [dry-run] скачать docker-bench-security %s и распаковать в %s\n' "$DB_REF" "$BENCH_HOME"
        return
    fi
    curl -fsSL "${DOCKER_BENCH_URL:-https://github.com/docker/docker-bench-security/archive/refs/tags/${DB_REF}.tar.gz}" \
        -o "$TMP/bench.tgz" || die "не удалось скачать Docker Bench ${DB_REF}"
    mkdir -p "$TMP/bench"
    tar -xzf "$TMP/bench.tgz" -C "$TMP/bench" --strip-components=1
    [ -f "$TMP/bench/docker-bench-security.sh" ] || die "в архиве Docker Bench нет docker-bench-security.sh"

    priv rm -rf "$BENCH_HOME"
    priv mkdir -p "$BENCH_HOME"
    priv cp -R "$TMP/bench/." "$BENCH_HOME/"
    # Скрипт запускается от root, поэтому файлы должны принадлежать root, а не
    # пользователю, который запустил установщик.
    priv chown -R root:root "$BENCH_HOME"
    # скрипт при старте создаёт ./log; пусть папка уже существует
    priv mkdir -p "$BENCH_HOME/log"
    priv chmod 755 "$BENCH_HOME/docker-bench-security.sh"
    echo "$DB_REF" | "${SUDO[@]+"${SUDO[@]}"}" tee "$marker" >/dev/null
    ok "установлен ($DB_REF) в $BENCH_HOME"
}
step "Docker Bench for Security (проверка настроек Docker по CIS)"
if [ "$WANT_BENCH" -eq 1 ]; then install_docker_bench; else ok "пропущено (--skip-docker-bench)"; fi

# ------------------------------------------------------------ cast
fetch_source() {
    local dest="$TMP/src"
    mkdir -p "$dest"
    if [ "$LOCAL" -eq 1 ]; then
        local here
        here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        [ -f "$here/pyproject.toml" ] || die "--local: рядом со скриптом нет pyproject.toml ($here)"
        tar -C "$here" --exclude=.venv --exclude=.git --exclude=__pycache__ --exclude='*.egg-info' \
            --exclude=build --exclude=.pytest_cache -cf - . | tar -C "$dest" -xf -
    else
        local url="${ARCHIVE_URL:-https://github.com/${REPO}/archive/${REF}.tar.gz}"
        curl -fsSL "$url" -o "$TMP/cast.tgz" || die "не удалось скачать $url (проверьте репозиторий и ветку)"
        tar -xzf "$TMP/cast.tgz" -C "$dest" --strip-components=1
        [ -f "$dest/pyproject.toml" ] || die "в скачанном архиве нет pyproject.toml"
    fi
    printf '%s' "$dest"
}

install_cast() {
    if [ "$DRY" -eq 1 ]; then
        printf '    [dry-run] получить исходники (%s), создать %s/venv, pip install\n' \
            "$([ "$LOCAL" -eq 1 ] && echo "локальная папка" || echo "${ARCHIVE_URL:-github.com/${REPO}@${REF}}")" "$CAST_HOME"
        printf '    [dry-run] ссылки %s/cast и %s/sarbar -> %s/venv/bin/\n' "$BIN_DIR" "$BIN_DIR" "$CAST_HOME"
        return
    fi
    local src
    src="$(fetch_source)"
    priv mkdir -p "$CAST_HOME"
    [ -x "$CAST_HOME/venv/bin/python" ] || priv "$PY" -m venv "$CAST_HOME/venv"
    priv "$CAST_HOME/venv/bin/pip" install --quiet --upgrade --force-reinstall "$src"
    ok "cast установлен в $CAST_HOME/venv"

    local name dest target
    for name in cast sarbar; do
        dest="$BIN_DIR/$name"; target="$CAST_HOME/venv/bin/$name"
        if [ -e "$dest" ] || [ -L "$dest" ]; then
            if [ "$(readlink -f "$dest")" = "$(readlink -f "$target")" ]; then
                ok "$dest уже указывает на cast"; continue
            fi
            if [ "$FORCE" -eq 1 ]; then
                priv rm -f "$dest"
            else
                warn "$dest уже существует и это не cast — не трогаю (перезаписать: --force)"
                continue
            fi
        fi
        priv ln -s "$target" "$dest"
        ok "команда $name -> $target"
    done
}
step "cast"
install_cast

# ------------------------------------------------------------ итог
step "Проверка результата"
if [ "$DRY" -eq 1 ]; then
    ok "dry-run: ничего не изменено"
    exit 0
fi

"$CAST_HOME/venv/bin/python" - <<'PY'
from cast.scanners import ALL_SCANNERS
import sys
tty = sys.stdout.isatty()
for cls in ALL_SCANNERS:
    s = cls()
    found = s.is_available()
    mark = ("\033[32m✓\033[0m" if tty else "✓") if found else ("\033[31m✗\033[0m" if tty else "✗")
    print(f"    {mark} {s.name:<13} {'найден' if found else 'НЕ найден'}")
PY

for name in cast sarbar; do
    found="$(command -v "$name" || true)"
    if [ -n "$found" ] && [ "$(readlink -f "$found")" != "$(readlink -f "$CAST_HOME/venv/bin/$name")" ]; then
        warn "в PATH раньше стоит другая команда '$name': $found"
        if [ "$found" = "$BIN_DIR/$name" ]; then
            warn "это не cast. Заменить её нашей: перезапустите установщик с --force"
        else
            warn "вероятно, это старая установка: удалите её (см. README) или запускайте $BIN_DIR/$name"
        fi
        warn "точно наш cast: $CAST_HOME/venv/bin/$name"
    fi
done

printf '\n%sГотово.%s Попробуйте:\n\n    sudo cast scan alpine:3.19\n    cast -h\n\n' "$G$B" "$Z"
printf 'sudo нужен, потому что Docker и Docker Bench требуют доступа к демону Docker.\n'
