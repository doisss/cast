#!/usr/bin/env bash
# cast — удаление. Убирает только то, что поставил install.sh.
#   sudo bash uninstall.sh              удалить cast и Docker Bench
#   sudo bash uninstall.sh --with-trivy  заодно удалить Trivy и его apt-репозиторий
set -euo pipefail

WITH_TRIVY=0
for a in "$@"; do
    case "$a" in
        --with-trivy) WITH_TRIVY=1 ;;
        -h|--help) printf 'Использование: [sudo] bash uninstall.sh [--with-trivy]\n'; exit 0 ;;
        *) printf 'Ошибка: неизвестная опция: %s\n' "$a" >&2; exit 2 ;;
    esac
done

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

# Удаляем ссылку только если она указывает на наш venv.
for name in cast sarbar; do
    link="/usr/local/bin/$name"
    if [ -L "$link" ] && [ "$(readlink "$link")" = "/opt/cast/venv/bin/$name" ]; then
        $SUDO rm -f "$link"
        printf '  удалено: %s\n' "$link"
    elif [ -e "$link" ]; then
        printf '  пропущено (не наше): %s\n' "$link"
    fi
done

if [ -f /etc/profile.d/cast.sh ]; then $SUDO rm -f /etc/profile.d/cast.sh; printf '  удалено: /etc/profile.d/cast.sh\n'; fi

for d in /opt/cast /opt/docker-bench-security /var/lib/cast /var/cache/cast; do
    if [ -d "$d" ]; then $SUDO rm -rf "$d"; printf '  удалено: %s\n' "$d"; fi
done

if [ "$WITH_TRIVY" -eq 1 ]; then
    $SUDO apt-get remove -y trivy || true
    $SUDO rm -f /etc/apt/sources.list.d/trivy.list /etc/apt/keyrings/trivy.gpg /usr/share/keyrings/trivy.gpg
    printf '  Trivy и его репозиторий удалены\n'
fi
printf 'Готово.\n'
