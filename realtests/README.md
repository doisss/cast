# realtests — проверка cast на настоящих целях

Обычные тесты (`pytest`) подставляют заранее сохранённые ответы Trivy и Docker Bench.
Здесь всё по-настоящему: настоящие образы, контейнер, файлы, кластер Kubernetes.

Порядок:

```bash
bash realtests/setup.sh      # один раз: поставить недостающее, скачать образы и базу Trivy, поднять кластер
bash realtests/run.sh        # все команды demo.sh all (или: run.sh basic / run.sh medium)
bash realtests/teardown.sh   # убрать кластер (с --all — ещё kind, kubectl и образы)
```

На чистом Debian/Ubuntu/Kali `setup.sh` сам ставит то, чего нет: curl, cast с Trivy и
Docker Bench (через `install.sh --local` из этой же копии репозитория) и Docker.
Без кластера: `setup.sh --no-cluster`, тогда `run.sh` пропускает его проверку.

| Скрипт | Что делает |
|---|---|
| `setup.sh` | ставит или проверяет cast, Trivy, Docker Bench и Docker; скачивает `alpine:3.19`, `nginx:alpine` и базу Trivy; ставит kind и kubectl в `~/.cache/cast-realtests/bin` и поднимает кластер `cast-test` из одного узла с намеренно небезопасной нагрузкой (`k8s/insecure-workload.yaml`) |
| `run.sh` | запускает `demo/demo.sh` и проверяет, что ни одна команда не вернула код 2 («проверка не выполнена»). Коды 0 и 1 зависят от свежести базы уязвимостей, поэтому не проверяются |
| `teardown.sh` | удаляет кластер и возвращает прежний `~/.kube/config` |

Основные команды (`run.sh basic`): образ, запущенный контейнер, Dockerfile, папка проекта,
Docker-хост, `cast engines`. Средние (`run.sh medium`): архив образа, Kubernetes, Terraform,
Helm, docker-compose, корневая ФС, git-репозиторий, SBOM, образ диска ВМ, кластер.

Что нужно: Linux (Debian, Ubuntu или Kali; amd64 или arm64), sudo (Docker Bench проверяет хост
от root), интернет. Для кластера — не меньше 4 ГБ памяти и ~2 ГБ на диске.

Проверить другую сборку cast, а не ту, что в PATH: `CAST=/путь/к/cast bash realtests/run.sh`.
