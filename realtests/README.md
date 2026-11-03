# realtests — проверка cast на настоящих целях

Обычные тесты (`pytest`) подставляют заранее сохранённые ответы Trivy и Docker Bench.
Здесь всё по-настоящему: настоящие образы, контейнер, файлы, кластер Kubernetes.

Порядок:

```bash
bash realtests/setup.sh --cluster   # один раз: проверить движки, скачать образы и базу Trivy, поднять кластер
bash realtests/run.sh               # все команды (или: run.sh basic / run.sh medium)
bash realtests/teardown.sh          # убрать кластер (с --all — ещё kind, kubectl и образы)
```

Без `--cluster` кластер не поднимается, а `run.sh` пропускает его проверку.

| Скрипт | Что делает |
|---|---|
| `setup.sh` | проверяет cast, Trivy, Docker Bench и Docker; скачивает `alpine:3.19`, `nginx:alpine` и базу Trivy; с `--cluster` ставит kind и kubectl в `~/.cache/cast-realtests/bin` и поднимает кластер `cast-test` из одного узла с намеренно небезопасной нагрузкой (`k8s/insecure-workload.yaml`) |
| `run.sh` | запускает `demo/demo.sh` и проверяет, что ни одна команда не вернула код 2 («проверка не выполнена»). Коды 0 и 1 зависят от свежести базы уязвимостей, поэтому не проверяются |
| `teardown.sh` | удаляет кластер и возвращает прежний `~/.kube/config` |

Основные команды (`run.sh basic`): образ, запущенный контейнер, Dockerfile, папка проекта,
Docker-хост, `cast engines`. Средние (`run.sh medium`): архив образа, Kubernetes, Terraform,
Helm, docker-compose, корневая ФС, git-репозиторий, SBOM, образ диска ВМ, кластер.

Что нужно: Linux, Docker, sudo (Docker Bench проверяет хост от root), интернет. Для кластера —
не меньше 4 ГБ памяти и ~2 ГБ на диске.

Проверить другую сборку cast, а не ту, что в PATH: `CAST=/путь/к/cast bash realtests/run.sh`.
