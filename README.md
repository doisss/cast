# cast

cast — программа для командной строки, которая проверяет безопасность Docker:
образы, контейнеры, Dockerfile, папки с кодом, конфигурации Kubernetes и сам
компьютер, на котором стоит Docker.

Сама cast уязвимости не ищет. Она запускает две известные бесплатные программы:

- **Trivy** — ищет уязвимые версии пакетов, ошибки в настройках и забытые пароли;
- **Docker Bench for Security** — проверяет Docker по рекомендациям CIS.

Дальше cast собирает их ответы в одну понятную таблицу на русском языке, убирает
повторы и подсказывает, что исправлять в первую очередь. cast показывает только то,
что нашли сами программы, и ничего не добавляет от себя.

Команду можно вызывать двумя именами: `cast` или `sarbar`, это одно и то же.

## Установка

Нужен Linux с Python 3.11 или новее, `curl` и `tar`. Скопируйте в терминал:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/doisss/cast/main/install.sh)
```

Установщик поставит cast и Docker Bench. На Debian, Ubuntu и Kali он сам поставит
и Trivy, на других дистрибутивах Trivy нужно поставить отдельно
([инструкция Trivy](https://trivy.dev/latest/getting-started/installation/)).
Docker он не ставит: если Docker нет, установщик подскажет, как его поставить.
Запускать установщик повторно можно, ничего не сломается.

Куда всё ставится (это обычные места для Linux):

| Что | Куда |
|---|---|
| cast | `/opt/cast` |
| команды `cast` и `sarbar` | `/usr/local/bin` |
| Docker Bench | `/opt/docker-bench-security` |
| Trivy | `/usr/bin` (ставится через apt) |

Проверить, что всё на месте:

```bash
cast -v          # версия cast
cast engines     # какие программы-движки найдены и где они лежат
```

Удалить: `sudo bash uninstall.sh`. Чтобы удалить и Trivy, добавьте `--with-trivy`.

### Версии

Список версий и что в них изменилось — на странице
[Releases](https://github.com/doisss/cast/releases) и в файле [CHANGELOG.md](CHANGELOG.md).

Посмотреть все версии и поставить нужную:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/doisss/cast/main/install.sh) --list-versions
bash <(curl -fsSL https://raw.githubusercontent.com/doisss/cast/main/install.sh) --version v0.1.0
```

Новая версия ставится вместо старой, а не рядом с ней.

## Как пользоваться

Главная команда одна: `cast scan` и то, что нужно проверить. Что именно ему дали,
cast поймёт сам и сам выберет программу для проверки.

```bash
cast scan alpine:3.19        # образ Docker
cast scan 12b1e6c27fd6       # запущенный контейнер (по ID)
cast scan Dockerfile         # Dockerfile
cast scan ./myapp            # папка с проектом
cast scan host               # текущая машина с Docker
```

Что ещё можно проверить:

```bash
cast scan deploy.yaml        # файл Kubernetes
cast scan main.tf            # файл Terraform
cast scan ./chart            # Helm-чарт
cast scan stack.yaml         # шаблон CloudFormation
cast scan docker-compose.yml # docker-compose
cast scan alpine.tar         # образ, сохранённый в файл (docker save)
cast scan sbom.cdx.json      # список компонентов SBOM (CycloneDX, SPDX)
cast scan /                  # вся файловая система текущей машины
cast scan https://github.com/aquasecurity/trivy-ci-test   # git-репозиторий
cast scan disk.qcow2         # образ диска виртуальной машины
cast scan cluster            # кластер Kubernetes
```

Если cast понял цель неправильно, скажите ему прямо, что это:

```bash
cast scan image alpine:3.19
cast scan container my-container
cast scan config ./k8s
```

Такие же подсказки есть для `dockerfile`, `fs`, `rootfs`, `archive`, `sbom`, `vm`, `repo`.

### Полезные флаги

```bash
cast scan alpine:3.19 -f html           # сохранить отчёт в HTML
cast scan alpine:3.19 -f json,html      # сразу в JSON и HTML
cast scan alpine:3.19 -o report.html    # сохранить под своим именем
cast scan alpine:3.19 --top 0           # показать все строки (по умолчанию 25)
cast scan 12b1e6c27fd6 -e trivy         # проверить контейнер через Trivy, а не Docker Bench
cast scan myapp:1.0 --requirements ./requirements.txt   # учесть, какие пакеты важны приложению
cast -h                                 # справка
```

### Как читать результат

У находок Trivy есть уровень опасности: CRITICAL, HIGH, MEDIUM, LOW.

У Docker Bench уровней нет, и cast их не придумывает. Он показывает статусы:

- **WARN** — рекомендация нарушена, стоит исправить;
- **NOTE** — решать вам;
- **INFO** — просто информация или проверка, которую надо сделать руками;
- **PASS** — всё в порядке.

Чем закончилась команда (это видно по коду выхода):

| Код | Что значит |
|---|---|
| 0 | проверка прошла, критичных находок нет |
| 1 | есть хотя бы одна критичная находка |
| 2 | проверку выполнить не удалось |
| 130 | вы остановили проверку (Ctrl+C) |

Если какая-то программа не установлена или сломалась, cast не падает. Он прямо
пишет, что проверка не выполнена, и не выдаёт чужие результаты за свои.

### Что важно знать

- Docker Bench нужен доступ к Docker. Запускайте `sudo cast scan ...` или добавьте
  себя в группу `docker`.
- При самом первом `cast scan` cast один раз дополнительно проверит текущую машину.
  Потом это делается только по команде `cast scan host`.
- Проверка всей системы, репозитория, диска ВМ или кластера идёт долго, до 30 минут.
- При проверке `/` Trivy может скачать большую базу Java (больше 700 МБ). Если в
  `/tmp` мало места, запускайте так: `TMPDIR=~/tmp-trivy cast scan /`. Папку
  `~/tmp-trivy` создайте заранее.

## Показ всех возможностей

```bash
bash demo/demo.sh
```

Скрипт сам подготовит всё нужное и по очереди запустит все виды проверок. Для каждой
он покажет команду, результат и время, а в конце выведет общую таблицу.
Подробности: `bash demo/demo.sh --help`.

## Для разработчиков

Как собрать и запустить тесты:

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
pytest -v
```

Для тестов Trivy и Docker Bench не нужны: вместо них подставляются заранее
сохранённые ответы. Проверка на настоящих целях (образы, контейнер, кластер) —
в папке [`realtests/`](realtests/README.md).

Ветки: вся работа идёт в `dev`, в `main` попадает только выпущенная версия (вместе
с меткой `vX.Y.Z`). Поэтому главная страница, кнопка «Download ZIP» и однострочник
установки всегда дают последнюю выпущенную версию.

Как устроен код:

```
src/cast/
├── cli.py            команды и флаги
├── targets.py        как cast понимает, что ему дали
├── pipeline.py       запуск проверок и сбор результатов
├── models.py         единый вид находки
├── dedup.py          удаление повторов
├── scoring.py        расчёт приоритета
├── context.py        чтение requirements.txt
├── state.py          отметка «текущая машина уже проверялась»
├── scanners/         обёртки над Trivy и Docker Bench
└── report/           вывод в терминал, JSON и HTML
```

Чтобы подключить новую программу-сканер (например, Grype), достаточно добавить
файл в `scanners/`. Остальной код менять не нужно. Логика проверки отделена от
вывода, поэтому позже к ней можно подключить веб-интерфейс.

## Что дальше

Пока не сделано:

- работа без интернета с сохранённой базой уязвимостей;
- история проверок и запуск из CI;
- веб-интерфейс.
