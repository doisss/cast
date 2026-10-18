# cast

CLI-утилита — оболочка-оркестратор над существующими сканерами безопасности
контейнеров. Сама не ищет уязвимости с нуля, а вызывает Trivy и Docker Bench
for Security, нормализует их разнородный вывод к единой схеме, убирает
дубликаты и пересчитывает приоритет находок с учётом контекста конкретного
приложения.

Вызывается двумя равнозначными именами — `cast` и `sarbar` (указаны в
`pyproject.toml` как два `console_scripts`, ведущих к одной и той же функции).

## Установка

Одной командой (Linux с apt: Debian, Ubuntu, Kali). Скрипт ставит `cast`, Trivy и
Docker Bench for Security; Docker сам не ставит (только подсказывает), если его нет:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/OWNER/cast/main/install.sh)
```

(`OWNER` замените на свой аккаунт GitHub.) Раскладка по правилам Linux:

| Что | Куда |
|---|---|
| cast (изолированный venv) | `/opt/cast/venv` |
| команды `cast` и `sarbar` | `/usr/local/bin` (симлинки) |
| Docker Bench for Security v1.6.1 | `/opt/docker-bench-security` |
| Trivy | пакет apt (репозиторий aquasecurity) |

Опции: `--local` (из локальной копии), `--skip-trivy`, `--skip-docker-bench`,
`--with-docker`, `--force`, `--dry-run`, `--ref`. Повторный запуск безопасен.
Чужие команды `cast`/`sarbar` в `/usr/local/bin` не затираются без `--force`.

Удаление: `sudo bash uninstall.sh` (добавьте `--with-trivy`, чтобы убрать и Trivy).

Для разработки: `python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"`.

Если какой-то сканер не найден — `cast` не падает, а пропускает его с предупреждением.

### Как утилита находит Docker Bench

Скрипт запускается только из своей папки, поэтому `cast` ищет его так:
`CAST_DOCKER_BENCH_DIR` → `PATH` → `/opt/docker-bench-security` →
`/usr/local/share/docker-bench-security` → `~/docker-bench-security` (в том числе
домашняя папка `SUDO_USER`). Запускается с флагом `-b`. Нужен доступ к Docker-демону:
запускайте `sudo cast scan ...` или добавьте пользователя в группу `docker`.

## Использование

Команд две: `scan` (проверить цель) и `engines` (показать движки). Движок под цель
cast выбирает сам.

```bash
cast scan alpine:3.19            # образ → Trivy
cast scan 12b1e6c27fd6           # ID запущенного контейнера → Docker Bench (настройки запуска)
cast scan Dockerfile             # Dockerfile → Trivy (ошибки конфигурации)
cast scan ./myapp                # папка → Trivy (зависимости, секреты, конфигурации)
cast scan host                   # Docker-хост → Docker Bench (CIS)
cast engines                     # список движков, версии, что умеют
```

**Как cast понимает цель.** Любое имя без `./` — образ. Путь, начинающийся с `.`, `./`,
`../`, `/` или `~`, — папка. Файл `Dockerfile` (`Dockerfile.*`, `*.Dockerfile`,
`Containerfile`) — Dockerfile. Hex-ID запущенного контейнера — контейнер. `host` — хост.
Явные формы, если автоопределение не подходит: `cast scan image X`, `container X`
(по имени или ID), `dockerfile ПУТЬ`, `fs ПУТЬ`. Слова `host`, `image`, `container`,
`dockerfile`, `fs` зарезервированы.

**Выбор движка** — флаг `-e/--engine` (через запятую):

```bash
cast scan 12b1e6c27fd6 -e trivy                 # вместо Docker Bench — Trivy по образу контейнера
cast scan 12b1e6c27fd6 -e docker-bench,trivy    # оба; главный (Docker Bench) выводится первым
```

Если движок не умеет такую цель, cast так и скажет. Для контейнера по умолчанию
запускается только Docker Bench, а в конце отчёта стоит пометка, что уязвимости внутри
образа не проверялись.

**Отчёты.** Таблица в консоли выводится всегда. Файлы добавляются флагами:

```bash
cast scan alpine:3.19 -f html            # файл создастся в текущей папке, имя сгенерируется само
cast scan alpine:3.19 -f json,html       # сразу два файла
cast scan alpine:3.19 -o my.html         # своё имя; формат определяется по расширению
cast scan alpine:3.19 --top 0            # показать в консоли все строки (по умолчанию 25)
cast scan myapp:1.0 --requirements ./requirements.txt   # приоритизация по зависимостям
```

**Docker Bench: статусы, а не уровни.** У Docker Bench нет уровней критичности, и cast их не
выдумывает: показываются статусы PASS / WARN / INFO / NOTE как есть. WARN — нарушение
рекомендации, NOTE — решение за вами, INFO — информация или ручная проверка, PASS — в
порядке (в таблице не показан, только в счётчике). У замечаний указано, к чему они
относятся (например, имя контейнера). Уровни критичности (CRITICAL…LOW) есть только
у находок Trivy.

**Проверка хоста при первом запуске.** При самом первом `cast scan` дополнительно один раз
показывается проверка Docker-хоста; дальше — только по `cast scan host`. Метка хранится в
`/var/lib/cast/host-checked` (или `~/.local/state/cast/`, если нет прав).

Коды возврата: `0` — всё отработало, критичных нет; `1` — найдена хотя бы одна
`critical`; `2` — проверка не выполнена (главный движок упал, цель указана неверно);
`130` — прервано по Ctrl+C.

Если главный движок не отработал, cast так и пишет и не выдаёт результаты другого
движка за результаты проверки.

## Архитектура

```
src/cast/
├── cli.py              тонкий слой argparse поверх pipeline.run_scan(); команды scan и engines
├── targets.py          определение цели: образ / контейнер / Dockerfile / папка / host
├── state.py            метка «проверка хоста уже показывалась»
├── pipeline.py          оркестрация: опрашивает сканеры, запускает dedup/scoring
├── models.py            единая схема находки (Finding) + Severity
├── context.py           ScanContext — парсинг requirements.txt для приоритизации
├── dedup.py              дедупликация находок от разных инструментов
├── scoring.py            собственный алгоритм приоритизации (ключевая логика)
├── scanners/
│   ├── base.py            абстрактный интерфейс Scanner — контракт для плагинов
│   ├── trivy.py            обёртка над Trivy (статический анализ, JSON)
│   └── docker_bench.py     обёртка над Docker Bench (текстовый вывод)
└── report/
    ├── sections.py         разделы отчёта по движкам (общие для console/json/html)
    ├── console.py          рендер в терминал (rich)
    ├── json_report.py      рендер в JSON
    ├── html_report.py      рендер в HTML (Jinja2)
    └── templates/report.html.jinja
```

**Почему так разложено.** `pipeline.py` ничего не знает о том, как устроен
Trivy или Docker Bench — он лишь опрашивает список объектов, реализующих
интерфейс `Scanner` (`scanners/base.py`). Это значит, что добавление нового
инструмента (например, Grype) не требует правок нигде,
кроме создания нового файла `scanners/grype.py` и добавления класса в
`scanners/__init__.py:ALL_SCANNERS`.

Логика анализа (`pipeline.run_scan()`) полностью отделена от способа вывода
результата — она возвращает структурированный `ScanResult`, а не печатает
текст. Это сознательное решение ради будущего расширения: тот же самый
`run_scan()` можно вызвать из веб-интерфейса (например, Streamlit-дашборда)
без единой правки в этом слое — поменяется только то, что `cli.py` заменится
на `app.py`, использующий те же функции.

## Тесты

```bash
pytest -v
```

Тесты не требуют установленных Trivy/Docker Bench — обращения к subprocess
подменяются через `unittest.mock`, а парсеры проверяются на реалистичных
фикстурах вывода (`tests/fixtures_trivy.py`). Пайплайн целиком тестируется
через `FakeScanner` (`tests/test_pipeline.py`) — так проверяется именно
*ваша* логика (оркестрация, дедупликация, скоринг), а не правильность
работы самого Trivy.

## Статус MVP / что дальше

Реализовано:
- [x] Оркестрация Trivy + Docker Bench с graceful degradation при сбое/отсутствии
- [x] Нормализация в единую схему `Finding`
- [x] Дедупликация по `(check_id, package)`
- [x] Контекстная приоритизация по `requirements.txt`
- [x] Вывод: консоль (rich) / JSON / HTML

Не реализовано (сознательно вне MVP, см. обсуждение в ВКР):
- [ ] Офлайн-режим с локальным кэшем базы уязвимостей
- [ ] Хранение истории сканирований / CI-триггер (переход от «ПО» к «системе»)
