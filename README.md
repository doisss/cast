# CAST — Container Automated Security Testing (`sarbar`)

CLI-утилита для выпускной квалификационной работы
**«Система автоматизированного тестирования безопасности контейнерных приложений»**.

CAST — это **оркестратор + политика + отчёт поверх существующих сканеров**.
Утилита сама выбирает нужные инструменты под тип цели, склеивает их выводы
в единую модель находок, добавляет собственные проверки, считает риск
и выносит вердикт «годен / не годен» для CI.

```bash
sarbar scan alpine:3.19        # образ      -> статический анализ
sarbar scan abc123def456       # контейнер  -> runtime + связь с образом
sarbar scan ./Dockerfile       # Dockerfile -> линт + misconfig
sarbar scan ./app              # каталог    -> уязвимости ФС + поиск секретов
```

> Команды `cast` и `scan` — полные алиасы `sarbar`.
> Репозиторий называется `cast`, пакет и команда по умолчанию — `sarbar`.
> Полная спецификация и журнал изменений — в [SPEC.md](SPEC.md).

---

## Содержание

- [Принцип честности результата](#принцип-честности-результата)
- [Чем это отличается от Trivy / Grype / Clair / Anchore](#чем-это-отличается-от-trivy--grype--clair--anchore)
- [Возможности](#возможности)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Команды и флаги](#команды-и-флаги)
- [Два режима: auto и агрегатор](#два-режима-auto-и-агрегатор)
- [Профили и политика](#профили-и-политика)
- [Risk score: методика](#risk-score-методика)
- [Форматы отчёта](#форматы-отчёта)
- [Offline-режим](#offline-режим)
- [Движки и их установка](#движки-и-их-установка)
- [История прогонов](#история-прогонов)
- [Архитектура](#архитектура)
- [Собственные проверки (sarbar-checks)](#собственные-проверки-sarbar-checks)
- [Структура репозитория](#структура-репозитория)
- [Тесты](#тесты)
- [Roadmap](#roadmap)
- [Лицензия](#лицензия)

---

## Принцип честности результата

Сканер безопасности, который отвечает «всё чисто» на упавшем движке, опаснее
отсутствия сканирования. Поэтому в sarbar жёстко зафиксированы инварианты
(полный список — в [SPEC.md](SPEC.md), раздел 3):

| Инвариант | Что это значит на практике |
|---|---|
| Упавший движок не может дать `PASS` | Прогон помечается `DEGRADED`, вердикт `FAIL`, причина в `diagnostics` |
| Наличие внешнего сканера не отключает `sarbar-checks` | Свои проверки идут **всегда**, а не «если ничего не нашлось» |
| `--offline` всегда выполняет `sarbar-checks` | Документация и поведение совпадают |
| Бинарь исполняется по абсолютному пути | `~/.sarbar/bin` не в PATH — и это не ломает сканирование |
| Неразрешимая цель — ошибка, а не пустой успех | Опечатка в пути даёт `exit 2`, а не зелёный CI |
| Усечение охвата не бывает молчащим | `files scanned`, `skipped_*`, `truncated` попадают в отчёт |
| HTML-отчёт экранирует внешние данные | Имя пакета из чужого реестра не executes JS в вашем отчёте |
| Сборка не ходит в сеть | Бинари движков ставит только явная `sarbar setup` |

Если эти правила нарушаются — это баг, а не «особенность режима».

---

## Чем это отличается от Trivy / Grype / Clair / Anchore

CAST **не** является «ещё одним сканером уязвимостей». Собственной CVE-базы,
парсеров всех языковых экосистем и runtime-агента с нуля здесь нет и не будет —
это сознательное ограничение темы. Существующие сканеры остаются **под капотом**
как сменные движки, а ценность работы — в слое над ними:

| Вопрос | Ответ (где в коде) |
|---|---|
| Зачем вы, если есть Trivy? | CAST решает другую задачу: **выбор инструмента, склейка результатов, оценка риска, политика**. Сканеры — адаптеры в `sarbar/engines/` |
| Что здесь вашего? | 1) определение типа цели (`target.py`); 2) объяснимый план скана (`orchestrator.plan_scan`); 3) единая модель находки (`model.py`); 4) дедупликация и корреляция (`normalize.py`); 5) собственные проверки (`checks/`); 6) композитный risk score (`risk.py`); 7) политика fail/pass (`policy.py`); 8) единый отчёт в 4 форматах (`report.py`); 9) локальная история (`history.py`) |
| Своя CVE-база? | Нет. CVE приходят из движков и только нормализуются |
| Парсеры экосистем? | Нет, это делают Trivy/Grype |
| Свой runtime-агент? | Нет и не будет. Runtime = `docker inspect` + эвристики (`checks.check_inspect`). Без kernel-модулей |
| Два режима? | Да: `auto` (CAST сама выбирает движки) и агрегатор (`--engine X` — движок фиксирован, а модель, риск, политика и отчёт всё равно наши) |

---

## Возможности

- **Единая модель находки** (`Finding`) для всех четырёх движков: нормализация
  severity из диалектов Trivy / Grype / Dockle / Falco, стабильный fingerprint.
- **Дедупликация** по fingerprint: один и тот же CVE от Trivy и Grype — одна
  строка с `engines_seen=[trivy, grype]`, худшей severity и максимальным CVSS.
- **Корреляция**: runtime-находка связывается с уязвимостью образа по пакету,
  поэтому `scan <container>` показывает цепочку «образ → поведение».
- **Объяснимый план** (`--explain`): какие движки выбраны и почему.
- **Собственные проверки** `sarbar-checks` — линт Dockerfile, поиск секретов,
  runtime-риски из `docker inspect`. Чистый Python, без БД и без сети.
- **Композитный risk score** 0–100 с затуханием вклада класса и построчным
  объяснением каждого числа.
- **Политика fail/pass** в профилях `default | ci | strict | offline | report`,
  переопределяется из CLI через `--fail-on`.
- **Четыре формата отчёта**: `console`, `json`, `sarif` (SARIF 2.1.0, валидна по
  официальной схеме), `html`.
- **Exit-коды**: `0` pass, `1` policy fail, `2` ошибка ввода или неразрешимая цель.
- **История прогонов** в SQLite с миграцией схемы.

---

## Установка

Требования: Python 3.10+. Обязательных зависимостей нет — утилита должна
работать в изолированном контуре.

```bash
git clone https://github.com/doisss/cast.git
cd cast

python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"        # или: pip install .
```

Опциональные extras:

| Extra | Что даёт |
|---|---|
| `report` | `rich` — табличный вывод в терминале (без него работает текстовый рендерер) |
| `yaml` | `PyYAML` — чтение `policies/*.yaml`. Без него работает встроенная таблица профилей |
| `dev` | pytest, pytest-cov, rich, PyYAML |

Сканеры — по желанию:

```bash
sarbar setup                   # скачать trivy и falco в ~/.sarbar/bin
sarbar engines                 # проверить, что видно и что работает
```

`~/.sarbar/bin` может не быть в `PATH` — sarbar это учитывает: движок ищется
сначала в `PATH`, затем в `~/.sarbar/bin`, и запускается по абсолютному пути.
Если хотите пользоваться им из shell:

```bash
export PATH="$HOME/.sarbar/bin:$PATH"
# или симлинк в ~/.local/bin
```

Полная установка одной командой (нужен root, ставит движки в `/usr/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/doisss/cast/main/install.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/doisss/cast/main/uninstall.sh | sudo bash
```

---

## Быстрый старт

```bash
# Статический анализ образа
sarbar scan alpine:3.19

# Запущенный контейнер: runtime-проверки + привязка к образу
sarbar scan abc123def456

# Dockerfile: собственный линт + dockle (если установлен)
sarbar scan ./Dockerfile

# Каталог: fs-уязвимости + поиск секретов + линт Dockerfile (если есть рядом)
sarbar scan ./app

# Только свои проверки, без внешних движков — работает где угодно
sarbar scan ./app --engine none

# Полностью офлайн: свои проверки + помеченные mock-данные
sarbar scan ./app --offline

# CI-режим: exit 1 при нарушении политики
sarbar pipeline ./app --profile strict

# Посмотреть историю
sarbar history --limit 10
```

Пример вывода (сокращён, `--offline --engine none`, движков в системе нет):

```
sarbar scan ./examples/vuln-app/Dockerfile  (kind=dockerfile, profile=default)
engines: (none)  [DEGRADED]
risk: 23.9 (low)  verdict: FAIL
counts: HIGH=2 LOW=2 MEDIUM=2
--------------------------------------------------------------------------
HIGH     CAST-DOCKER-003   -  -  [sarbar-checks]  Running as root (no USER)
HIGH     CAST-DOCKER-005   -  -  [sarbar-checks]  Secrets via ENV/ARG
MEDIUM   CAST-DOCKER-001   -  -  [sarbar-checks]  Avoid ADD in favor of COPY
MEDIUM   CAST-DOCKER-002   -  -  [sarbar-checks]  Base image not version-pinned
LOW      CAST-DOCKER-004   -  -  [sarbar-checks]  apt-get without cleanup
LOW      CAST-DOCKER-006   -  -  [sarbar-checks]  Missing HEALTHCHECK
--------------------------------------------------------------------------
risk reasons: HIGH:2x -> +17.1; MEDIUM:2x -> +5.1; LOW:2x -> +1.7
policy: leaked secret findings 1 >= threshold 1; no external scanner produced
        results and policy requires at least one working engine;
        DEGRADED: results come from sarbar-checks/mock only, not from a real scanner
```

Строка `DEGRADED` — не украшение, а требование инварианта I-1: прогон без
работающего внешнего движка не имеет права выглядеть зелёным.

---

## Команды и флаги

```
sarbar scan TARGET [--profile NAME] [--engine NAME] [--format FMT]
                   [-o FILE] [--offline] [--no-cast-checks] [--no-mock]
                   [--explain] [--no-history] [--fail-on SPEC]
sarbar pipeline TARGET [те же флаги]   # CI: exit 1 при verdict=fail
sarbar history [--limit N]
sarbar engines
sarbar setup
```

| Флаг | Назначение |
|---|---|
| `--profile default\|ci\|strict\|offline\|report` | профиль риска и политики |
| `--engine trivy\|grype\|dockle\|falco\|none` | агрегатор: зафиксировать один движок; `none` — только `sarbar-checks` |
| `--format console\|json\|sarif\|html` | формат отчёта |
| `-o, --output FILE` | записать отчёт в файл (работает для всех форматов, включая `console`) |
| `--offline` | не вызывать внешние движки; `sarbar-checks` всё равно выполняются |
| `--no-cast-checks` | отключить собственные проверки |
| `--no-mock` | никогда не подставлять mock-данные вместо отсутствующих движков |
| `--explain` | показать, почему выбраны именно эти движки |
| `--no-history` | не сохранять прогон в историю |
| `--fail-on SPEC` | переопределить пороги, например `critical=1,high=5,secret=0,score=60,degraded=off` |

Exit-коды: `0` — verdict `pass`; `1` — verdict `fail`; `2` — ошибка ввода или
неразрешимая цель.

---

## Два режима: auto и агрегатор

**Режим A — auto.** Пользователь даёт цель, CAST сама выбирает движки по
профилю и показывает план:

1. определяет тип цели (`image` / `container` / `dockerfile` / `fs`);
2. выбирает движки из профиля;
3. выполняет их и разбирает вывод;
4. добавляет свои проверки `sarbar-checks`;
5. дедуплицирует и коррелирует;
6. считает risk score;
7. применяет политику;
8. печатает отчёт и сохраняет прогон.

| Цель (профиль `ci`) | Движки | Свои проверки |
|---|---|---|
| image | trivy, grype | — |
| container | trivy, grype, falco (по образу из `docker inspect`) | runtime-inspect |
| dockerfile | dockle | dockerfile-lint (всегда) |
| fs | trivy, grype | secret-scan + dockerfile-lint (если Dockerfile рядом) |

**Режим B — агрегатор.** Пользователь явно фиксирует движок
(`--engine trivy`), но формат вывода, нормализация, политика и отчёт — всё
равно наши. Так один и тот же пайплайн сравнивает движки между собой.

---

## Профили и политика

Профили лежат в `sarbar/policies/*.yaml` **внутри пакета** — поэтому они
доходят до установленной копии. Код работает и без PyYAML: в `policy.py` есть
встроенная таблица, YAML — редактируемый оверлей. Битая YAML-файл выводит
предупреждение, а не игнорируется молча.

| Профиль | Движки (fs) | Пороги fail |
|---|---|---|
| `default` | trivy | critical ≥ 1, secret ≥ 1, score ≥ 80, degraded |
| `ci` | trivy + grype | critical ≥ 1, high ≥ 5, secret ≥ 1, score ≥ 60, degraded |
| `strict` | trivy + grype | critical ≥ 1, high ≥ 1, secret ≥ 1, score ≥ 40, degraded |
| `offline` | — | critical ≥ 1, secret ≥ 1, score ≥ 80 (degraded разрешён) |
| `report` | trivy | ничего не валит — для baseline перед выбором порогов |

Значение `-1` означает «никогда». Флаг `degraded` означает «не проходить прогон,
где ни один внешний движок не отработал».

---

## Risk score: методика

Композитная оценка 0–100 (`sarbar/risk.py`) — собственная методика, выносится
на защиту:

```
score = min(100, severity_points + cvss_lift + category_penalty)
```

- **severity_points**: веса CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1 с затуханием
  `w/√n` (один critical — плохо, двадцать — не в 20 раз хуже) и капом вклада
  класса: CRITICAL ≤ 60, HIGH ≤ 40, MEDIUM ≤ 25, LOW ≤ 10;
- **cvss_lift** = `min(15, max_cvss × 1.5)`;
- **category_penalty**: +5 за утёкший секрет, +5 за runtime-проблему.

Уровни: ≥ 80 critical, ≥ 60 high, ≥ 30 medium, ≥ 5 low, иначе ok.
Каждая цифра в отчёте объясняется строкой `risk reasons`.

**Честное ограничение методики.** Капы делают оценку насыщающейся: уже 5
CRITICAL дают потолок в 60 баллов, а 10 HIGH — 40. В диапазоне примерно от 5 до
200 находок одного класса score перестаёт различать случаи. Это осознанное
решение (score отвечает на вопрос «насколько всё плохо», а не «сколько всего
находок»), но детализацию в этом диапазоне несут сами находки, а не число.
Кап всегда помечается в `risk reasons` словом `class cap`.

---

## Форматы отчёта

- **console** — человек читает в терминале; verdict, причины и диагностика
  всегда внизу. С `-o FILE` используется текстовый рендерер, чтобы вывод
  попал в файл.
- **json** — машиночитаемый, поле `plan.why` фиксирует объяснимость выбора
  движков; `diagnostics`, `engine_status`, `coverage`, `degraded` позволяют
  отличить «чисто» от «не смогли проверить».
- **sarif** — SARIF 2.1.0, валидна по официальной схеме; `rules[]`
  дедуплицированы по id (иначеGitHub Code Scanning отвергает файл, когда один
  CVE задевает два пакета), у результатов есть `ruleIndex` и `locations`.
- **html** — одностраничный отчёт для приложения к диплому. Любое поле,
  пришедшее извне, экранируется через `html.escape`.

Exit-код: `0` при `verdict=pass`, `1` при `verdict=fail`, `2` при ошибке —
CI-системы понимают без парсинга.

---

## Offline-режим

```bash
sarbar scan ./examples/vuln-app --offline --explain
```

Гарантирует воспроизводимость (демо на защите без интернета): внешние бинари
не вызываются, **собственные проверки выполняются всегда**, результат
дополняется детерминированным mock-ом, прогон помечается `DEGRADED`.
Mock-данные явно подписаны `engine=mock` и не должны трактоваться как живой
CVE-фид — это стенд-заглушка. Убрать его совсем: `--no-mock`.

Чтобы получить **только** свои проверки без mock-данных:

```bash
sarbar scan ./examples/vuln-app --engine none --no-mock
```

---

## Движки и их установка

| Движок | Режимы | Нужен root | Замечание |
|---|---|---|---|
| `trivy` | image, fs, dockerfile, container | нет | основной движок |
| `grype` | image, fs, container | нет | второе мнение по уязвимостям |
| `dockle` | image, dockerfile | нет | misconfig для Dockerfile и образа |
| `falco` | container, image | **да** | eBPF/kmod-драйвер; см. ниже |
| `sarbar-checks` | все | нет | встроенный Python, всегда доступен |

`sarbar engines` различает `ready`, `absent` и **`broken`** — файл найден, но
`--version` на нём падает. Такой движок не считается доступным.

**Про Falco честно.** Falco — привилегированный демон, работающий через eBPF или
kernel-модуль. Короткое окно запуска в адаптере (20 с) **не является настоящим
runtime-сканом**. Адаптер запускает Falco в ограниченном окне и честно сообщает
результат: если событий нет или время вышло — выводится предупреждение, а не
запись «контейнер проверен и чист». Для реального runtime-детектирования
запускайте Falco как сервис.

---

## История прогонов

Каждый прогон (если не указан `--no-history`) сохраняется в SQLite
`~/.sarbar/history.db`: цель, профиль, движки, score, verdict, признак
деградации и находки. Схема версионируется и мигрируется, поэтому база от
предыдущей версии sarbar продолжает работать.

Будущий web-интерфейс будет читать эту же базу — ядро переписывать не придётся
(web сейчас сознательно не делается по ТЗ).

---

## Архитектура

```
                    ┌──────────────┐
   sarbar scan ────▶│    cli.py    │  UX: аргументы, коды возврата, вывод
                    └──────┬───────┘
                    ┌──────▼───────┐
                    │   target.py  │  1. что за цель
                    └──────┬───────┘
                    ┌──────▼────────┐
                    │ orchestrator  │  2. план → исполнение → деградация
                    └──────┬────────┘
           ┌───────────────┼────────────────┐
    ┌──────▼─────┐  ┌──────▼──────┐  ┌──────▼────────┐
    │  engines/  │  │  checks/    │  │    policy.py  │
    │ trivy      │  │ Dockerfile  │  │  профили и    │
    │ grype      │  │ секреты     │  │  пороги       │
    │ dockle     │  │ runtime     │  └──────┬────────┘
    │ falco      │  │ (inspect)   │         │
    └──────┬─────┘  └──────┬──────┘  ┌──────▼────────┐
           └───────────────┴─────────┤    risk.py    │
                                      │  score 0..100 │
                                      └──────┬────────┘
                                ┌────────────┴────────────┐
                        ┌───────▼───────┐          ┌───────▼──────┐
                        │  report.py    │          │  history.py  │
                        │ console/json  │          │ SQLite       │
                        │ sarif/html    │          └──────────────┘
                        └───────────────┘
```

| Модуль | Роль |
|---|---|
| `sarbar/target.py` | классификация цели, разрешение неоднозначностей |
| `sarbar/model.py` | `Finding`, алиасы severity, fingerprint |
| `sarbar/engines/` | адаптеры движков, контракт `EngineResult` со статусом |
| `sarbar/checks/` | собственные проверки (Dockerfile, секреты, runtime) |
| `sarbar/normalize.py` | дедупликация и корреляция |
| `sarbar/risk.py` | композитный score |
| `sarbar/policy.py` | профили, пороги, YAML-оверлей |
| `sarbar/report.py` | четыре формата вывода |
| `sarbar/cli.py` | разбор аргументов, коды возврата |
| `sarbar/history.py` | журнал прогонов |
| `sarbar/setup.py` | установка бинарей движков |

---

## Собственные проверки (sarbar-checks)

Чистый Python, без сети и без CVE-базы. Выполняются всегда, если
`run_cast_checks` включён в профиле.

| ID | Проверка | Серьёзность |
|---|---|---|
| CAST-DOCKER-001…007 | `ADD` вместо `COPY`, непинованный тег, запуск от root (нет `USER`), `apt-get` без чистки, секреты в `ENV/ARG`, нет `HEALTHCHECK`, установлен `sudo` | LOW…HIGH |
| CAST-SECRET-001…005 | AWS-ключи, приватные ключи, GitHub-токены, пароли в присваиваниях, generic API-токены | MEDIUM…HIGH |
| CAST-RT-001…009 | `--privileged`, root, опасные capabilities, host-сеть, `docker.sock`, host PID, host IPC, отключённый AppArmor/seccomp, writable rootfs | LOW…CRITICAL |

Секрет-сканер помнит **все** вхождения: 40 совпадений в 40 файлах дают одну
находку с пометкой `x40 locations`, а не одну находку с именем случайного
файла. Любое усечение охвата (лимит файлов, бинарники, слишком большие файлы)
попадает в `diagnostics`.

---

## Структура репозитория

```
sarbar/
├── sarbar/
│   ├── __init__.py       # публичный API
│   ├── __main__.py       # python -m sarbar
│   ├── model.py          # Finding, severity, fingerprint
│   ├── target.py         # классификация цели
│   ├── orchestrator.py   # план, исполнение, деградация
│   ├── normalize.py      # дедупликация, корреляция
│   ├── risk.py           # композитный score
│   ├── policy.py         # профили и пороги
│   ├── report.py         # console / json / sarif / html
│   ├── history.py        # SQLite-журнал
│   ├── cli.py            # CLI
│   ├── setup.py          # sarbar setup
│   ├── checks/           # sarbar-checks
│   ├── engines/          # адаптеры + mock
│   └── policies/         # *.yaml — профили (внутри пакета)
├── tests/                # pytest
├── examples/vuln-app/    # намеренно дырявый пример
├── install.sh            # установка одной командой (нужен root)
├── uninstall.sh          # удаление с выбором движков
├── pyproject.toml        # метаданные пакета
├── SPEC.md               # спецификация + журнал изменений
└── README.md
```

---

## Тесты

```bash
pip install -e ".[dev]"
pytest                              # весь набор
pytest --cov=sarbar --cov-report=term-missing
```

Набор покрывает адаптеры движков на фикстурах реального JSON (Trivy, Grype,
Dockle, Falco), инварианты оркестратора, дедупликацию и корреляцию, методику
risk score, пороги политики, все четыре формата отчёта, CLI и SQLite-историю.
Тесты `tests/test_orchestrator.py` защищают инварианты из [SPEC.md](SPEC.md)
и не должны удаляться.

---

## Roadmap

- [x] Оркестратор с объяснимым планом
- [x] Четыре движка + `sarbar-checks`
- [x] Risk score и политика профилей
- [x] Четыре формата отчёта (включая валидный SARIF)
- [x] Offline-режим без зависимостей
- [x] Один тест на каждый инвариант
- [ ] Web-интерфейс поверх существующей базы истории
- [ ] Интеграция с CI (GitHub Actions / GitLab CI) как готовый action
- [ ] Baseline-режим: сравнение прогонов и регресс-детект

---

## Лицензия

MIT — см. [LICENSE](LICENSE).