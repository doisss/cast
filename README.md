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

> Бинарь `cast` — полный алиас `sarbar`, все примеры ниже работают с обоими именами.
> Репозиторий называется `cast`, пакет и команда по умолчанию — `sarbar`.

---

## Содержание

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
- [История прогонов](#история-прогонов)
- [Архитектура](#архитектура)
- [Собственные проверки (cast-checks)](#собственные-проверки-cast-checks)
- [Структура репозитория](#структура-репозитория)
- [Тесты](#тесты)
- [Roadmap](#roadmap)
- [Лицензия](#лицензия)

---

## Чем это отличается от Trivy / Grype / Clair / Anchore

CAST **не** является «ещё одним сканером уязвимостей». Собственной CVE-базы,
парсеров всех языковых экосистем и runtime-агента с нуля здесь нет и не будет —
это сознательное ограничение темы. Существующие сканеры остаются **под капотом**
как сменные движки, а ценность работы — в слое над ними:

| Вопрос | Ответ (где в коде) |
|---|---|
| Зачем вы, если есть Trivy? | CAST решает другую задачу: **выбор инструмента, склейка результатов, оценка риска, политика**. Сканеры — адаптеры в `sarbar/engines/` |
| Что здесь вашего? | 1) определение типа цели (`sarbar/target.py`); 2) объяснимый план сканирования (`orchestrator.plan_scan`); 3) единая модель находки (`model.py`); 4) дедупликация и корреляция (`normalize.py`); 5) собственные проверки (`checks/`); 6) композитный risk score (`risk.py`); 7) политика fail/pass (`policy.py`); 8) единый отчёт в 4 форматах (`report.py`); 9) локальная история (`history.py`) |
| Своя CVE-база? | Нет. CVE приходят из движков и только нормализуются |
| Парсеры экосистем? | Нет, это делают Trivy/Grype |
| Свой runtime-агент? | Нет. Runtime = `docker inspect` + эвристики (`checks.check_inspect`): privileged, root, capabilities, `docker.sock`, host-сеть. Без kernel-модулей |
| Два режима? | Да: `auto` (CAST сама выбирает движки) и агрегатор (`--engine X` — движок фиксирован, а модель, риск, политика и отчёт всё равно наши) |

Научный руководитель согласовал направление как «применяешь тот инструмент,
который необходим; если готовый не подходит — своё решение или комбинация».
Это реализовано буквально: `orchestrator.plan_scan` подбирает движок под тип
цели и профиль, а там, где универсальные сканеры слабы (секреты, гигиена
Dockerfile, runtime-конфигурация), работают `cast-checks`.

---

## Возможности

- **4 типа целей из одного аргумента**: образ, запущенный контейнер, Dockerfile, каталог/файл.
- **2 режима**: `auto` (интеллектуальный выбор движков) и агрегатор (`--engine`).
- **Единая модель находки**: любой движок → `Finding(severity, package, cvss, engine, category, …)`.
- **Дедупликация** по стабильному fingerprint: один и тот же CVE от Trivy и Grype — одна строка с `engines_seen=[trivy, grype]`.
- **Корреляция** image ↔ runtime: находки запущенного контейнера связываются с уязвимостями его образа.
- **Собственные проверки** там, где сканеры слабы: секреты, Dockerfile, runtime-конфиг.
- **Композитный risk score 0–100** с объяснением (`risk reasons`).
- **Политика fail/pass** с профилями `default / ci / strict / offline` и переопределением из CLI для CI.
- **4 формата отчёта**: console, JSON, SARIF (импорт в GitHub Code Scanning), HTML.
- **Локальная история** прогонов в SQLite — задел под будущий web-интерфейс без переписывания ядра.
- **Offline-режим**: воспроизводимое демо без сети и без установленных сканеров.

---

## Установка

Требования: Python 3.10+. Опционально (для живых сканирований): `docker`, `trivy`, `grype`, `dockle`.
Без них утилита работает в offline/demo-режиме.

```bash
git clone https://github.com/doisss/cast.git
cd cast
python3 -m venv .venv
.venv/bin/pip install -e .
ln -sf "$PWD/.venv/bin/sarbar" ~/.local/bin/sarbar   # если ~/.local/bin в PATH
ln -sf "$PWD/.venv/bin/cast" ~/.local/bin/cast       # алиас
```

Проверка:

```bash
sarbar --version
sarbar engines     # какие движки реально доступны, какие уйдут во fallback
```

Для разработки:

```bash
.venv/bin/pip install -e ".[dev]"
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

# CI-режим: молча, exit 1 при нарушении политики
sarbar pipeline ./app

# Посмотреть историю
sarbar history --limit 10
```

Пример вывода (сокращён):

```
sarbar scan ./examples/vuln-app  (kind=fs, profile=default)
engines: mock, cast-checks  [offline/fallback]
risk: 85.3 (critical)  verdict: FAIL
counts: CRITICAL=1 HIGH=5 LOW=2 MEDIUM=4
----------------------------------------------------------------------------------------------------
CRITICAL CVE-2024-21626           runc:1.1.9        1.1.12  [mock] Container escape via runC
HIGH     CAST-SECRET-001          -                 -       [cast-checks] Possible AWS access key
HIGH     CAST-DOCKER-003          -                 -       [cast-checks] Running as root (no USER)
...
risk reasons: CRITICAL:1x -> +25.0; HIGH:5x -> +32.3; ...; leaked secret -> +5.0
policy: critical findings 1 >= threshold 1; risk score 85.3 >= threshold 80.0
```

---

## Команды и флаги

```
sarbar scan TARGET [--profile NAME] [--engine NAME] [--format FMT]
                   [-o FILE] [--offline] [--no-cast-checks] [--explain]
                   [--no-history] [--fail-on SPEC]
sarbar pipeline TARGET [те же флаги]   # CI: exit 1 при verdict=fail
sarbar history [--limit N]
sarbar engines
```

| Флаг | Назначение |
|---|---|
| `--profile default\|ci\|strict\|offline` | профиль риска и политики (по умолчанию `default`) |
| `--engine trivy\|grype\|dockle\|none` | режим агрегатора: зафиксировать один движок; модель, риск, политика и отчёт остаются наши |
| `--format console\|json\|sarif\|html` | формат отчёта |
| `-o, --output FILE` | записать отчёт в файл вместо stdout |
| `--offline` | без сети: внешние движки не вызываются, только локальные проверки + помеченный mock |
| `--no-cast-checks` | отключить собственные проверки |
| `--explain` | показать, почему выбраны именно эти движки (`plan.why`) |
| `--no-history` | не сохранять прогон в историю |
| `--fail-on critical=1,high=5,score=60` | переопределить пороги политики из CLI (удобно для CI) |

Полезные комбинации:

```bash
sarbar scan alpine:3.19 --engine trivy --explain
sarbar scan ./app --offline --format json -o report.json
sarbar scan ./app --format sarif -o report.sarif     # импорт в GitHub Code Scanning
sarbar scan ./app --format html -o report.html
sarbar pipeline ./app --profile strict --fail-on critical=1,high=1,score=40
```

---

## Два режима: auto и агрегатор

**Режим A — `auto` (по умолчанию).** Пользователь указывает цель, CAST сама:
1. определяет тип цели (`target.py`);
2. выбирает сканеры по профилю (`orchestrator.plan_scan`);
3. запускает их;
4. нормализует выводы в одну модель (`model.py`);
5. дедуплицирует и коррелирует (`normalize.py`);
6. запускает свои `cast-checks`;
7. считает risk score (`risk.py`);
8. применяет политику fail/pass (`policy.py`);
9. печатает единый отчёт и сохраняет прогон в историю.

Выбор движков по типу цели (профиль `ci`):

| Цель | Движки | Свои проверки |
|---|---|---|
| image | trivy, grype | метки образа |
| container | trivy, grype (по образу из `docker inspect`) | runtime-inspect |
| dockerfile | dockle | dockerfile-lint (всегда, офлайн) |
| fs | trivy, grype | secret-scan + dockerfile-lint, если Dockerfile рядом |

**Режим B — агрегатор.** Пользователь явно фиксирует движок (`--engine trivy`),
но формат вывода, нормализация, политика и отчёт — всё равно наши.
Так один и тот же пайплайн сравнивает движки между собой.

---

## Профили и политика

Профили лежат в `policies/*.yaml` (код работает и без PyYAML — есть встроенный
fallback в `policy.py`, поэтому offline-режим не требует зависимостей):

| Профиль | Движки | Пороги fail |
|---|---|---|
| `default` | минимум шума | critical ≥ 1 или score ≥ 80 |
| `ci` | trivy+grype cross-check | critical ≥ 1, high ≥ 5, score ≥ 60 |
| `strict` | всё включено | critical/high ≥ 1, score ≥ 40 |
| `offline` | только cast-checks (air-gap, демо без интернета) | critical ≥ 1, score ≥ 80 |

---

## Risk score: методика

Композитная оценка 0–100 (`sarbar/risk.py`) — собственная методика, выносится на защиту:

```
score = min(100, severity_points + cvss_lift + category_penalty)
```

- **severity_points**: веса CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1 с затуханием
  `w/sqrt(n)` (один critical — плохо, двадцать — не в 20 раз хуже) и капом вклада класса;
- **cvss_lift** = `min(15, max_cvss × 1.5)`;
- **category_penalty**: +5 за утёкший секрет, +5 за runtime-проблему.

Уровни: ≥ 80 critical, ≥ 60 high, ≥ 30 medium, ≥ 5 low, иначе ok.
Каждая цифра в отчёте объясняется строкой `risk reasons`.

---

## Форматы отчёта

- **console** — человек читает в терминале; verdict и причины — всегда внизу;
- **json** — машиночитаемый, поле `plan.why` фиксирует объяснимость выбора движков;
- **sarif** — стандарт SARIF 2.1.0, грузится в GitHub Code Scanning;
- **html** — одностраничный отчёт для приложения к диплому.

Exit-код: `0` при `verdict=pass`, `1` при `verdict=fail` — CI-системы понимают без парсинга.

---

## Offline-режим

```bash
sarbar scan ./examples/vuln-app --offline --explain
```

Гарантирует воспроизводимость (демо на защите без интернета): внешние бинари
не вызываются, результат строится из `cast-checks` + детерминированного mock,
прогон помечается `offline=True`. Mock-данные явно подписаны `engine=mock`
и не должны трактоваться как живой CVE-фид — это стенд-заглушка.

---

## История прогонов

Каждый прогон (если не указан `--no-history`) сохраняется в SQLite
`~/.sarbar/history.db`: цель, профиль, движки, score, verdict, находки.
Будущий web-интерфейс будет читать эту же базу — ядро переписывать не придётся
(web сейчас сознательно не делается по ТЗ).

---

## Архитектура

```
sarbar/cli.py            только UX (argparse) -> вызывает orchestrator
sarbar/orchestrator.py   plan_scan / run_scan: выбор движков, порядок, offline
sarbar/target.py         detect_target: image | container | dockerfile | fs
sarbar/engines/          адаптеры: run() -> list[Finding]; недоступен -> fallback
sarbar/checks/           своё: dockerfile-lint, secrets, runtime-inspect
sarbar/normalize.py      dedup по fingerprint + корреляция image<->runtime
sarbar/risk.py           композитный score + уровень
sarbar/policy.py         профили default/ci/strict/offline + fail/pass
sarbar/report.py         console / json / sarif / html — один UX для всех движков
sarbar/history.py        SQLite ~/.sarbar/history.db — будущий бэкенд web
```

Поток данных: `цель → план → движки + cast-checks → нормализация → риск → политика → отчёт + история`.
Сканер заменяется одним адаптером с контрактом `run(target, kind) -> list[Finding]`.

---

## Собственные проверки (cast-checks)

Всегда локальные, работают офлайн, движок `cast-checks`:

| ID | Проверка | Серьёзность |
|---|---|---|
| CAST-DOCKER-001…006 | Dockerfile: `ADD` вместо `COPY`, тег `:latest`, запуск от root (нет `USER`), `apt-get` без чистки, секреты в `ENV/ARG`, нет `HEALTHCHECK` | LOW…HIGH |
| CAST-SECRET-001…005 | AWS-ключи, приватные ключи, GitHub-токены, пароли в присваиваниях, generic API-токены | MEDIUM…HIGH |
| CAST-RT-001…005 | `--privileged`, запуск от root, опасные capabilities, host-сеть, монтирование `docker.sock` | MEDIUM…CRITICAL |

---

## Структура репозитория

```
.
├── sarbar/                 # пакет (ядро + CLI)
│   ├── cli.py              # только UX
│   ├── target.py           # определение типа цели
│   ├── orchestrator.py     # план и запуск (ядро диплома)
│   ├── engines/            # адаптеры trivy / grype / dockle + mock
│   ├── checks/             # собственные проверки
│   ├── model.py            # единая модель Finding
│   ├── normalize.py        # дедупликация + корреляция
│   ├── risk.py             # risk score
│   ├── policy.py           # профили и fail/pass
│   ├── report.py           # 4 формата отчёта
│   └── history.py          # SQLite-история
├── policies/               # default.yaml, ci.yaml, strict.yaml, offline.yaml
├── tests/                  # pytest: target, normalize, risk, checks, cli
├── examples/vuln-app/      # уязвимый пример для демо (Dockerfile + app.py)
└── pyproject.toml          # установка: pip install -e .
```

---

## Тесты

```bash
.venv/bin/python -m pytest -q
```

Покрыто: классификация целей, дедупликация и сортировка, score и политика,
все группы cast-checks, план оркестратора (auto/forced), offline-скан,
команды `engines`/`history`. Живые прогоны без сети:

```bash
sarbar scan ./examples/vuln-app --offline --explain
```

---

## Roadmap

- [x] CLI, оба режима, 4 типа целей
- [x] Политика, risk score, 4 формата отчёта, история
- [ ] E2E-прогоны с живыми trivy/grype/dockle в CI
- [ ] Web-интерфейс поверх `history.db` (ядро не меняется)
- [ ] Уведомления, дашборд, сравнение прогонов во времени

---

## Лицензия

MIT, см. [LICENSE](LICENSE).
