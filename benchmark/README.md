# DGF Benchmark (Directed Greybox Fuzzing)

Автономный воспроизводимый бенчмарк для сравнительной оценки **5 современных направленных серых фаззеров (Directed Greybox Fuzzers)** на 5 подтвержденных уязвимостях реального мира (FSE '24 / DAFL).

Бенчмарк полностью управляется через единый конфигурационный файл [`config.yaml`](config.yaml) и запускается одной командой через Docker Compose:

```bash
docker compose up -d
```

---

## 📑 Содержание
1. [Состав бенчмарка](#1-состав-бенчмарка)
   - [Сравниваемые фаззеры](#сравниваемые-фаззеры-5-dgf)
   - [Исследуемые уязвимости](#исследуемые-уязвимости-5-real-world-targets)
   - [Оцениваемые метрики (TTT vs TTE)](#оцениваемые-метрики-ttt-vs-tte)
2. [Быстрый старт (One-Command Run)](#2-быстрый-старт-one-command-run)
3. [Клонирование на чистый сервер](#3-клонирование-на-чистый-сервер)
4. [Конфигурация (config.yaml)](#4-конфигурация-configyaml)
5. [Архитектура оркестратора](#5-архитектура-оркестратора)
6. [Альтернативный запуск напрямую (CLI)](#6-альтернативный-запуск-напрямую-cli)
7. [Результаты и отчеты](#7-результаты-и-отчеты)
8. [Структура репозитория](#8-структура-репозитория)

---

## 1. Состав бенчмарка

### Сравниваемые фаззеры (5 DGF):
| Фаззер | Архитектурная роль / Принцип | Репозиторий / Источник |
| :--- | :--- | :--- |
| **`aflgo_mod`** | **Кандидат (наша модификация):** учет цикломатической сложности блоков, энтропии и дерева доминаторов | [aflgo-research](https://github.com/cooN4i/aflgo-research) (branch: `develop`) |
| **`aflgo_orig`** | **Базовый эталон:** классический Vanilla AFLGo (ACM CCS '17) | [aflgo-research](https://github.com/cooN4i/aflgo-research) (branch: `develop`) |
| **`dafl`** | **SotA:** селективная инструментация и скоринг функций (USENIX Security '23) | `prosyslab/DAFL` |
| **`fishfuzz`** | **SotA:** мульти-дистанции и динамический ранкинг таргетов (USENIX Security '23) | `HexHive/FishFuzz` |
| **`windranger`** | **SotA:** анализ блоков отклонения (DBB) и недостижимости (ICSE '22) | `prosyslab/DAFL-artifact` |

### Исследуемые уязвимости (5 Real-world Targets):
Отобраны сложные уязвимости со временем обнаружения от 12 до 24 часов:
1. **`cxxfilt`** — GNU Binutils `cxxfilt` (CVE-2016-4487 Demangle Invalid Free / UAF, `cplus-dem.c:4319`)
2. **`swftophp_20427`** — Libming `swftophp` (CVE-2018-20427 Action Compiler Null Dereference, `actioncompiler.c:98`)
3. **`swftophp_12982`** — Libming `swftophp` (CVE-2019-12982 Decompile Heap Out-Of-Bounds, `decompile.c:398`)
4. **`objdump_8397`** — GNU Binutils `objdump` (CVE-2017-8397 DWARF Reloc Heap Overflow, `dwarf.c:7554`)
5. **`nm_14940`** — GNU Binutils `nm-new` (CVE-2017-14940 ELF Version Information Crash, `elf.c:1997`)

### Оцениваемые метрики (TTT vs TTE):
В соответствии с научными стандартами исследования DGF метрики разделены на два независимых этапа:
- **TTT (Time-to-Target / $T_{\text{reach}}$)** — время (в секундах) и число выполнений (**ETT**) до первого реального попадания потока управления в целевой уязвимый базовый блок кода (верифицируется точкой останова GDB Breakpoint на каждом новом сиде из очереди).
- **TTE (Time-to-Exposure / $T_{\text{trigger}}$)** — время (в секундах) и число выполнений (**ETE**) до первого реального воспроизведения уязвимости / краша (верифицируется триажем AddressSanitizer и GDB stack trace).
- **Reach Rate & Trigger Rate** — процент успешных триалов, достигших цели и вызвавших краш за отведенный лимит времени.
- **Статистика Манна-Уитни ($p$-value)** и непараметрический размер эффекта **Варги-Делейни ($\hat{A}_{12}$)** против базового фаззера.

---

## 2. Быстрый старт (One-Command Run)

Для запуска всего эксперимента не требуется устанавливать Python-библиотеки или настраивать пути. Достаточно установленного Docker и Docker Compose:

```bash
docker compose up -d
```

### Что произойдет автоматически:
1. **Сборка (Build)**: соберутся базовый Docker-образ, образы активных фаззеров и скомпилируются бинарники активных уязвимостей (уже собранные бинарники пропускаются мгновенно).
2. **Запуск (Run)**: запустятся параллельные контейнеры фаззинга с жесткой изоляцией CPU (1 физическое ядро на триал) и лимитом памяти (2 ГБ на контейнер).
3. **Анализ (Analyze)**: фоновый триаж в реальном времени собирает TTT/TTE, а по завершении строит статистический Markdown-отчет.
4. **Архивация**: формируется готовый архив `results.tar.gz` со всеми сырыми данными кампаний и отчетом.

### Мониторинг процесса:
```bash
# Просмотр логов оркестратора
docker logs -f dgf-benchmark-orchestrator

# Просмотр запущенных фаззеров и нагрузки на ядра
docker ps
docker stats
```

### Остановка эксперимента:
```bash
docker compose down
```

---

## 3. Клонирование на чистый сервер

Репозиторий публичный, поэтому для развертывания на новом сервере Ubuntu/Debian **не требуются SSH-ключи или настройка профиля Git**:

```bash
# 1. Установка Git и Docker (если не установлены)
sudo apt update && sudo apt install -y git docker.io docker-compose-v2

# 2. Клонирование репозитория
git clone https://github.com/cooN4i/dgf-benchmark.git
cd dgf-benchmark

# 3. Запуск бенчмарка
docker compose up -d
```

---

## 4. Конфигурация (config.yaml)

Файл [`config.yaml`](config.yaml) является **единственным источником правды**. Любые изменения проводятся в нем без правки исходного кода.

### Пример настройки для тестового прогона (1 фаззер, 1 триал, 24 часа):
```yaml
resources:
  cpu_per_trial: 1           # 1 ядро на контейнер
  memory_limit: "2g"         # Максимум 2 ГБ RAM на контейнер
  max_parallel_workers: 5    # До 5 одновременных задач

experiment:
  duration: "24h"            # Длительность триала (24h, 12h, 1h, 30m)
  trials: 1                  # Число повторений на пару (фаззер, таргет)
  metric_poll_interval: 30   # Опрос TTT/TTE каждые 30 сек

fuzzers:
  - id: "aflgo_mod"
    enabled: true            # Включаем наш фаззер
  - id: "aflgo_orig"
    enabled: false           # Базовые фаззеры отключены для быстрого теста
  - id: "dafl"
    enabled: false
  - id: "fishfuzz"
    enabled: false
  - id: "windranger"
    enabled: false

targets:
  - id: "cxxfilt"
    enabled: true
  - id: "swftophp_20427"
    enabled: true
  - id: "swftophp_12982"
    enabled: true
  - id: "objdump_8397"
    enabled: true
  - id: "nm_14940"
    enabled: true
```

### Как переключить на финальный прогон для статьи/научрука:
Просто поменяйте в [`config.yaml`](config.yaml):
- Всем фаззерам поставьте `enabled: true`.
- Укажите `trials: 10` и `duration: "12h"`.
- Снова выполните `docker compose up -d`.

---

## 5. Архитектура оркестратора

Оркестратор построен по стандарту **Docker-outside-of-Docker (DooD)**:
- Контейнер `dgf-benchmark-orchestrator` монтирует Docker-сокет сервера (`/var/run/docker.sock`) и рабочий каталог.
- Внутри оркестратора скрипт `bench.py` управляет жизненным циклом рабочих контейнеров `dgf_run_<fuzzer>_<target>_t<trial>`.
- Изоляция ядер: каждое испытание привязывается к выделенному ядру CPU через `--cpuset-cpus`.
- Ограничение памяти: флаг `-m 2g` предотвращает сбои OOM-killer и зависания сервера.
- Автоматический расчет хостовых путей (`to_docker_host_path`) исключает конфликты путей монтирования между контейнером и хостом.

---

## 6. Альтернативный запуск напрямую (CLI)

Если вы хотите запускать этапы вручную на хосте (без использования Docker Compose):

```bash
# Установка зависимостей Python
pip install pyyaml scipy numpy

# 1. Посмотреть статус конфигурации
python3 bench.py info

# 2. Собрать образы и бинарники (только включенные в config.yaml)
python3 bench.py build --all

# 3. Запустить кампании согласно config.yaml
python3 bench.py run

# 4. Провести статистический анализ существующих результатов
python3 bench.py analyze
```

---

## 7. Результаты и отчеты

После завершения кампаний оркестратор упаковывает все результаты в архив:
`results.tar.gz`

Внутри архива:
1. `storage/plots/benchmark_report.md` — сформированный отчет со сводными таблицами:
   - Reach Rate, Median TTT, IQR TTT, Median ETT.
   - Trigger Rate, Median TTE, IQR TTE, Median ETE.
   - Значения $p$-value теста Манна-Уитни и размер эффекта Варги-Делейни ($\hat{A}_{12}$).
2. `storage/runs/<fuzzer>/<target>/trial_<N>/` — сырые данные:
   - `out/crashes/` — найденные краширующие входы.
   - `out/queue/` — эволюция тестовой очереди.
   - `out/fuzzer_stats` и `out/plot_data` — поминутная динамика скорости и покрытия.
   - `trial_result.json` — точные тайминги TTT и TTE с подтвержденными трейсами.
3. `config.yaml` — точный конфиг, на котором проводился расчет.

---

## 8. Структура репозитория

```text
.
├── docker-compose.yml       # Единая точка запуска бенчмарка (docker compose up -d)
├── config.yaml              # Конфигурация фаззеров, целей, ресурсов и метрик
├── bench.py                 # Главный оркестратор (build, run, triage, analyze)
├── docker/
│   ├── base/
│   │   └── Dockerfile       # Базовый компиляторный образ (Ubuntu 22.04, LLVM 11, Clang)
│   ├── fuzzers/             # Dockerfile'ы каждого из 5 фаззеров
│   │   ├── aflgo_mod.Dockerfile
│   │   ├── aflgo_orig.Dockerfile
│   │   ├── dafl.Dockerfile
│   │   ├── fishfuzz.Dockerfile
│   │   └── windranger.Dockerfile
│   └── orchestrator/        # Образ раннера для docker-compose
│       ├── Dockerfile
│       └── entrypoint.sh
├── targets/                 # Рецепты сборки уязвимостей реального мира
│   ├── cxxfilt/             # CVE-2016-4487 (target.yaml, build.sh, seeds/)
│   ├── swftophp_20427/      # CVE-2018-20427 (target.yaml, build.sh, seeds/)
│   ├── swftophp_12982/      # CVE-2019-12982 (target.yaml, build.sh, seeds/)
│   ├── objdump_8397/        # CVE-2017-8397 (target.yaml, build.sh, seeds/)
│   └── nm_14940/            # CVE-2017-14940 (target.yaml, build.sh, seeds/)
└── storage/                 # Директория артефактов (в .gitignore)
    ├── cache/               # Исходные коды целевых программ
    ├── binaries/            # Скомпилированные под каждый фаззер бинарники
    ├── runs/                # Выходные данные фаззинга и краши
    └── plots/               # Markdown-отчеты и графики
```
