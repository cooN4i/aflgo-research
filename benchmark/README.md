# DGF Benchmark (Directed Greybox Fuzzing)

Автономный воспроизводимый бенчмарк для сравнительной оценки **5 направленных фаззеров (Directed Greybox Fuzzers)** на реальных уязвимостях из базы `bikini/exploitarium`.

---

## 📑 Содержание
1. [Состав бенчмарка](#1-состав-бенчмарка)
2. [Клонирование репозитория](#2-клонирование-репозитория)
3. [Системные требования и подготовка](#3-системные-требования-и-подготовка)
4. [Конфигурация (config.yaml)](#4-конфигурация-configyaml)
5. [Сборка (Build Phase)](#5-сборка-build-phase)
   - [5.1. Собрать всё разом](#51-собрать-всё-разом-one-command)
   - [5.2. Сборка Docker-образов фаззеров](#52-сборка-docker-образов-фаззеров)
   - [5.3. Сборка целей с инструментацией](#53-сборка-целей-с-инструментацией)
6. [Запуск фаззинг-кампаний (Run Phase)](#6-запуск-фаззинг-кампаний-run-phase)
   - [6.1. Запуск всех экспериментов](#61-запуск-всех-экспериментов)
   - [6.2. Запуск конкретной цели или фаззера](#62-запуск-конкретной-цели-или-фаззера)
7. [Анализ результатов (Analyze Phase)](#7-анализ-результатов-analyze-phase)
8. [Структура каталогов](#8-структура-каталогов)

---

## 1. Состав бенчмарка

### Сравниваемые фаззеры (5 DGF):
| Фаззер | Архитектурная роль / Принцип | Источник кода |
| :--- | :--- | :--- |
| **`aflgo_mod`** | Кандидатная модификация (сложность блоков + энтропия + доминаторы) | `aflgo-research` (develop) |
| **`aflgo_orig`** | Базовый эталон (Vanilla AFLGo, CCS '17) | `aflgo-research` (develop) |
| **`dafl`** | Селективная инструментация среза функций (USENIX Sec '23) | `prosyslab/DAFL` |
| **`fishfuzz`** | Мульти-дистанции и динамический ранкинг (USENIX Sec '23) | `HexHive/FishFuzz` |
| **`windranger`** | Блоки отклонения DBB + анализ недостижимости (ICSE '22) | `prosyslab/DAFL-artifact` |

### Реальные уязвимости (5 Real-world Targets):
1. **`objdump_dlx`** — GNU Binutils `objdump` (DLX ELF OOB Write, `elf32-dlx.c:1340`)
2. **`ffmpeg_rasc`** — FFmpeg RASC Decoder (`decode_dlta` OOB Write)
3. **`vlc_vp9`** — FFmpeg/VLC VP9 Video Decoder (Slice-Thread Memory Corruption)
4. **`cares_tcp`** — c-ares C DNS Resolver Library (`ares_getaddrinfo` Use-After-Free)
5. **`libssh2_packet`** — libssh2 SSH Transport (`packet_length` Integer Wrap / Out-of-bounds)

---

## 2. Клонирование репозитория
```bash
git clone https://github.com/cooN4i/dgf-benchmark.git
cd dgf-benchmark
```

---

## 3. Системные требования и подготовка

- **ОС:** Linux (Ubuntu 20.04/22.04 LTS) или Windows 10/11 с WSL2 + Docker Desktop.
- **Docker:** Docker Engine 20.10+ (с поддержкой Docker BuildKit).
- **Python:** 3.8 или новее.
- **Память и CPU:** От 16 ГБ RAM, 4+ ядер CPU.

### Установка зависимостей Python:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Настройка ядра хоста под AFL (только для Linux/WSL):
```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

---

## 4. Конфигурация (config.yaml)

Все параметры эксперимента, лимиты ресурсов, списки активных фаззеров и уязвимостей настраиваются в файле `config.yaml`:

```yaml
# Ограничения аппаратных ресурсов
resources:
  cpu_per_trial: 1           # Изоляция: ровно 1 физическое ядро на инстанс фаззера
  memory_limit: "4g"         # Лимит RAM на один контейнер
  max_parallel_workers: 4    # Число одновременно работающих контейнеров

# Параметры по умолчанию для кампаний
experiment:
  duration: "12h"            # Длительность кампании (например: 30m, 1h, 8h, 12h)
  trials: 5                  # Количество повторений (триалов) для статистики
  metric_poll_interval: 30   # Частота опроса метрик и проверки крашей (в секундах)

# Список сравниваемых фаззеров (можно временно отключать через enabled: false)
fuzzers:
  - id: "aflgo_mod"
    enabled: true
  - id: "aflgo_orig"
    enabled: true
  - id: "dafl"
    enabled: true
  - id: "fishfuzz"
    enabled: true
  - id: "windranger"
    enabled: true

# Список исследуемых уязвимостей
targets:
  - id: "objdump_dlx"
    enabled: true
  - id: "ffmpeg_rasc"
    enabled: true
  - id: "vlc_vp9"
    enabled: true
  - id: "cares_tcp"
    enabled: true
  - id: "libssh2_packet"
    enabled: true
```

### Просмотр текущей конфигурации:
Вывести сводную таблицу активных фаззеров, целей и ресурсов:
```bash
python3 bench.py info
```

---

## 5. Сборка (Build Phase)

### 5.1. Собрать ВСЁ разом (One-Command)
Команда соберет базовый Docker-образ, образы всех 5 фаззеров и скомпилирует инструментрованные бинарники всех 5 целей под каждый фаззер (25 бинарников):
```bash
python3 bench.py build --all
```

---

### 5.2. Сборка Docker-образов фаззеров
Если требуется пересобрать только окружение или конкретный фаззер:

```bash
# Сборка базового образа (LLVM 11, Clang, Gold Linker):
python3 bench.py build --base

# Сборка конкретного фаззера:
python3 bench.py build --fuzzer aflgo_mod
python3 bench.py build --fuzzer aflgo_orig
python3 bench.py build --fuzzer dafl
python3 bench.py build --fuzzer fishfuzz
python3 bench.py build --fuzzer windranger
```

---

### 5.3. Сборка целей с инструментацией

```bash
# Собрать одну конкретную цель под ВСЕ 5 фаззеров:
python3 bench.py build --target cares_tcp
python3 bench.py build --target libssh2_packet
python3 bench.py build --target vlc_vp9
python3 bench.py build --target ffmpeg_rasc
python3 bench.py build --target objdump_dlx

# Собрать конкретную цель под конкретный фаззер:
python3 bench.py build --target cares_tcp --fuzzer aflgo_mod
python3 bench.py build --target libssh2_packet --fuzzer windranger
```

Скомпилированные исполняемые файлы и сиды сохраняются в:
`storage/binaries/<fuzzer_id>/<target_id>/`

---

## 6. Запуск фаззинг-кампаний (Run Phase)

Каждый инстанс фаззера стартует в изолированном Docker-контейнере с жесткой привязкой к ядру CPU (`--cpuset-cpus`), лимитом памяти и мониторингом крашей AddressSanitizer.

### 6.1. Запуск всех экспериментов
Запуск полного набора кампаний по всем целям и фаззерам:
```bash
# Кампания на 30 минут по 1 повторению на 4 параллельных воркерах:
python3 bench.py run --duration 30m --trials 1 --workers 4

# Полноценный научный эксперимент (например, 5 повторений по 12 часов):
python3 bench.py run --duration 12h --trials 5 --workers 4
```

---

### 6.2. Запуск конкретной цели или фаззера

```bash
# Запустить одну цель на ВСЕХ 5 фаззерах (30 минут):
python3 bench.py run --target cares_tcp --duration 30m
python3 bench.py run --target libssh2_packet --duration 30m
python3 bench.py run --target vlc_vp9 --duration 30m

# Запустить конкретный фаззер на конкретной цели:
python3 bench.py run --target cares_tcp --fuzzer aflgo_mod --duration 30m
python3 bench.py run --target objdump_dlx --fuzzer dafl --duration 1h

# С указанием числа параллельных потоков и повторений:
python3 bench.py run --target libssh2_packet --fuzzer aflgo_mod --trials 3 --duration 1h --workers 3
```

---

## 7. Анализ результатов (Analyze Phase)

После завершения кампаний запустите модуль статистической обработки:
```bash
python3 bench.py analyze
```

### Что делает анализ:
1. Сканирует все триалы в `storage/runs/`.
2. Вычисляет робастные научные метрики: **TTT** (Time-To-Target), **ETT** (Execs-To-Target), **Success Rate**, **Median & IQR**.
3. Выполняет двусторонний тест **Манна-Уитни ($U$-test)** на статистическую значимость ($p$-value).
4. Рассчитывает непараметрический размер эффекта **Варги-Делейни ($\hat{A}_{12}$)** для сравнения `aflgo_mod` с каждым из конкурентов.
5. Генерирует Markdown-отчет со сводными таблицами:  
   `storage/plots/benchmark_report.md`

---

## 8. Структура каталогов

```text
.
├── bench.py               # Главный CLI-оркестратор бенчмарка
├── config.yaml            # Конфигурация целей, фаззеров, таймингов и ядер
├── requirements.txt       # Python-зависимости (scipy, numpy, pyyaml, pandas, matplotlib)
├── .gitignore             # Исключает кэш, бинарники и результаты прогонов
├── docker/
│   ├── base/
│   │   └── Dockerfile     # Базовый образ (LLVM 11, Clang, ASan, OpenSSL, CMake)
│   └── fuzzers/           # Рецепты сборки Docker-образов каждого фаззера
│       ├── aflgo_mod.Dockerfile
│       ├── aflgo_orig.Dockerfile
│       ├── dafl.Dockerfile
│       ├── fishfuzz.Dockerfile
│       └── windranger.Dockerfile
├── targets/               # Рецепты сборки уязвимостей
│   ├── cares_tcp/         # c-ares (harness.c, build.sh, target.yaml, seeds/)
│   ├── ffmpeg_rasc/       # FFmpeg (build.sh, target.yaml)
│   ├── libssh2_packet/    # libssh2 (harness.c, build.sh, target.yaml, seeds/)
│   ├── objdump_dlx/       # GNU Binutils (build.sh, target.yaml, seeds/)
│   └── vlc_vp9/           # VLC Media Player (build.sh, target.yaml)
└── storage/               # Генерируемые данные (не коммитятся в git)
    ├── cache/             # Чистые клоны апстримов уязвимостей
    ├── binaries/          # Скомпилированные инструментрованные бинарники
    ├── runs/              # Логи, результаты прогонов, очереди и краши фаззеров
    └── plots/             # Статистические отчеты и графики
```
