# DGF Benchmark (Directed Greybox Fuzzing)

Автономный, воспроизводимый бенчмарк для сравнительной оценки **5 направленных фаззеров (Directed Greybox Fuzzers)** на реальных уязвимостях из базы `bikini/exploitarium`.

---

## 📑 Содержание
1. [Архитектура и состав](#1-архитектура-и-состав)
2. [Как склонировать ТОЛЬКО папку benchmark на другой ПК](#2-как-склонировать-только-папку-benchmark-на-другой-пк)
3. [Системные требования и подготовка хоста](#3-системные-требования-и-подготовка-хоста)
4. [Конфигурация (config.yaml и target.yaml)](#4-конфигурация-configyaml-и-targetyaml)
5. [Сборка (Build Phase)](#5-сборка-build-phase)
6. [Запуск фаззинг-кампаний (Run Phase)](#6-запуск-фаззинг-кампаний-run-phase)
7. [Сбор результатов и статистический анализ (Analyze Phase)](#7-сбор-результатов-и-статистический-анализ-analyze-phase)
8. [Как добавить новую уязвимость](#8-как-добавить-новую-уязвимость)

---

## 1. Архитектура и состав

Бенчмарк спроектирован так, чтобы в репозитории **не хранились бинарники, архивы или тяжелые исходники**. Всё подтягивается на лету во время сборки через официальные апстримы и Git-репозитории:

### Сравниваемые направленные фаззеры (5 DGF):
| Фаззер | Архитектура / Принцип наведения | Источник загрузки |
| :--- | :--- | :--- |
| **`aflgo_orig`** | Базовый эталон (Vanilla AFLGo, CCS '17) | Репозиторий `cooN4i/aflgo-research` (ветка `develop`) |
| **`aflgo_mod`** | Кандидат (Учет сложности блоков + Доминаторы) | Репозиторий `cooN4i/aflgo-research` (ветка `develop`) |
| **`dafl`** | Селективная инструментация и скоринг (USENIX Sec '23) | Официальный GitHub: `prosyslab/DAFL` |
| **`fishfuzz`** | Мульти-дистанции и динамический ранкинг (USENIX Sec '23) | Официальный GitHub: `HexHive/FishFuzz` |
| **`windranger`** | Блоки отклонения DBB + статический анализ `cbi` (ICSE '22) | Канонический билд: `prosyslab/DAFL-artifact` |

### Тестовые цели (Real-world Bugs из exploitarium):
1. **`objdump_dlx`** — GNU Binutils `objdump` (DLX ELF OOB Write, `elf32-dlx.c:1340`)
2. **`ffmpeg_rasc`** — FFmpeg RASC Decoder (`decode_dlta` OOB Write)
3. **`vlc_vp9`** — FFmpeg/VLC VP9 Video Decoder (Slice-Thread Memory Corruption)
4. **`cares_tcp`** — c-ares C DNS Resolver Library (`ares_getaddrinfo` Use-After-Free)
5. **`libssh2_packet`** — libssh2 SSH Transport (`packet_length` Integer Wrap / Out-of-bounds)

---

## 2. Как склонировать ТОЛЬКО папку benchmark на другой ПК

Чтобы не скачивать весь репозиторий с историей и другими ветками, на новом компьютере используется штатный механизм **Git Sparse Checkout** (частичный клон).

### Для Linux / macOS:
```bash
# 1. Создаем папку и инициализируем репозиторий без скачивания файлов
git clone --depth 1 --filter=blob:none --sparse -b develop https://github.com/cooN4i/aflgo-research.git
cd aflgo-research

# 2. Указываем скачать ТОЛЬКО папку benchmark
git sparse-checkout set benchmark

# 3. Переходим в бенчмарк
cd benchmark
```

### Для Windows (PowerShell):
```powershell
# 1. Клонируем только структуру ветки develop
git clone --depth 1 --filter=blob:none --sparse -b develop https://github.com/cooN4i/aflgo-research.git
cd aflgo-research

# 2. Скачиваем исключительно папку benchmark
git sparse-checkout set benchmark

# 3. Переходим в папку бенчмарка
cd benchmark
```

*(Опционально)* Если вы хотите извлечь `benchmark` как самостоятельный корень без внешней папки:
```bash
mv benchmark ../dgf-benchmark && cd ../dgf-benchmark && rm -rf ../aflgo-research
```

---

## 3. Системные требования и подготовка хоста

### Требования к оборудованию и ПО:
- **ОС:** Linux (Ubuntu 20.04/22.04 LTS рекомендуется) или Windows 10/11 с WSL2 + Docker Desktop.
- **Docker:** Docker Engine 20.10+ (с поддержкой Docker BuildKit).
- **Python:** 3.8 или новее.
- **RAM:** Рекомендуется от 16 ГБ (минимум 4 ГБ на 1 параллельный контейнер).
- **CPU:** 4+ ядер (каждому инстансу фаззера изолированно выделяется ровно 1 физическое ядро).

### Шаг 3.1. Установка Python-зависимостей:
Внутри папки `benchmark` выполните:
```bash
pip install -r requirements.txt
```

### Шаг 3.2. Настройка ядра Linux под AFL (только для Linux-хостов):
AFL требует корректной обработки крашей и отключения энергосбережения CPU:
```bash
# Установить шаблон именования core dump (чтобы AFL не перехватывал сторонние дампы)
echo core | sudo tee /proc/sys/kernel/core_pattern

# Перевести процессор в режим максимальной производительности (performance governor)
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

---

## 4. Конфигурация (config.yaml и target.yaml)

Все глобальные параметры эксперимента задаются в файле `config.yaml`.

### Структура `config.yaml`:
```yaml
# ------------------------------------------------------------------------------
# Ограничения ресурсов
# ------------------------------------------------------------------------------
resources:
  cpu_per_trial: 1           # Жесткая изоляция: ровно 1 ядро CPU на инстанс фаззера
  memory_limit: "4g"         # Лимит оперативной памяти на контейнер (защита от ООМ)
  max_parallel_workers: 4    # Количество одновременно работающих контейнеров

# ------------------------------------------------------------------------------
# Параметры кампании
# ------------------------------------------------------------------------------
experiment:
  duration: "12h"            # Длительность одной сессии (например: 10m, 1h, 8h, 12h, 24h)
  trials: 5                  # Количество повторений (для стат. значимости нужно >= 5)
  metric_poll_interval: 30   # Частота опроса метрик и проверки крашей (в секундах)

# ------------------------------------------------------------------------------
# Список уязвимостей
# ------------------------------------------------------------------------------
targets:
  - id: "objdump_dlx"
    name: "GNU Binutils objdump (DLX ELF OOB Write)"
    path: "targets/objdump_dlx"
    enabled: true            # Можно выключить цель, установив false

  - id: "ffmpeg_rasc"
    path: "targets/ffmpeg_rasc"
    enabled: true

  - id: "vlc_vp9"
    path: "targets/vlc_vp9"
    enabled: true

  - id: "cares_tcp"
    path: "targets/cares_tcp"
    enabled: true

  - id: "libssh2_packet"
    path: "targets/libssh2_packet"
    enabled: true
```

### Проверка конфигурации:
Чтобы убедиться, что все пути и синтаксис корректны, запустите:
```bash
python bench.py info
```
Команда выведет сводную таблицу всех 5 фаззеров, 5 целей и активных метрик.

---

## 5. Сборка (Build Phase)

Сборка состоит из двух этапов:
1. Сборка Docker-образов инструментов (Base + 5 фаззеров).
2. Сборка бинарников уязвимых программ с инструментацией под каждый фаззер.

### Шаг 5.1. Сборка базового Docker-образа:
Базовый образ содержит LLVM 11, Clang 11, компилятор с Gold Linker и научные библиотеки:
```bash
python bench.py build --base
```

### Шаг 5.2. Сборка образов фаззеров:
Каждый образ автоматически скачивает свой исходный код и компилирует инструментарий:
```bash
# Сборка отдельных фаззеров:
python bench.py build --fuzzer aflgo_mod
python bench.py build --fuzzer aflgo_orig
python bench.py build --fuzzer dafl
python bench.py build --fuzzer fishfuzz
python bench.py build --fuzzer windranger
```

> [!TIP]
> **Сборка из другой ветки:**  
> По умолчанию `aflgo_mod` и `aflgo_orig` скачиваются из ветки `develop`. Если вы хотите протестировать отдельную ветку, просто укажите флаг `--branch`:
> ```bash
> python bench.py build --fuzzer aflgo_mod --branch feature/my-new-formula
> ```
> Оркестратор автоматически определит SHA последнего коммита на GitHub и передаст его в Docker, сбросив кэш только для свежего кода.

### Шаг 5.3. Компиляция целей (инструментация бинарников):
Оркестратор скачает точные коммиты программ из апстримов и выполнит двухпроходную инструментацию:
```bash
# Собрать конкретную цель под конкретный фаззер:
python bench.py build --target objdump_dlx --fuzzer aflgo_mod

# Или собрать все цели под все активные фаззеры:
python bench.py build --all
```
Скомпилированные бинарники и сиды сохраняются в папку:  
`storage/binaries/<fuzzer_id>/<target_id>/`

---

## 6. Запуск фаззинг-кампаний (Run Phase)

Оркестратор запускает фаззеры в изолированных Docker-контейнерах с жесткой привязкой к ядрам CPU (`--cpuset-cpus`) и автоматическим отслеживанием крашей.

### 6.1. Быстрый тестовый запуск (Smoke-тест на 10 минут):
Для быстрой проверки, что вся цепочка работает корректно:
```bash
python bench.py run --target objdump_dlx --fuzzer aflgo_mod --trials 1 --duration 10m
```

### 6.2. Полноценный научный эксперимент:
Для получения академически достоверных результатов (5 повторений по 12 часов):
```bash
python bench.py run --trials 5 --duration 12h --workers 4
```
Параметр `--workers 4` означает, что одновременно будут крутиться 4 контейнера на ядрах 0, 1, 2, 3. Как только один заканчивается, пул автоматически стартует следующий.

### 6.3. Что происходит во время работы (Real-time ASan Triage):
1. Оркестратор каждые `metric_poll_interval` секунд считывает директорию `out/crashes`.
2. При обнаружении нового тесткейса оркестратор **немедленно запускает верификацию через AddressSanitizer**.
3. Символизированный стек-трейс сопоставляется с целевой строкой бага (`target_line`, например `elf32-dlx.c:1340`).
4. Если баг совпал, фиксируется **Time-To-Target (TTT)** и количество выполненных тестов **Execs-To-Target (ETT)**, а в консоль выводится сообщение:
   ```text
   [+] >>> BUG TRIGGERED! [aflgo_mod on objdump_dlx Trial 1] <<<
       Time-to-Target (TTT): 1420.5s | Execs: 342,109
   ```

---

## 7. Сбор результатов и статистический анализ (Analyze Phase)

Все сырые данные (краши, очереди, `fuzzer_stats`, логи ASan) сохраняются в:
```text
storage/runs/<fuzzer_id>/<target_id>/trial_<idx>/
  ├── in/               # Сиды
  ├── out/              # Результаты AFL (crashes, queue, fuzzer_stats)
  └── trial_result.json # JSON-отчет триала (TTT, ETT, статус, стек-трейс)
```

### Запуск статистического модуля:
```bash
python bench.py analyze
```

### Что делает анализ:
1. **Медиана и интерквартильный размах (Median & IQR):**  
   Для каждой связки (цель, фаззер) рассчитываются робастные метрики TTT и ETT, устойчивые к выбросам (в соответствии с рекомендациями *Klees et al., IEEE S&P '18*).
2. **Процент воспроизведения (Success Rate):**  
   Доля запусков, успешно триггернувших уязвимость за отведенный таймаут.
3. **Двусторонний тест Манна-Уитни ($U$-test):**  
   Проверяет гипотезу статистического превосходства модификации над базовой линией `aflgo_orig`. Значение $p < 0.05$ подтверждает статистическую значимость.
4. **Размер эффекта Варги-Делейни ($\hat{A}_{12}$):**  
   Показывает вероятность того, что кандидатный фаззер быстрее найдет баг, чем базовый:
   - $\hat{A}_{12} > 0.5$ — кандидат превосходит baseline;
   - $\hat{A}_{12} \ge 0.71$ — большой размер эффекта (large effect size).

Итоговый Markdown-отчет сохраняется в `storage/plots/benchmark_report.md`.

---

## 8. Как добавить новую уязвимость

Чтобы подключить новую цель из `exploitarium` или собственной практики:

1. Создайте каталог `targets/<my_target>/`.
2. Добавьте манифест `target.yaml`:
   ```yaml
   target:
     id: "my_target"
     name: "Target Name"
     repo_url: "https://github.com/example/repo.git"
     commit: "abcdef123456"
     vulnerability:
       target_line: "source_file.c:123"
   fuzzing:
     target_args: "@@"
   ```
3. Создайте скрипт `build.sh` (по аналогии с [objdump_dlx/build.sh](targets/objdump_dlx/build.sh)), поддерживающий генерацию графов (Pass 1), расчет дистанций и финальную сборку (Pass 2).
4. Зарегистрируйте цель в `config.yaml`.
