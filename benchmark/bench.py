#!/usr/bin/env python3
"""
Custom Directed Fuzzing Benchmark Orchestrator (bench.py)
Manages Build, Execution, Real-time Triage, and Statistical Analysis
for comparing Directed Greybox Fuzzers (AFLGo-orig, AFLGo-mod, DAFL).
"""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import yaml
except ImportError:
    print("[!] PyYAML not installed. Run: pip install pyyaml")
    sys.exit(1)

# Auto-recover from WSL2 / DrvFS stale directory inode (avoids getcwd() FileNotFoundError)
def _recover_wsl_cwd():
    try:
        os.getcwd()
        return
    except (FileNotFoundError, OSError):
        pass

    pwd = os.environ.get("PWD")
    if pwd and os.path.exists(pwd):
        try:
            os.chdir(pwd)
            return
        except OSError:
            pass

    try:
        if os.path.isabs(__file__):
            script_dir = os.path.dirname(__file__)
        else:
            script_dir = os.path.dirname(os.path.join(pwd or "", __file__))
        if script_dir and os.path.exists(script_dir):
            os.chdir(script_dir)
            return
    except Exception:
        pass

    try:
        os.chdir(".")
    except OSError:
        pass

_recover_wsl_cwd()

try:
    BENCH_ROOT = Path(__file__).resolve().parent
except Exception:
    pwd = os.environ.get("PWD")
    if pwd and os.path.exists(pwd):
        BENCH_ROOT = Path(pwd)
    else:
        BENCH_ROOT = Path(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = BENCH_ROOT / "config.yaml"
STORAGE_DIR = BENCH_ROOT / "storage"
CACHE_DIR = STORAGE_DIR / "cache"
BINARIES_DIR = STORAGE_DIR / "binaries"
RUNS_DIR = STORAGE_DIR / "runs"
PLOTS_DIR = STORAGE_DIR / "plots"

def _detect_host_workdir() -> Optional[str]:
    # 1. Explicit env var
    hw = os.environ.get("HOST_WORKDIR")
    if hw:
        return hw
    # 2. Auto-detect from container inspect (Docker-outside-of-Docker host path discovery)
    for cname in ["dgf-benchmark-orchestrator", os.environ.get("HOSTNAME", "")]:
        if not cname:
            continue
        try:
            res = subprocess.run(
                ["docker", "inspect", cname],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if data and isinstance(data, list):
                    mounts = data[0].get("Mounts", [])
                    for m in mounts:
                        if m.get("Destination") == "/benchmark":
                            src = m.get("Source")
                            if src:
                                return src
        except Exception:
            pass
    return None


HOST_WORKDIR = _detect_host_workdir()


def to_docker_host_path(p: Union[str, Path]) -> str:
    """Translates a path to the host Docker daemon perspective when running inside an orchestrator container."""
    p_obj = Path(p).resolve()
    if HOST_WORKDIR:
        try:
            rel = p_obj.relative_to(BENCH_ROOT.resolve())
            return str(Path(HOST_WORKDIR) / rel).replace(os.sep, "/")
        except ValueError:
            pass
    return str(p_obj).replace(os.sep, "/")


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        print(f"[!] Config file not found at {CONFIG_PATH}")
        sys.exit(1)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_duration(duration_str: str) -> int:
    """Parses duration string like '12h', '30m', '3600s' into seconds."""
    duration_str = duration_str.strip().lower()
    if duration_str.endswith("h"):
        return int(float(duration_str[:-1]) * 3600)
    elif duration_str.endswith("m"):
        return int(float(duration_str[:-1]) * 60)
    elif duration_str.endswith("s"):
        return int(float(duration_str[:-1]))
    return int(duration_str)


def safe_mkdir(path: Path):
    """Safely creates directories, ignoring transient NTFS/DrvFS EEXIST errors."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except FileExistsError:
        pass


# ==============================================================================
# Command: info
# ==============================================================================
def cmd_info(args, config: Dict[str, Any]):
    print("=" * 75)
    print(f" {config['benchmark']['name']} (v{config['benchmark']['version']})")
    print("=" * 75)
    print(f"Description : {config['benchmark']['description']}")
    print(f"Duration    : {config['experiment']['duration']} per trial")
    print(f"Trials      : {config['experiment']['trials']} repetitions per target/fuzzer")
    print(f"CPU limit   : {config['resources']['cpu_per_trial']} core(s) per container")
    print(f"RAM limit   : {config['resources']['memory_limit']}")
    print("-" * 75)
    print("Competing Fuzzers:")
    for f in config['fuzzers']:
        role = "[BASELINE]" if f.get("baseline") else "[CANDIDATE]"
        print(f"  - {f['id']:<15} {role:<12} ({f['name']})")
    print("-" * 75)
    print("Benchmark Targets (from bikini/exploitarium):")
    for t in config['targets']:
        status = "ENABLED" if t.get("enabled", True) else "DISABLED"
        print(f"  - {t['id']:<15} [{status}] {t['name']}")
    print("-" * 75)
    print("Approved Evaluation Metrics:")
    for m in config['metrics']:
        print(f"  - {m['id']:<25}: {m['name']}")
    print("=" * 75)


# ==============================================================================
# Command: build
# ==============================================================================
def docker_image_exists(tag: str) -> bool:
    try:
        res = subprocess.run(["docker", "image", "inspect", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


def build_base_image():
    if docker_image_exists("dgf-base:latest") or docker_image_exists("dgf-base"):
        print("[+] Base Docker Image 'dgf-base' already exists (skipping build).\n")
        return

    print("[*] Building Base Docker Image (dgf-base)...")
    base_dockerfile = BENCH_ROOT / "docker" / "base" / "Dockerfile"
    cmd = [
        "docker", "build",
        "-t", "dgf-base",
        "-f", str(base_dockerfile),
        str(BENCH_ROOT / "docker" / "base")
    ]
    subprocess.run(cmd, check=True)
    print("[+] Base Docker Image built successfully.\n")


def get_remote_branch_sha(repo_url: str, branch: str) -> Optional[str]:
    try:
        res = subprocess.run(["git", "ls-remote", repo_url, f"refs/heads/{branch}"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().split()[0]
    except Exception:
        pass
    try:
        import urllib.request
        api_url = f"https://api.github.com/repos/cooN4i/aflgo-research/commits/{branch}"
        req = urllib.request.Request(api_url, headers={"User-Agent": "DGF-Benchmark"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get("sha")
    except Exception:
        pass
    return None


def build_fuzzer_image(fuzzer_id: str, branch: str = "develop"):
    image_tag = f"dgf-fuzzer-{fuzzer_id}"
    if docker_image_exists(f"{image_tag}:latest") or docker_image_exists(image_tag):
        print(f"[+] Fuzzer Image '{image_tag}' already exists (skipping build).\n")
        return

    print(f"[*] Building Fuzzer Docker Image for {fuzzer_id}...")
    fuzzers_dir = BENCH_ROOT / "docker" / "fuzzers"
    dockerfiles = {
        "aflgo_mod": fuzzers_dir / "aflgo_mod.Dockerfile",
        "aflgo_orig": fuzzers_dir / "aflgo_orig.Dockerfile",
        "dafl": fuzzers_dir / "dafl.Dockerfile",
        "fishfuzz": fuzzers_dir / "fishfuzz.Dockerfile",
        "windranger": fuzzers_dir / "windranger.Dockerfile",
    }
    if fuzzer_id not in dockerfiles:
        print(f"[!] Unknown fuzzer: {fuzzer_id}")
        return

    dockerfile = dockerfiles[fuzzer_id]
    image_tag = f"dgf-fuzzer-{fuzzer_id}"
    cmd = [
        "docker", "build",
        "-t", image_tag,
        "-f", str(dockerfile),
    ]

    if fuzzer_id in ("aflgo_mod", "aflgo_orig"):
        cmd.extend(["--build-arg", f"REPO_BRANCH={branch}"])
        sha = get_remote_branch_sha("https://github.com/cooN4i/aflgo-research.git", branch)
        if sha:
            cmd.extend(["--build-arg", f"COMMIT_SHA={sha}"])
            print(f"    [+] Pinning {fuzzer_id} to commit {sha[:8]} on branch '{branch}'")
        else:
            print(f"    [*] Using branch '{branch}' for {fuzzer_id}")

    cmd.append(str(fuzzers_dir))
    print(f"    Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"[+] Fuzzer {image_tag} built successfully.\n")


def clone_target_source(target: Dict[str, Any], cache_dir: Path):
    target_id = target['id']
    target_cache = cache_dir / target_id
    if target_cache.exists() and (target_cache / ".git").exists():
        print(f"    [+] Source cached for {target_id} at {target_cache}")
        return target_cache

    print(f"[*] Cloning source for {target_id} at commit {target.get('commit', 'HEAD')}...")
    safe_mkdir(target_cache)

    # Use shallow fetch of exact commit for fast download
    repo_url = target['repo_url']
    commit = target['commit']

    subprocess.run(["git", "init"], cwd=target_cache, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=target_cache, check=True)
    subprocess.run(["git", "remote", "add", "origin", repo_url], cwd=target_cache, check=True, stdout=subprocess.DEVNULL)
    print(f"    Fetching commit {commit}...")
    subprocess.run(["git", "fetch", "--depth", "1", "origin", commit], cwd=target_cache, check=True)
    try:
        subprocess.run(["git", "checkout", "FETCH_HEAD"], cwd=target_cache, check=True)
    except subprocess.CalledProcessError:
        # Fallback for Windows path compatibility (e.g. libming files containing ':')
        subprocess.run(["git", "checkout", "-f", "FETCH_HEAD", "--", ":!docs/perl*", ":!docs/perlman*"], cwd=target_cache, check=True)
    print(f"[+] Cloned {target_id} successfully.")
    return target_cache


def build_target_binary(target: Dict[str, Any], fuzzer: Dict[str, Any], config: Dict[str, Any], force: bool = False):
    target_id = target['id']
    fuzzer_id = fuzzer['id']
    print(f"\n=======================================================")
    print(f"[*] Compiling Target '{target_id}' with Fuzzer '{fuzzer_id}'")
    print(f"=======================================================")

    recipe_dir = (BENCH_ROOT / target['path']).resolve()
    target_yaml_path = recipe_dir / "target.yaml"
    if not target_yaml_path.exists():
        print(f"[!] Target recipe not found: {target_yaml_path}")
        return False

    with open(target_yaml_path, "r", encoding="utf-8") as f:
        target_info = yaml.safe_load(f)['target']

    out_dir = (BINARIES_DIR / fuzzer_id / target_id).resolve()
    safe_mkdir(out_dir)

    # Copy seeds and dictionary into out_dir for trial use
    seeds_src = recipe_dir / "seeds"
    if seeds_src.exists():
        seeds_dst = out_dir / "seeds"
        if seeds_dst.exists():
            shutil.rmtree(seeds_dst)
        shutil.copytree(seeds_src, seeds_dst)

    # Check if target binary already exists to avoid redundant recompilation
    candidates = [c for c in out_dir.glob(f"{target_id}*") if c.is_file() and c.stat().st_size > 0]
    if candidates and not force:
        print(f"[+] Binary for target '{target_id}' with fuzzer '{fuzzer_id}' already exists -> {candidates[0]} (skipping build).")
        return True

    # Clone source to cache if not present
    safe_mkdir(CACHE_DIR)
    source_cache = clone_target_source(target_info, CACHE_DIR)

    # Run compilation inside fuzzer container
    image_tag = f"dgf-fuzzer-{fuzzer_id}"
    container_name = f"dgf_build_{fuzzer_id}_{target_id}_{int(time.time())}"

    # Build script runs inside container
    docker_cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "-e", "ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:use_sigaltstack=0",
        "-v", f"{to_docker_host_path(recipe_dir)}:/recipe:ro",
        "-v", f"{to_docker_host_path(source_cache)}:/src_cache:ro",
        "-v", f"{to_docker_host_path(out_dir)}:/out",
        image_tag,
        "bash", "-c",
        f"""
        set -euo pipefail
        trap 'for l in /work/*.log; do if [ -f "$l" ]; then echo "=== LOG: $l ==="; cat "$l"; fi; done' ERR
        export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:use_sigaltstack=0"
        export PATH="/usr/lib/llvm-11/bin:$PATH"
        if [ ! -f /usr/bin/opt ] && [ -f /usr/lib/llvm-11/bin/opt ]; then
            ln -sf /usr/lib/llvm-11/bin/opt /usr/bin/opt 2>/dev/null || true
        fi
        chmod -R +x /fuzzer 2>/dev/null || true
        if [ -d "/fuzzer/dafl" ]; then export AFL_PATH="/fuzzer/dafl"; fi
        if [ -d "/fuzzer/WindRanger/fuzz" ]; then export AFL_PATH="/fuzzer/WindRanger/fuzz"; fi
        if [ -d "/fuzzer/fishfuzz/FF_AFL" ]; then export AFL_PATH="/fuzzer/fishfuzz/FF_AFL"; fi
        if [ -d "/fuzzer/aflgo-mod/instrument" ]; then export AFL_PATH="/fuzzer/aflgo-mod/instrument"; fi
        if [ -d "/fuzzer/aflgo-orig/instrument" ]; then export AFL_PATH="/fuzzer/aflgo-orig/instrument"; fi
        mkdir -p /src/{target_id} /work /tmp/recipe
        cp -a /recipe/. /tmp/recipe/
        tr -d '\\r' < /recipe/build.sh > /tmp/recipe/build.sh
        chmod +x /tmp/recipe/build.sh
        if [ -d /src_cache/.git ]; then
            tar --exclude=.git --exclude='./gdb' --exclude='./sim' --exclude='ld/testsuite' --exclude='gas/testsuite' --exclude='binutils/testsuite' --exclude='gold/testsuite' -cf - -C /src_cache . | tar -xf - -C /src/{target_id}/
        else
            cp -a /src_cache/. /src/{target_id}/
        fi
        cd /src/{target_id}
        find . -type f \\( -name "configure*" -o -name "*.sh" -o -name "*.ac" -o -name "*.in" -o -name "config.*" -o -name "mkinstalldirs" -o -name "install-sh" -o -name "depcomp" -o -name "compile" -o -name "move-if-change" -o -name "*.sed" \\) | xargs sed -i 's/\\r$//' 2>/dev/null || true
        ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:use_sigaltstack=0" SRC_DIR="/src/{target_id}" WORK_DIR="/work" OUT_DIR="/out" /tmp/recipe/build.sh all
        """
    ]

    print(f"[*] Running compilation container...")
    res = subprocess.run(docker_cmd)
    if res.returncode != 0:
        print(f"[!] Compilation failed for {target_id} with {fuzzer_id} (exit code {res.returncode})!")
        return False

    # Verify that the expected instrumented binary was produced and is non-empty
    candidates = [c for c in out_dir.glob(f"{target_id}*") if c.is_file() and c.stat().st_size > 0]
    if not candidates:
        print(f"[!] Compilation completed, but no non-empty binary matching '{target_id}*' was found in {out_dir}!")
        return False

    print(f"[+] Successfully built target {target_id} with {fuzzer_id} -> {candidates[0]} ({candidates[0].stat().st_size:,} bytes)")
    return True


def cmd_build(args, config: Dict[str, Any]):
    print("[*] Starting Benchmark Build Phase...")

    # 1. Base image
    if args.base or args.all:
        build_base_image()

    # 2. Fuzzers
    fuzzers_to_build = []
    if args.fuzzer:
        fuzzers_to_build = [f for f in config['fuzzers'] if f['id'] == args.fuzzer and f.get('enabled', True)]
    elif args.all:
        fuzzers_to_build = [f for f in config['fuzzers'] if f.get('enabled', True)]

    branch = getattr(args, 'branch', 'develop') or 'develop'
    for f in fuzzers_to_build:
        build_fuzzer_image(f['id'], branch=branch)

    # 3. Targets
    targets_to_build = []
    if args.target:
        targets_to_build = [t for t in config['targets'] if t['id'] == args.target]
    elif args.all or (not args.base and not args.fuzzer):
        targets_to_build = [t for t in config['targets'] if t.get('enabled', True)]

    active_fuzzers = [f for f in config['fuzzers'] if (args.fuzzer is None or f['id'] == args.fuzzer) and f.get('enabled', True)]

    force_build = getattr(args, 'force', False)
    for t in targets_to_build:
        for f in active_fuzzers:
            success = build_target_binary(t, f, config, force=force_build)
            if not success:
                print(f"\n[FATAL] Compilation failed for target '{t['id']}' with fuzzer '{f['id']}'. Stopping build immediately!")
                sys.exit(1)


# ==============================================================================
# Command: run (Execution & Real-time Crash Triage)
# ==============================================================================
def is_target_in_stack_frames(stack_trace: str, target_loc: str, max_depth: int = 5) -> bool:
    """
    Parses ASan and GDB stack traces frame-by-frame and checks
    if target file and line match accurately in the top `max_depth` stack frames.
    Prevents false positives from line numbers in addresses or unrelated callers.
    """
    if not target_loc or not stack_trace:
        return False

    if ":" in target_loc:
        t_file_part, t_line_part = target_loc.split(":", 1)
        target_file = Path(t_file_part.strip()).name
        try:
            target_line = int(t_line_part.strip())
        except ValueError:
            target_line = None
    else:
        target_file = Path(target_loc.strip()).name
        target_line = None

    frame_patterns = [
        # GDB frame format: #0  0x... in func (...) at /path/to/file.c:4319
        re.compile(r'^\s*#(?P<frame>\d+)\s+.*?\bat\s+(?P<file>[^\s:]+):(?P<line>\d+)'),
        # ASan frame format: #0 0x... in func /path/to/file.c:4319:12 or :4319
        re.compile(r'^\s*#(?P<frame>\d+)\s+0x[0-9a-fA-F]+\s+(?:in\s+\S+\s+)?(?:\(|at\s+)?(?P<file>[^\s\(\):]+):(?P<line>\d+)(?::\d+)?'),
        # Generic frame format: #0 ... file.c:123
        re.compile(r'^\s*#(?P<frame>\d+)\s+.*?(?:\s|\()(?P<file>[a-zA-Z0-9_\-\.\/]+\.[a-zA-Z0-9_\-]+):(?P<line>\d+)'),
    ]

    for line in stack_trace.splitlines():
        line = line.strip()
        if not line.startswith("#"):
            continue
        for pat in frame_patterns:
            m = pat.match(line)
            if m:
                frame_idx = int(m.group("frame"))
                if frame_idx >= max_depth:
                    break
                f_name = Path(m.group("file")).name
                f_line = int(m.group("line"))
                if f_name == target_file:
                    if target_line is None or abs(f_line - target_line) <= 5:
                        return True
                break

    return False


def triage_crash(target_bin: str, target_args: str, crash_path: Path, target_loc: str, image_tag: str) -> Tuple[bool, str]:
    """
    Runs the crashing input inside a container and checks
    if the target bug line appears in the top stack frames (via ASan or GDB).
    """
    crash_file = f"/crash_dir/{crash_path.name}"
    if "@@" in target_args:
        run_cmd = f"/bin_dir/{Path(target_bin).name} {target_args.replace('@@', crash_file)}"
        gdb_run = f"r {target_args.replace('@@', crash_file)}"
    else:
        run_cmd = f"/bin_dir/{Path(target_bin).name} {target_args} < {crash_file}"
        gdb_run = f"r {target_args} < {crash_file}"

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{to_docker_host_path(crash_path.parent)}:/crash_dir:ro",
        "-v", f"{to_docker_host_path(Path(target_bin).parent)}:/bin_dir:ro",
        "-e", "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0:use_sigaltstack=0",
        "-e", "ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-11/bin/llvm-symbolizer",
        "-e", "PATH=/usr/lib/llvm-11/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        image_tag,
        "bash", "-c", run_cmd
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    stack_trace = res.stderr + "\n" + res.stdout

    # Verification: check if target file and line match accurately in top stack frames
    matched = is_target_in_stack_frames(stack_trace, target_loc, max_depth=5)

    # If not matched directly, run with GDB to capture backtrace on native SIGSEGV
    if not matched and res.returncode != 0:
        gdb_cmd = [
            "docker", "run", "--rm",
            "-v", f"{to_docker_host_path(crash_path.parent)}:/crash_dir:ro",
            "-v", f"{to_docker_host_path(Path(target_bin).parent)}:/bin_dir:ro",
            image_tag,
            "bash", "-c", f"gdb -batch -ex \"{gdb_run}\" -ex \"bt\" /bin_dir/{Path(target_bin).name}"
        ]
        gdb_res = subprocess.run(gdb_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
        gdb_trace = gdb_res.stdout + "\n" + gdb_res.stderr
        if is_target_in_stack_frames(gdb_trace, target_loc, max_depth=5):
            matched = True
            stack_trace = gdb_trace

    return matched, stack_trace


def check_inputs_reach_batch(target_bin: str, target_args: str, input_paths: List[Path], target_loc: str, image_tag: str) -> Optional[Tuple[str, Path]]:
    """
    Checks a batch of input files inside a single container execution.
    Returns (hit_filename, hit_path) if any input executes target_loc (via GDB breakpoint), else None.
    """
    if not input_paths or not target_loc:
        return None

    queue_dir = input_paths[0].parent
    file_names = [p.name for p in input_paths]

    if ":" in target_loc:
        t_file = Path(target_loc.split(":", 1)[0].strip()).name
        try:
            t_line = int(target_loc.split(":", 1)[1].strip())
        except ValueError:
            t_line = None
    else:
        t_file = Path(target_loc.strip()).name
        t_line = None

    runner_script = f"""
import subprocess, sys, re, os
from pathlib import Path

target_bin = '/bin_dir/{Path(target_bin).name}'
target_loc = '{target_loc}'
target_file = '{t_file}'
target_line = {t_line if t_line is not None else 'None'}
target_args = '{target_args}'
file_names = {json.dumps(file_names)}

hit_pat = re.compile(r'Breakpoint\\s+\\d+,\\s+.*?\\bat\\s+(?P<file>[^\\s:]+):(?P<line>\\d+)')

for fname in file_names:
    fpath = f'/queue_dir/{{fname}}'
    if '@@' in target_args:
        gdb_run = f'r {{target_args.replace("@@", fpath)}}'
    else:
        gdb_run = f'r {{target_args}} < {{fpath}}'

    cmd = ['gdb', '-batch', '-ex', f'b {{target_loc}}', '-ex', gdb_run, target_bin]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
    out = res.stdout + '\\n' + res.stderr

    for line in out.splitlines():
        m = hit_pat.search(line)
        if m:
            fname_matched = Path(m.group('file')).name
            fline_matched = int(m.group('line'))
            if fname_matched == target_file:
                if target_line is None or abs(fline_matched - target_line) <= 5:
                    print(f'TARGET_REACH_HIT:{{fname}}')
                    sys.exit(0)
"""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{to_docker_host_path(queue_dir)}:/queue_dir:ro",
        "-v", f"{to_docker_host_path(Path(target_bin).parent)}:/bin_dir:ro",
        image_tag,
        "python3", "-c", runner_script
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    for line in res.stdout.splitlines():
        if line.startswith("TARGET_REACH_HIT:"):
            hit_name = line.split(":", 1)[1].strip()
            for p in input_paths:
                if p.name == hit_name:
                    return hit_name, p

    return None


def run_single_trial(fuzzer: Dict[str, Any], target: Dict[str, Any], trial_idx: int,
                     duration_sec: int, cpu_core: int, config: Dict[str, Any]) -> Dict[str, Any]:
    fuzzer_id = fuzzer['id']
    target_id = target['id']
    bin_dir = (BINARIES_DIR / fuzzer_id / target_id).resolve()
    target_recipe_dir = (BENCH_ROOT / target['path']).resolve()

    with open(target_recipe_dir / "target.yaml", "r", encoding="utf-8") as f:
        target_info = yaml.safe_load(f)

    target_loc = target_info['target']['vulnerability']['target_line']
    target_args = target_info['fuzzing'].get('target_args', '@@')

    # Find compiled binary
    candidates = [c for c in bin_dir.glob(f"{target_id}*") if c.is_file()]
    if not candidates:
        return {
            "fuzzer": fuzzer_id,
            "target": target_id,
            "trial": trial_idx,
            "status": "ERROR",
            "error": f"Binary not found in {bin_dir}. Did you run 'bench.py build --target={target_id}' first?"
        }
    target_bin = str(candidates[0])

    run_dir = (RUNS_DIR / fuzzer_id / target_id / f"trial_{trial_idx}").resolve()
    in_dir = run_dir / "in"
    out_dir = run_dir / "out"

    # Reset out_dir to ensure AFL starts cleanly without 'at-risk data found in /out'
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)

    run_dir.mkdir(parents=True, exist_ok=True)
    in_dir.mkdir(exist_ok=True)
    out_dir.mkdir(exist_ok=True)

    # Populate seeds
    seeds_dir = bin_dir / "seeds"
    if seeds_dir.exists():
        for s in seeds_dir.iterdir():
            if s.is_file():
                shutil.copy(s, in_dir / s.name)
    if not any(in_dir.iterdir()):
        (in_dir / "seed.txt").write_bytes(b"A" * 16)

    container_name = f"dgf_run_{fuzzer_id}_{target_id}_t{trial_idx}_{int(time.time())}"
    image_tag = f"dgf-fuzzer-{fuzzer_id}"
    memory_limit = config['resources']['memory_limit']
    cooling_time = max(int(duration_sec * 0.8), 60)

    # AFL command customized for each fuzzer architecture
    if fuzzer_id in ("aflgo_mod", "aflgo_orig", "windranger"):
        afl_cmd = f"cd /target && afl-fuzz -m none -t 1000+ -z exp -c {cooling_time}s -i /in -o /out -- /target/{Path(target_bin).name} {target_args}"
    else:
        # DAFL, FishFuzz (compile-time / runtime distance model without -z/-c)
        afl_cmd = f"cd /target && afl-fuzz -m none -t 1000+ -i /in -o /out -- /target/{Path(target_bin).name} {target_args}"

    docker_run_cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        f"--cpuset-cpus={cpu_core}",
        f"-m={memory_limit}",
        "-e", "AFL_NO_UI=1",
        "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_NO_AFFINITY=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
        "-e", "ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0:use_sigaltstack=0",
    ]
    if fuzzer_id == "fishfuzz":
        docker_run_cmd.extend(["-e", "TMP_DIR=/target/TEMP"])
        (bin_dir / "TEMP" / "runtimes").mkdir(parents=True, exist_ok=True)
        calldst = bin_dir / "TEMP" / "runtimes" / "calldst.json"
        if not calldst.exists():
            calldst.write_text("{}")
    elif fuzzer_id == "windranger":
        for fn in ("distance.txt", "targets.txt", "condition_info.txt"):
            fpath = bin_dir / fn
            if not fpath.exists():
                fpath.touch()

    docker_run_cmd.extend([
        "-v", f"{to_docker_host_path(bin_dir)}:/target:ro",
        "-v", f"{to_docker_host_path(in_dir)}:/in:ro",
        "-v", f"{to_docker_host_path(out_dir)}:/out",
        image_tag,
        "bash", "-c", afl_cmd
    ])

    print(f"[*] [Core {cpu_core}] Launching {fuzzer_id} on {target_id} (Trial {trial_idx})...")
    subprocess.run(docker_run_cmd, check=True)

    start_time = time.time()
    poll_interval = config['experiment'].get('metric_poll_interval', 30)
    seen_crashes = set()
    seen_queue = set()
    result = {
        "fuzzer": fuzzer_id,
        "target": target_id,
        "trial": trial_idx,
        "status": "TIMEOUT",
        "reached": False,
        "ttt": None,          # Time-to-Target (T_reach, seconds)
        "ett": None,          # Executions-to-Target (E_reach)
        "reach_file": None,
        "triggered": False,
        "tte": None,          # Time-to-Exposure (T_trigger, seconds)
        "ete": None,          # Executions-to-Exposure (E_trigger)
        "crash_file": None,
        "stack_trace": None,
        "total_execs": 0,
        "wall_time": duration_sec,
    }

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed >= duration_sec:
                break

            # 1. Check reachability (TTT / T_reach) on new queue files if target not yet reached
            queue_dir = out_dir / "queue"
            if not result["reached"] and queue_dir.exists():
                new_queue = [f for f in sorted(queue_dir.glob("id:*")) if f.name not in seen_queue]
                for f in new_queue:
                    seen_queue.add(f.name)
                if new_queue:
                    hit = check_inputs_reach_batch(target_bin, target_args, new_queue, target_loc, image_tag)
                    if hit:
                        hit_name, hit_path = hit
                        result["reached"] = True
                        result["ttt"] = round(elapsed, 2)
                        result["reach_file"] = hit_name
                        stats_file = out_dir / "fuzzer_stats"
                        if stats_file.exists():
                            for line in stats_file.read_text(encoding="utf-8", errors="replace").splitlines():
                                if line.startswith("execs_done"):
                                    result["ett"] = int(line.split(":")[1].strip())
                        print(f"\n[+] >>> TARGET REACHED (TTT)! [{fuzzer_id} on {target_id} Trial {trial_idx}] <<<")
                        print(f"    Time-to-Target (TTT / T_reach): {result['ttt']}s | Execs: {result['ett']}\n")

            # 2. Check vulnerability exposure (TTE / T_trigger) on new crash files
            crashes_dir = out_dir / "crashes"
            if crashes_dir.exists():
                for c in crashes_dir.iterdir():
                    if c.name.startswith("id:") and c.name not in seen_crashes:
                        seen_crashes.add(c.name)
                        # Verify crash with ASan or GDB
                        matched, trace = triage_crash(target_bin, target_args, c, target_loc, image_tag)
                        if matched:
                            # Target vulnerability reached and triggered!
                            result["status"] = "SUCCESS"
                            result["triggered"] = True
                            result["tte"] = round(elapsed, 2)
                            result["crash_file"] = c.name
                            result["stack_trace"] = trace[:1000]

                            # If target reach was not marked yet, crash also marks first reach
                            if not result["reached"]:
                                result["reached"] = True
                                result["ttt"] = result["tte"]
                                result["reach_file"] = c.name

                            # Read execs from fuzzer_stats
                            stats_file = out_dir / "fuzzer_stats"
                            if stats_file.exists():
                                for line in stats_file.read_text(encoding="utf-8", errors="replace").splitlines():
                                    if line.startswith("execs_done"):
                                        cur_execs = int(line.split(":")[1].strip())
                                        result["ete"] = cur_execs
                                        if result["ett"] is None:
                                            result["ett"] = cur_execs
                            print(f"\n[+] >>> BUG TRIGGERED (TTE)! [{fuzzer_id} on {target_id} Trial {trial_idx}] <<<")
                            print(f"    Reachability (TTT):     {result['ttt']}s | Execs: {result['ett']}")
                            print(f"    Exposure (TTE):         {result['tte']}s | Execs: {result['ete']}\n")
                            break

            if result["status"] == "SUCCESS":
                break

            time.sleep(poll_interval)

    finally:
        # Stop and remove container
        subprocess.run(["docker", "stop", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "rm", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Parse final execs
        stats_file = out_dir / "fuzzer_stats"
        if stats_file.exists():
            for line in stats_file.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("execs_done"):
                    result["total_execs"] = int(line.split(":")[1].strip())

        # Save trial result
        with open(run_dir / "trial_result.json", "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    return result


def cmd_run(args, config: Dict[str, Any]):
    print("[*] Starting Benchmark Execution Phase...")
    duration_str = args.duration or config['experiment']['duration']
    duration_sec = parse_duration(duration_str)
    trials = args.trials or config['experiment']['trials']
    max_workers = args.workers or config['resources']['max_parallel_workers']

    if args.target:
        targets = [t for t in config['targets'] if t['id'] == args.target]
    else:
        targets = [t for t in config['targets'] if t.get('enabled', True)]
    fuzzers = [f for f in config['fuzzers'] if (args.fuzzer is None or f['id'] == args.fuzzer) and f.get('enabled', True)]

    print(f"[*] Configuration: Duration={duration_str} ({duration_sec}s), Trials={trials}, Workers={max_workers}")
    print(f"[*] Targets: {[t['id'] for t in targets]}")
    print(f"[*] Fuzzers: {[f['id'] for f in fuzzers]}")

    tasks = []
    cpu_core = 0
    available_cores = os.cpu_count() or 4

    for trial_idx in range(1, trials + 1):
        for t in targets:
            for f in fuzzers:
                assigned_core = cpu_core % available_cores
                cpu_core += 1
                tasks.append((f, t, trial_idx, duration_sec, assigned_core, config))

    print(f"[*] Total trials scheduled: {len(tasks)}. Executing pool...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(run_single_trial, *task) for task in tasks]
        for fut in futures:
            try:
                res = fut.result()
                if "error" in res:
                    print(f"[!] Error: {res.get('fuzzer')} on {res.get('target')} trial {res.get('trial')}: {res['error']}")
                else:
                    print(f"[+] Completed: {res.get('fuzzer')} on {res.get('target')} trial {res.get('trial')}: {res.get('status')}")
            except Exception as e:
                print(f"[!] Trial error: {e}")


# ==============================================================================
# Command: analyze (Statistical Evaluation & Visualization)
# ==============================================================================
def calculate_mann_whitney_and_a12(sample1: List[float], sample2: List[float]) -> Tuple[float, float]:
    """
    Computes two-sided Mann-Whitney U test and Vargha-Delaney A12 effect size.
    sample1: Candidate (e.g. aflgo_mod)
    sample2: Baseline (e.g. aflgo_orig)
    """
    try:
        from scipy.stats import mannwhitneyu
    except ImportError:
        return 1.0, 0.5

    m = len(sample1)
    n = len(sample2)
    if m == 0 or n == 0:
        return 1.0, 0.5

    # Mann-Whitney U test (less means sample1 tends to be smaller / faster than sample2)
    stat, p_value = mannwhitneyu(sample1, sample2, alternative='two-sided')

    # Vargha-Delaney A12
    # R1: rank sum of sample1
    all_vals = [(v, 1) for v in sample1] + [(v, 2) for v in sample2]
    all_vals.sort(key=lambda x: x[0])
    ranks = {}
    i = 0
    while i < len(all_vals):
        j = i
        while j < len(all_vals) and all_vals[j][0] == all_vals[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    r1 = sum(ranks[idx] for idx, item in enumerate(all_vals) if item[1] == 1)
    a12 = (r1 / m - (m + 1.0) / 2.0) / n
    return p_value, round(a12, 4)


def cmd_analyze(args, config: Dict[str, Any]):
    print("[*] Starting Benchmark Statistical Analysis Phase...")
    results_dir = Path(args.results_dir) if args.results_dir else RUNS_DIR
    out_dir = Path(args.out_dir) if args.out_dir else PLOTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if not results_dir.exists():
        print(f"[!] Results directory not found: {results_dir}")
        return

    # Collect trial results
    data: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for res_json in results_dir.glob("*/*/trial_*/trial_result.json"):
        with open(res_json, "r", encoding="utf-8") as f:
            res = json.load(f)
        fuzzer = res['fuzzer']
        target = res['target']
        data.setdefault(target, {}).setdefault(fuzzer, []).append(res)

    if not data:
        print("[!] No trial results found to analyze.")
        return

    import numpy as np

    # Generate Statistical Summary Table
    report_lines = [
        "# DGF Benchmark: Statistical Evaluation & Experimental Report",
        f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "\n## 1. Executive Summary & Raw Metrics Across All Fuzzers (Reachability TTT vs. Exposure TTE)\n",
        "| Target | Fuzzer | Role | Trials | Reach Rate | Med TTT (s) | IQR TTT | Med ETT | Trigger Rate | Med TTE (s) | IQR TTE | Med ETE |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    for target, fuzzers in data.items():
        for fuzzer, trials in fuzzers.items():
            n_trials = len(trials)
            
            # Reachability metrics (TTT / T_reach)
            reached = [t for t in trials if t.get('reached', False) or t.get('ttt') is not None]
            reach_rate = (len(reached) / n_trials * 100) if n_trials > 0 else 0
            ttts = [t['ttt'] for t in reached if t.get('ttt') is not None]
            etts = [t['ett'] for t in reached if t.get('ett') is not None]
            med_ttt = f"{np.median(ttts):.1f}" if ttts else "N/A"
            iqr_ttt = f"{np.percentile(ttts, 75) - np.percentile(ttts, 25):.1f}" if len(ttts) >= 2 else "N/A"
            med_ett = f"{int(np.median(etts)):,}" if etts else "N/A"

            # Exposure / Bug trigger metrics (TTE / T_trigger)
            triggered = [t for t in trials if t.get('triggered', False) or t.get('status') == "SUCCESS"]
            trigger_rate = (len(triggered) / n_trials * 100) if n_trials > 0 else 0
            ttes = [t.get('tte', t.get('ttt')) for t in triggered if (t.get('tte') is not None or t.get('ttt') is not None)]
            etes = [t.get('ete', t.get('ett')) for t in triggered if (t.get('ete') is not None or t.get('ett') is not None)]
            med_tte = f"{np.median(ttes):.1f}" if ttes else "N/A"
            iqr_tte = f"{np.percentile(ttes, 75) - np.percentile(ttes, 25):.1f}" if len(ttes) >= 2 else "N/A"
            med_ete = f"{int(np.median(etes)):,}" if etes else "N/A"

            role = "Proposed (Ours)" if fuzzer == "aflgo_mod" else ("Vanilla Baseline" if fuzzer == "aflgo_orig" else "SotA Competitor")

            report_lines.append(
                f"| `{target}` | `{fuzzer}` | {role} | {n_trials} | **{reach_rate:.1f}%** | {med_ttt} | {iqr_ttt} | {med_ett} | **{trigger_rate:.1f}%** | {med_tte} | {iqr_tte} | {med_ete} |"
            )

    report_lines.append("\n## 2. Comparative Evaluation: Proposed `aflgo_mod` vs. All Competitors\n")
    report_lines.append(
        "| Target | Compared Baseline | Baseline Role | Reach Speedup (TTT) | Trigger Speedup (TTE) | Mann-Whitney $p$ (TTE) | Vargha-Delaney $\\hat{A}_{12}$ | Statistical Significance |"
    )
    report_lines.append(
        "| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- |"
    )

    preferred_order = ["aflgo_orig", "dafl", "fishfuzz", "windranger"]

    for target, fuzzers in data.items():
        if "aflgo_mod" not in fuzzers:
            report_lines.append(f"\n*Note: `aflgo_mod` trials not yet present for `{target}`.*")
            continue

        mod_trials = fuzzers["aflgo_mod"]
        mod_reached = [t for t in mod_trials if t.get('reached', False) or t.get('ttt') is not None]
        mod_triggered = [t for t in mod_trials if t.get('triggered', False) or t.get('status') == "SUCCESS"]
        mod_med_ttt = np.median([t['ttt'] for t in mod_reached if t.get('ttt') is not None]) if mod_reached else None
        mod_med_tte = np.median([t.get('tte', t.get('ttt')) for t in mod_triggered if (t.get('tte') is not None or t.get('ttt') is not None)]) if mod_triggered else None
        mod_ttes_for_mw = [t.get('tte', t.get('ttt')) if (t.get('triggered', False) or t.get('status') == "SUCCESS") else t['wall_time'] * 2 for t in mod_trials]

        competitors = [f for f in fuzzers.keys() if f != "aflgo_mod"]
        competitors.sort(key=lambda x: preferred_order.index(x) if x in preferred_order else 99)

        for comp in competitors:
            comp_trials = fuzzers[comp]
            comp_reached = [t for t in comp_trials if t.get('reached', False) or t.get('ttt') is not None]
            comp_triggered = [t for t in comp_trials if t.get('triggered', False) or t.get('status') == "SUCCESS"]
            comp_med_ttt = np.median([t['ttt'] for t in comp_reached if t.get('ttt') is not None]) if comp_reached else None
            comp_med_tte = np.median([t.get('tte', t.get('ttt')) for t in comp_triggered if (t.get('tte') is not None or t.get('ttt') is not None)]) if comp_triggered else None
            comp_ttes_for_mw = [t.get('tte', t.get('ttt')) if (t.get('triggered', False) or t.get('status') == "SUCCESS") else t['wall_time'] * 2 for t in comp_trials]

            p_val, a12 = calculate_mann_whitney_and_a12(mod_ttes_for_mw, comp_ttes_for_mw)

            reach_speedup = f"{comp_med_ttt / mod_med_ttt:.2f}x" if (mod_med_ttt and comp_med_ttt and mod_med_ttt > 0) else "N/A"
            trigger_speedup = f"{comp_med_tte / mod_med_tte:.2f}x" if (mod_med_tte and comp_med_tte and mod_med_tte > 0) else "N/A"

            if comp == "aflgo_orig":
                role = "Direct Ancestor (Ablation)"
            elif comp == "dafl":
                role = "KAIST DGF (Selective)"
            elif comp == "fishfuzz":
                role = "USENIX'23 DGF (Dynamic Rank)"
            elif comp == "windranger":
                role = "ICSE'20 DGF (Deviation BB)"
            else:
                role = "Competitor"

            sig_verdict = "**Significant** ($p < 0.05$)" if p_val < 0.05 else "Inconclusive ($p \\ge 0.05$)"
            if a12 > 0.5:
                sig_verdict += " (Ours Superior)"
            elif a12 < 0.5:
                sig_verdict += " (Competitor Superior)"
            else:
                sig_verdict += " (Equivalent)"

            report_lines.append(
                f"| `{target}` | `{comp}` | {role} | **{reach_speedup}** | **{trigger_speedup}** | {p_val:.4f} | **{a12:.3f}** | {sig_verdict} |"
            )

    report_content = "\n".join(report_lines)
    report_file = out_dir / "benchmark_report.md"
    report_file.write_text(report_content, encoding="utf-8")
    print(f"[+] Statistical Report generated at {report_file}")
    print("\n" + report_content + "\n")


# ==============================================================================
# CLI Entrypoint
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="DGF Benchmark Orchestrator")
    subparsers = parser.add_subparsers(dest="command", help="Benchmark command")

    # Command: info
    subparsers.add_parser("info", help="Display benchmark configuration and status")

    # Command: build
    build_parser = subparsers.add_parser("build", help="Build Docker images and target binaries")
    build_parser.add_argument("--base", action="store_true", help="Build base Docker image")
    build_parser.add_argument("--fuzzer", type=str, help="Specific fuzzer image to build (aflgo_mod, aflgo_orig, dafl, fishfuzz, windranger)")
    build_parser.add_argument("--branch", type=str, default="develop", help="Git branch to clone for aflgo_mod and aflgo_orig (default: develop)")
    build_parser.add_argument("--target", type=str, help="Specific target to compile")
    build_parser.add_argument("--all", action="store_true", help="Build all images and targets")
    build_parser.add_argument("-f", "--force", action="store_true", help="Force recompilation even if binary already exists")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Execute fuzzing experiments with pinned CPUs")
    run_parser.add_argument("--target", type=str, help="Specific target to run")
    run_parser.add_argument("--fuzzer", type=str, help="Specific fuzzer to run")
    run_parser.add_argument("--trials", type=int, help="Number of trials per pair")
    run_parser.add_argument("--duration", type=str, help="Duration per trial (e.g. 10m, 1h, 12h)")
    run_parser.add_argument("--workers", type=int, default=None, help="Max parallel workers")

    # Command: analyze
    analyze_parser = subparsers.add_parser("analyze", help="Analyze logs, calculate stats and plot results")
    analyze_parser.add_argument("--results-dir", type=str, help="Directory containing trial runs")
    analyze_parser.add_argument("--out-dir", type=str, help="Output directory for plots and tables")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = load_config()

    if args.command == "info":
        cmd_info(args, config)
    elif args.command == "build":
        cmd_build(args, config)
    elif args.command == "run":
        cmd_run(args, config)
    elif args.command == "analyze":
        cmd_analyze(args, config)


if __name__ == "__main__":
    main()
