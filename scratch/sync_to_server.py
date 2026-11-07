import subprocess
import sys
from pathlib import Path

HOST = "root@31.77.11.162"
PW = "overplanet"
PSCP = r"C:\Program Files\PuTTY\pscp.exe"
PLINK = r"C:\Program Files\PuTTY\plink.exe"
HOSTKEY = "SHA256:fOyoaxGlUD/VDlgAdiUFPnyZt4YblOAeDe+DPnhgzOA"

def remote_cmd(cmd):
    full_cmd = [PLINK, "-batch", "-hostkey", HOSTKEY, "-ssh", HOST, "-pw", PW, cmd]
    print(f"[*] Remote exec: {cmd}")
    res = subprocess.run(full_cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        print(f"[!] Error (code {res.returncode}): {res.stderr}")
    else:
        print(f"[+] Output:\n{res.stdout.strip()}")
    return res

def upload_file(local_path, remote_path):
    print(f"[*] Uploading {local_path} -> {remote_path}")
    cmd = [PSCP, "-batch", "-hostkey", HOSTKEY, "-pw", PW, str(local_path), f"{HOST}:{remote_path}"]
    res = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        print(f"[!] Upload failed: {res.stderr}")
    return res.returncode == 0

def upload_dir(local_dir, remote_dir):
    print(f"[*] Uploading recursive {local_dir} -> {remote_dir}")
    cmd = [PSCP, "-batch", "-hostkey", HOSTKEY, "-pw", PW, "-r", str(local_dir), f"{HOST}:{remote_dir}"]
    res = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        print(f"[!] Upload failed: {res.stderr}")
    return res.returncode == 0

if __name__ == "__main__":
    remote_cmd("mkdir -p /root/dgf-benchmark/docker/orchestrator /root/dgf-benchmark/targets")

    upload_file("benchmark/config.yaml", "/root/dgf-benchmark/config.yaml")
    upload_file("benchmark/bench.py", "/root/dgf-benchmark/bench.py")
    upload_file("benchmark/docker-compose.yml", "/root/dgf-benchmark/docker-compose.yml")

    upload_dir("benchmark/docker/orchestrator", "/root/dgf-benchmark/docker")
    upload_dir("benchmark/targets/swftophp_20427", "/root/dgf-benchmark/targets")
    upload_dir("benchmark/targets/swftophp_12982", "/root/dgf-benchmark/targets")
    upload_dir("benchmark/targets/objdump_8397", "/root/dgf-benchmark/targets")
    upload_dir("benchmark/targets/nm_14940", "/root/dgf-benchmark/targets")

    # Fix line endings and permissions on remote
    remote_cmd("chmod +x /root/dgf-benchmark/bench.py /root/dgf-benchmark/docker/orchestrator/entrypoint.sh /root/dgf-benchmark/targets/*/build.sh")
    remote_cmd("dos2unix /root/dgf-benchmark/bench.py /root/dgf-benchmark/docker/orchestrator/entrypoint.sh /root/dgf-benchmark/targets/*/build.sh 2>/dev/null || sed -i 's/\\r$//' /root/dgf-benchmark/bench.py /root/dgf-benchmark/docker/orchestrator/entrypoint.sh /root/dgf-benchmark/targets/*/build.sh")
    remote_cmd("cd /root/dgf-benchmark && source venv/bin/activate && python3 bench.py info")

