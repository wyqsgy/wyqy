import socket
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("redis_unauth")


@register_scanner
class RedisUnauthScanner(BaseScanner):
    name = "Redis 未授权访问"
    description = "Redis数据库未授权访问检测，可导致RCE、数据泄露"
    category = "redis"
    module = "redis_unauth"
    risk_level = "critical"
    risk_score = 9
    cve_ids = []
    references = [
        "https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html",
    ]
    fix_suggestion = "设置requirepass，绑定127.0.0.1，禁用危险命令(CONFIG/FLUSHALL等)"

    COMMON_PORTS = [6379, 16379, 6380, 6381]

    def _try_redis_connect(self, host: str, port: int) -> tuple:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(b"INFO\r\n")
            data = sock.recv(4096)
            sock.close()
            return True, data.decode("utf-8", errors="ignore")
        except Exception as e:
            return False, str(e)

    def _try_http_redis(self, host: str, port: int) -> tuple:
        url = f"http://{host}:{port}"
        try:
            resp = http_request("GET", url, timeout=5)
            if resp and "redis_version" in resp.text:
                return True, resp.text
        except Exception:
            pass
        return False, ""

    def check(self) -> bool:
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        host = parsed.hostname or self.target.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]

        ports_to_check = self.COMMON_PORTS[:]
        if parsed.port and parsed.port not in ports_to_check:
            ports_to_check.insert(0, parsed.port)

        found = False
        for port in ports_to_check:
            success, data = self._try_redis_connect(host, port)
            if success and "redis_version" in data:
                version = "unknown"
                for line in data.split("\n"):
                    if line.startswith("redis_version:"):
                        version = line.split(":")[1].strip()
                        break

                self.add_result(
                    name="Redis 未授权访问",
                    risk_level="critical",
                    risk_score=9,
                    target_url=f"{host}:{port}",
                    detail=f"Redis未授权访问确认，版本: {version}。攻击者可读写数据、写入WebShell或SSH公钥",
                    response_snippet=data[:500],
                    evidence=f"INFO命令返回Redis信息，版本: {version}",
                    fix_suggestion="1. 设置requirepass\n2. bind 127.0.0.1\n3. rename-command CONFIG \"\"\n4. rename-command FLUSHALL \"\"",
                )
                found = True

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                try:
                    sock.connect((host, port))
                    sock.send(b"CONFIG GET dir\r\n")
                    config_data = sock.recv(4096).decode("utf-8", errors="ignore")
                    if "dir" in config_data:
                        self.add_result(
                            name="Redis CONFIG命令可执行",
                            risk_level="critical",
                            risk_score=9,
                            target_url=f"{host}:{port}",
                            detail="Redis CONFIG命令未被禁用，攻击者可修改配置写入crontab或SSH公钥",
                            payload="CONFIG GET dir",
                            response_snippet=config_data[:300],
                            evidence="CONFIG GET dir命令执行成功",
                        )
                except Exception:
                    pass
                finally:
                    sock.close()

            http_success, http_data = self._try_http_redis(host, port)
            if http_success and not success:
                self.add_result(
                    name="Redis HTTP接口未授权访问",
                    risk_level="high",
                    risk_score=7,
                    target_url=f"http://{host}:{port}",
                    detail="Redis HTTP接口可未授权访问",
                    response_snippet=http_data[:500],
                    evidence="HTTP请求返回Redis信息",
                )
                found = True

        return found
