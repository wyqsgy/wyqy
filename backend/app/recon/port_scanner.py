import socket
import concurrent.futures
from typing import List, Dict, Callable, Optional
from app.utils.logger import get_logger

logger = get_logger("port_scanner")

TOP_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 513: "rlogin", 554: "rtsp", 587: "submission",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1099: "rmi", 1433: "mssql", 1434: "mssql-mgmt",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 2888: "zookeeper-leader",
    3306: "mysql", 3389: "rdp", 3690: "svn", 4443: "https-alt",
    4848: "glassfish", 5000: "flask-upnp", 5432: "postgresql",
    5555: "adb", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes", 7001: "weblogic", 7002: "weblogic-ssl",
    8000: "http-alt", 8001: "http-alt", 8008: "http-alt",
    8009: "ajp", 8080: "http-proxy", 8081: "http-alt", 8082: "http-alt",
    8083: "http-alt", 8088: "http-alt", 8090: "http-alt",
    8161: "activemq", 8443: "https-alt", 8834: "nessus",
    8880: "http-alt", 8888: "http-alt", 8983: "solr",
    9000: "fastcgi-portainer", 9001: "supervisor",
    9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 9999: "http-alt",
    10000: "webmin", 11211: "memcached",
    27017: "mongodb", 27018: "mongodb", 50000: "sap",
    50070: "hdfs", 61616: "activemq",
}

WEB_PORTS = {
    80, 443, 81, 88, 4443, 4848, 5000, 7001, 7002, 8000, 8001, 8008,
    8009, 8080, 8081, 8082, 8083, 8088, 8090, 8161, 8443, 8834, 8880,
    8888, 8983, 9000, 9001, 9090, 9200, 9999, 10000, 50070,
}

SERVICE_BANNERS = {}


class PortScanner:
    def __init__(self, timeout: float = 1.5, max_workers: int = 200):
        self.timeout = timeout
        self.max_workers = max_workers

    def scan_host(self, host: str, ports: Optional[List[int]] = None,
                  on_port_open: Optional[Callable] = None) -> List[Dict]:
        if ports is None:
            ports = list(TOP_PORTS.keys())
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {
                executor.submit(self._probe_port, host, port): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(future_map):
                port = future_map[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if on_port_open:
                            on_port_open(result)
                except Exception as e:
                    logger.debug(f"Error scanning {host}:{port} - {e}")
        results.sort(key=lambda x: x["port"])
        return results

    def _probe_port(self, host: str, port: int) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = TOP_PORTS.get(port, "unknown")
                banner = self._grab_banner(sock, host, port)
                sock.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                    "is_web": port in WEB_PORTS,
                }
            sock.close()
            return None
        except Exception:
            return None

    def _grab_banner(self, sock: socket.socket, host: str, port: int) -> str:
        try:
            sock.settimeout(2)
            if port in (80, 8080, 8000, 8081, 8888, 9000, 9090, 8443, 443):
                probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            elif port == 22:
                probe = ""
            elif port in (21,):
                probe = ""
            elif port in (3306,):
                probe = ""
            elif port == 6379:
                probe = "INFO\r\n"
            elif port == 27017:
                probe = ""
            else:
                probe = ""
            if probe:
                sock.send(probe.encode())
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner[:500]
            else:
                sock.settimeout(3)
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    return banner[:500]
                except socket.timeout:
                    return ""
        except Exception:
            return ""

    def quick_scan(self, host: str, top_n: int = 100) -> List[Dict]:
        ports = list(TOP_PORTS.keys())[:top_n]
        return self.scan_host(host, ports)

    def full_scan(self, host: str, port_range: str = "1-65535") -> List[Dict]:
        start, end = port_range.split("-")
        ports = list(range(int(start), int(end) + 1))
        return self.scan_host(host, ports)

    def is_port_open(self, host: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False


def scan_ports(host: str, ports: Optional[List[int]] = None,
               timeout: float = 1.5, max_workers: int = 200,
               on_port_open: Optional[Callable] = None) -> List[Dict]:
    scanner = PortScanner(timeout=timeout, max_workers=max_workers)
    return scanner.scan_host(host, ports, on_port_open)


def quick_scan(host: str, top_n: int = 100) -> List[Dict]:
    return scan_ports(host, ports=list(TOP_PORTS.keys())[:top_n])
