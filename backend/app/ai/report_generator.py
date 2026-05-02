from datetime import datetime
from app.config import RISK_LEVELS
from app.utils.logger import get_logger

logger = get_logger("ai_report")


class AIReportGenerator:

    def generate_analysis(self, vuln_name: str, vuln_detail: str, evidence: str,
                          risk_level: str, payload: str = "", category: str = "") -> str:
        sections = []

        severity_info = RISK_LEVELS.get(risk_level, RISK_LEVELS["info"])
        sections.append(f"**风险等级**: {severity_info['label']} (CVSS评分: {severity_info['score']}/10)")

        if category:
            category_names = {
                "spring": "Spring Framework",
                "shiro": "Apache Shiro",
                "log4j2": "Apache Log4j2",
                "fastjson": "Alibaba Fastjson",
                "nacos": "Alibaba Nacos",
                "druid": "Alibaba Druid",
                "tomcat": "Apache Tomcat",
                "struts2": "Apache Struts2",
                "thinkphp": "ThinkPHP",
                "weblogic": "WebLogic",
                "redis": "Redis",
                "confluence": "Confluence",
                "f5": "F5 BIG-IP",
                "jenkins": "Jenkins",
                "flink": "Apache Flink",
                "xxljob": "XXL-JOB",
                "nginx": "Nginx",
                "elasticsearch": "Elasticsearch",
                "waf": "WAF绕过引擎",
                "deserialization": "反序列化检测",
                "ssrf": "SSRF链利用",
                "jwt": "JWT攻击套件",
                "honeypot": "蜜罐识别",
                "fuzzer": "智能模糊测试",
                "linux_privesc": "Linux提权扫描",
                "fingerprint": "资产指纹识别",
                "subdomain": "子域名枚举",
                "portscan": "端口扫描",
            }
            sections.append(f"**影响组件**: {category_names.get(category, category)}")

        analysis = self._analyze_vuln_impact(vuln_name, vuln_detail, evidence)
        sections.append(f"**漏洞分析**: {analysis}")

        exploitability = self._assess_exploitability(risk_level, payload, evidence)
        sections.append(f"**可利用性评估**: {exploitability}")

        business_impact = self._assess_business_impact(risk_level, vuln_name)
        sections.append(f"**业务影响**: {business_impact}")

        priority = self._get_repair_priority(risk_level)
        sections.append(f"**修复优先级**: {priority}")

        return "\n\n".join(sections)

    def generate_summary(self, vulns: list) -> str:
        if not vulns:
            return "扫描完成，未发现安全漏洞。"

        total = len(vulns)
        risk_dist = {}
        for v in vulns:
            level = v.get("risk_level", "info")
            risk_dist[level] = risk_dist.get(level, 0) + 1

        categories = set(v.get("category", "") for v in vulns)

        summary_parts = [
            f"本次扫描共发现 **{total}** 个安全漏洞。",
        ]

        dist_text = "、".join(
            f"{RISK_LEVELS.get(level, {}).get('label', level)} {count}个"
            for level, count in sorted(risk_dist.items(),
                                       key=lambda x: RISK_LEVELS.get(x[0], {}).get("score", 0),
                                       reverse=True)
        )
        summary_parts.append(f"风险分布: {dist_text}。")

        summary_parts.append(f"涉及组件: {', '.join(categories)}。")

        critical_count = risk_dist.get("critical", 0) + risk_dist.get("high", 0)
        if critical_count > 0:
            summary_parts.append(
                f"⚠️ 发现 {critical_count} 个高危/严重漏洞，建议立即修复！"
            )

        return " ".join(summary_parts)

    def _analyze_vuln_impact(self, name: str, detail: str, evidence: str) -> str:
        if "RCE" in name or "远程代码执行" in detail:
            return "该漏洞允许攻击者在目标服务器上执行任意代码，可能导致服务器完全被控制。"
        if "反序列化" in name or "deserialization" in name.lower():
            return "反序列化漏洞可被利用执行恶意代码，通常需要特定的Gadget链配合。"
        if "注入" in name or "injection" in name.lower():
            return "注入漏洞允许攻击者向应用注入恶意指令，可能导致数据泄露或代码执行。"
        if "未授权" in name or "unauth" in name.lower():
            return "未授权访问漏洞允许攻击者绕过身份验证访问敏感功能或数据。"
        if "信息泄露" in name or "泄露" in detail:
            return "信息泄露漏洞暴露了敏感数据，可能被攻击者用于进一步渗透。"
        if "绕过" in name or "bypass" in name.lower():
            return "认证/授权绕过漏洞可让攻击者访问受保护的资源。"
        return detail[:200] if detail else "需要进一步人工分析确认漏洞影响。"

    def _assess_exploitability(self, risk_level: str, payload: str, evidence: str) -> str:
        if risk_level == "critical":
            if payload:
                return "高可利用性。已有现成Payload可直接利用，攻击门槛低。"
            return "高可利用性。漏洞原理明确，攻击者可快速构造利用代码。"
        if risk_level == "high":
            return "中高可利用性。需要一定技术能力，但在公开资料充足的情况下可被利用。"
        if risk_level == "medium":
            return "中等可利用性。通常需要特定条件或配合其他漏洞才能利用。"
        return "低可利用性。主要作为信息收集，直接危害较小。"

    def _assess_business_impact(self, risk_level: str, name: str) -> str:
        impacts = {
            "critical": "可能导致服务器沦陷、核心数据泄露、业务中断，造成重大经济损失和声誉损害。",
            "high": "可能导致敏感数据泄露、权限提升，对业务安全构成严重威胁。",
            "medium": "可能导致部分信息泄露或有限的功能滥用，需评估实际影响范围。",
            "low": "影响有限，通常作为安全加固的参考项。",
            "info": "信息性发现，供安全评估参考。",
        }
        return impacts.get(risk_level, impacts["info"])

    def _get_repair_priority(self, risk_level: str) -> str:
        priorities = {
            "critical": "🔴 P0 - 立即修复（24小时内）",
            "high": "🟠 P1 - 紧急修复（72小时内）",
            "medium": "🟡 P2 - 计划修复（1周内）",
            "low": "🟢 P3 - 排期修复（1月内）",
            "info": "🔵 P4 - 优化建议",
        }
        return priorities.get(risk_level, priorities["info"])

    def generate_html_report(self, task_info: dict, vulns: list, summary: str) -> str:
        vuln_rows = ""
        for v in vulns:
            level = v.get("risk_level", "info")
            color = RISK_LEVELS.get(level, {}).get("color", "#666")
            label = RISK_LEVELS.get(level, {}).get("label", "信息")
            vuln_rows += f"""
            <tr>
                <td>{v.get('vuln_id', '')[:12]}</td>
                <td><span style="color:{color};font-weight:bold">[{label}]</span> {v.get('name', '')}</td>
                <td>{v.get('category', '')}</td>
                <td>{v.get('target_url', '')}</td>
                <td>{v.get('ai_confidence', 0)}%</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WyqYan安全扫描报告</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;background:#f5f5f5}}
.container{{max-width:1000px;margin:0 auto;background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}}
h1{{color:#1a1a2e;border-bottom:3px solid #e94560;padding-bottom:10px}}
h2{{color:#16213e;margin-top:30px}}
.summary{{background:#f0f4f8;padding:20px;border-radius:6px;margin:20px 0}}
table{{width:100%;border-collapse:collapse;margin:20px 0}}
th,td{{padding:10px;border:1px solid #ddd;text-align:left;font-size:13px}}
th{{background:#1a1a2e;color:#fff}}
tr:nth-child(even){{background:#f9f9f9}}
.footer{{margin-top:40px;padding-top:20px;border-top:1px solid #eee;color:#888;font-size:12px;text-align:center}}
</style></head><body>
<div class="container">
<h1>🛡️ WyqYan 安全扫描报告</h1>
<p><strong>扫描目标</strong>: {task_info.get('target', 'N/A')}</p>
<p><strong>扫描时间</strong>: {task_info.get('created_at', 'N/A')}</p>
<p><strong>完成时间</strong>: {task_info.get('finished_at', 'N/A')}</p>

<div class="summary"><h2>📊 扫描摘要</h2><p>{summary}</p></div>

<h2>🔴 发现的漏洞</h2>
<table>
<tr><th>漏洞ID</th><th>漏洞名称</th><th>类型</th><th>目标URL</th><th>AI置信度</th></tr>
{vuln_rows}
</table>

<div class="footer">
<p>由 WyqYan AI安全扫描平台 生成 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
</div>
</div></body></html>"""
        return html
