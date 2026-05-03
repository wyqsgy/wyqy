"""
Professional Report Generator - Nessus-Style
Generates comprehensive security assessment reports with:
- Executive Summary
- Risk Distribution Charts (SVG-based, no external deps)
- Detailed Vulnerability Findings
- Remediation Roadmap
- CVSS-Style Scoring
- JSON/HTML/PDF Export
"""
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

REPORT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

RISK_CONFIG = {
    "critical": {
        "label": "严重", "label_en": "Critical",
        "color": "#dc2626", "bg": "#fef2f2", "border": "#fca5a5",
        "score_range": "9.0-10.0", "icon": "🔴",
    },
    "high": {
        "label": "高危", "label_en": "High",
        "color": "#ea580c", "bg": "#fff7ed", "border": "#fdba74",
        "score_range": "7.0-8.9", "icon": "🟠",
    },
    "medium": {
        "label": "中危", "label_en": "Medium",
        "color": "#ca8a04", "bg": "#fefce8", "border": "#fde047",
        "score_range": "4.0-6.9", "icon": "🟡",
    },
    "low": {
        "label": "低危", "label_en": "Low",
        "color": "#16a34a", "bg": "#f0fdf4", "border": "#86efac",
        "score_range": "0.1-3.9", "icon": "🟢",
    },
    "info": {
        "label": "信息", "label_en": "Info",
        "color": "#2563eb", "bg": "#eff6ff", "border": "#93c5fd",
        "score_range": "0.0", "icon": "🔵",
    },
}

REMEDIATION_TIMELINE = {
    "critical": "立即修复 (24小时内)",
    "high": "紧急修复 (72小时内)",
    "medium": "计划修复 (30天内)",
    "low": "建议修复 (90天内)",
    "info": "参考信息",
}


def generate_report_id() -> str:
    return f"RPT-{uuid.uuid4().hex[:8].upper()}"


def build_svg_risk_chart(risk_distribution: Dict[str, int]) -> str:
    total = sum(risk_distribution.values()) or 1
    colors = {
        "critical": "#dc2626", "high": "#ea580c",
        "medium": "#ca8a04", "low": "#16a34a", "info": "#2563eb",
    }
    labels = {
        "critical": "严重", "high": "高危",
        "medium": "中危", "low": "低危", "info": "信息",
    }

    bars = ""
    y = 30
    for level in ["critical", "high", "medium", "low", "info"]:
        count = risk_distribution.get(level, 0)
        pct = round(count / total * 100, 1)
        width = max(pct * 3, 2) if count > 0 else 0
        bars += f'''
        <g transform="translate(0, {y})">
          <text x="0" y="14" font-size="12" fill="#e5e7eb" font-family="monospace">{labels[level]}</text>
          <rect x="60" y="2" width="{width}" height="20" rx="3" fill="{colors[level]}" opacity="0.85"/>
          <text x="{65 + width}" y="16" font-size="11" fill="#9ca3af" font-family="monospace">{count} ({pct}%)</text>
        </g>'''
        y += 32

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="{y + 10}" viewBox="0 0 400 {y + 10}">
      <rect width="400" height="{y + 10}" fill="#111827" rx="8"/>
      {bars}
    </svg>'''


def build_svg_score_gauge(score: float, max_score: float = 10.0) -> str:
    pct = min(score / max_score * 100, 100)
    if score >= 9.0:
        color = "#dc2626"
    elif score >= 7.0:
        color = "#ea580c"
    elif score >= 4.0:
        color = "#ca8a04"
    elif score > 0:
        color = "#16a34a"
    else:
        color = "#2563eb"

    circumference = 2 * 3.14159 * 54
    dash = circumference * pct / 100

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="140" height="140" viewBox="0 0 140 140">
      <circle cx="70" cy="70" r="54" fill="none" stroke="#374151" stroke-width="10"/>
      <circle cx="70" cy="70" r="54" fill="none" stroke="{color}" stroke-width="10"
        stroke-dasharray="{dash} {circumference - dash}" stroke-linecap="round"
        transform="rotate(-90 70 70)"/>
      <text x="70" y="65" text-anchor="middle" font-size="28" font-weight="bold" fill="#f9fafb" font-family="monospace">{score}</text>
      <text x="70" y="85" text-anchor="middle" font-size="11" fill="#9ca3af" font-family="monospace">/ {max_score}</text>
    </svg>'''


def generate_html_report(
    task_info: Dict,
    vulnerabilities: List[Dict],
    fingerprint: Optional[Dict] = None,
    summary: str = "",
    report_id: str = "",
) -> str:
    if not report_id:
        report_id = generate_report_id()

    risk_dist: Dict[str, int] = {}
    for v in vulnerabilities:
        level = v.get("risk_level", "info")
        risk_dist[level] = risk_dist.get(level, 0) + 1

    total_vulns = len(vulnerabilities)
    risk_chart_svg = build_svg_risk_chart(risk_dist)

    target = task_info.get("target", "N/A")
    scan_start = task_info.get("created_at", "N/A")
    scan_end = task_info.get("finished_at", "N/A")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    vuln_rows = ""
    for idx, v in enumerate(vulnerabilities, 1):
        level = v.get("risk_level", "info")
        cfg = RISK_CONFIG.get(level, RISK_CONFIG["info"])
        score = v.get("risk_score", 0)
        gauge_svg = build_svg_score_gauge(score)
        cve_str = ", ".join(v.get("cve_ids", [])) or "N/A"
        refs = v.get("references", [])
        refs_html = "".join(
            f'<li><a href="{r}" target="_blank" style="color:#60a5fa;">{r}</a></li>'
            for r in refs[:5]
        ) if refs else "<li>N/A</li>"

        vuln_rows += f'''
        <div style="background:{cfg['bg']};border:1px solid {cfg['border']};border-radius:8px;padding:20px;margin-bottom:16px;page-break-inside:avoid;">
          <div style="display:flex;justify-content:space-between;align-items:start;flex-wrap:wrap;gap:12px;">
            <div style="flex:1;min-width:200px;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <span style="background:{cfg['color']};color:#fff;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:700;">{cfg['label']}</span>
                <span style="font-size:11px;color:#6b7280;">#{idx}</span>
              </div>
              <h3 style="margin:0 0 6px 0;font-size:16px;color:#111827;">{v.get('name', 'Unknown')}</h3>
              <p style="margin:0 0 8px 0;font-size:13px;color:#4b5563;line-height:1.5;">{v.get('description', '')}</p>
              <div style="font-size:12px;color:#6b7280;margin-bottom:4px;">
                <strong>目标URL:</strong> <code style="background:#e5e7eb;padding:1px 6px;border-radius:3px;">{v.get('target_url', 'N/A')}</code>
              </div>
              <div style="font-size:12px;color:#6b7280;margin-bottom:4px;">
                <strong>CVE:</strong> {cve_str}
              </div>
            </div>
            <div style="text-align:center;flex-shrink:0;">
              {gauge_svg}
              <div style="font-size:10px;color:#6b7280;margin-top:2px;">风险评分</div>
            </div>
          </div>
          <details style="margin-top:12px;">
            <summary style="cursor:pointer;font-size:13px;font-weight:600;color:#374151;">详细证据与修复建议</summary>
            <div style="margin-top:8px;padding:12px;background:#fff;border-radius:6px;font-size:12px;line-height:1.6;">
              <p><strong>漏洞详情:</strong><br/>{v.get('detail', 'N/A')}</p>
              <p><strong>Payload:</strong><br/><code style="background:#f3f4f6;padding:4px 8px;display:block;overflow-x:auto;white-space:pre-wrap;word-break:break-all;">{v.get('payload', 'N/A')}</code></p>
              <p><strong>修复建议:</strong><br/>{v.get('fix_suggestion', 'N/A')}</p>
              <p><strong>修复时限:</strong> {REMEDIATION_TIMELINE.get(level, '计划修复')}</p>
              <p><strong>参考链接:</strong></p>
              <ul>{refs_html}</ul>
            </div>
          </details>
        </div>'''

    fp_html = ""
    if fingerprint:
        fp_parts = []
        for key, label in [("framework", "框架"), ("language", "语言"),
                            ("middleware", "中间件"), ("server", "服务器"),
                            ("cdn", "CDN"), ("waf", "WAF")]:
            items = fingerprint.get(key, [])
            if isinstance(items, list) and items:
                names = [f"{i.get('name','')} {i.get('version','')}".strip() for i in items]
                fp_parts.append(f"<tr><td style='padding:6px 12px;color:#6b7280;'>{label}</td><td style='padding:6px 12px;font-weight:600;'>{', '.join(names)}</td></tr>")
            elif items:
                fp_parts.append(f"<tr><td style='padding:6px 12px;color:#6b7280;'>{label}</td><td style='padding:6px 12px;font-weight:600;'>{items}</td></tr>")
        if fp_parts:
            fp_html = f'''
            <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:20px;">
              <h3 style="margin:0 0 12px 0;font-size:14px;color:#374151;">目标指纹信息</h3>
              <table style="width:100%;font-size:13px;border-collapse:collapse;">{"".join(fp_parts)}</table>
            </div>'''

    html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全评估报告 - {target}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', sans-serif; background:#f3f4f6; color:#1f2937; line-height:1.6; }}
  .container {{ max-width:900px; margin:0 auto; padding:20px; }}
  .header {{ background: linear-gradient(135deg, #111827 0%, #1f2937 100%); color:#fff; padding:40px; border-radius:12px; margin-bottom:24px; }}
  .header h1 {{ font-size:24px; margin-bottom:8px; }}
  .header .meta {{ font-size:13px; color:#9ca3af; }}
  .card {{ background:#fff; border-radius:12px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.08); }}
  .card h2 {{ font-size:18px; color:#111827; margin-bottom:16px; padding-bottom:8px; border-bottom:2px solid #e5e7eb; }}
  .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:12px; margin-bottom:20px; }}
  .stat-box {{ background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:16px; text-align:center; }}
  .stat-box .num {{ font-size:28px; font-weight:700; }}
  .stat-box .lbl {{ font-size:12px; color:#6b7280; margin-top:4px; }}
  .footer {{ text-align:center; padding:20px; font-size:12px; color:#9ca3af; }}
  @media print {{
    body {{ background:#fff; }}
    .card {{ box-shadow:none; border:1px solid #e5e7eb; }}
    .header {{ background:#111827 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>WyqYan 安全评估报告</h1>
    <div class="meta">
      <div>报告编号: {report_id}</div>
      <div>生成时间: {generated_at}</div>
      <div>扫描目标: {target}</div>
      <div>扫描时间: {scan_start} ~ {scan_end}</div>
    </div>
  </div>

  <div class="card">
    <h2>执行摘要</h2>
    <p style="font-size:14px;color:#4b5563;line-height:1.7;">{summary or f'本次安全评估共发现 <strong>{total_vulns}</strong> 个安全漏洞，其中严重漏洞 <strong>{risk_dist.get("critical", 0)}</strong> 个，高危漏洞 <strong>{risk_dist.get("high", 0)}</strong> 个。建议立即对严重和高危漏洞进行修复。'}</p>
  </div>

  <div class="card">
    <h2>风险概览</h2>
    <div class="stats-grid">
      <div class="stat-box">
        <div class="num" style="color:#dc2626;">{risk_dist.get('critical', 0)}</div>
        <div class="lbl">严重</div>
      </div>
      <div class="stat-box">
        <div class="num" style="color:#ea580c;">{risk_dist.get('high', 0)}</div>
        <div class="lbl">高危</div>
      </div>
      <div class="stat-box">
        <div class="num" style="color:#ca8a04;">{risk_dist.get('medium', 0)}</div>
        <div class="lbl">中危</div>
      </div>
      <div class="stat-box">
        <div class="num" style="color:#16a34a;">{risk_dist.get('low', 0)}</div>
        <div class="lbl">低危</div>
      </div>
      <div class="stat-box">
        <div class="num" style="color:#2563eb;">{risk_dist.get('info', 0)}</div>
        <div class="lbl">信息</div>
      </div>
    </div>
    <div style="text-align:center;">{risk_chart_svg}</div>
  </div>

  {fp_html}

  <div class="card">
    <h2>漏洞详情 ({total_vulns})</h2>
    {vuln_rows if vuln_rows else '<p style="color:#6b7280;text-align:center;padding:40px;">未发现漏洞</p>'}
  </div>

  <div class="card">
    <h2>修复优先级路线图</h2>
    <table style="width:100%;font-size:13px;border-collapse:collapse;">
      <tr style="background:#f9fafb;">
        <th style="padding:10px;text-align:left;border-bottom:2px solid #e5e7eb;">优先级</th>
        <th style="padding:10px;text-align:left;border-bottom:2px solid #e5e7eb;">风险等级</th>
        <th style="padding:10px;text-align:left;border-bottom:2px solid #e5e7eb;">数量</th>
        <th style="padding:10px;text-align:left;border-bottom:2px solid #e5e7eb;">修复时限</th>
      </tr>
      <tr>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">P0</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;color:#dc2626;font-weight:600;">严重</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{risk_dist.get('critical', 0)}</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{REMEDIATION_TIMELINE['critical']}</td>
      </tr>
      <tr>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">P1</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;color:#ea580c;font-weight:600;">高危</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{risk_dist.get('high', 0)}</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{REMEDIATION_TIMELINE['high']}</td>
      </tr>
      <tr>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">P2</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;color:#ca8a04;font-weight:600;">中危</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{risk_dist.get('medium', 0)}</td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{REMEDIATION_TIMELINE['medium']}</td>
      </tr>
      <tr>
        <td style="padding:10px;">P3</td>
        <td style="padding:10px;color:#16a34a;font-weight:600;">低危</td>
        <td style="padding:10px;">{risk_dist.get('low', 0)}</td>
        <td style="padding:10px;">{REMEDIATION_TIMELINE['low']}</td>
      </tr>
    </table>
  </div>

  <div class="footer">
    <p>本报告由 WyqYan 漏洞扫描平台 自动生成</p>
    <p>报告仅供授权安全评估使用，请勿用于非法用途</p>
    <p>Generated at {generated_at}</p>
  </div>

</div>
</body>
</html>'''

    return html


def save_report(
    task_id: str,
    task_info: Dict,
    vulnerabilities: List[Dict],
    fingerprint: Optional[Dict] = None,
    summary: str = "",
) -> Dict:
    report_id = generate_report_id()
    html = generate_html_report(task_info, vulnerabilities, fingerprint, summary, report_id)

    risk_dist: Dict[str, int] = {}
    for v in vulnerabilities:
        level = v.get("risk_level", "info")
        risk_dist[level] = risk_dist.get(level, 0) + 1

    json_data = {
        "report_id": report_id,
        "task_id": task_id,
        "task_info": task_info,
        "vulnerabilities": vulnerabilities,
        "fingerprint": fingerprint,
        "summary": summary,
        "risk_distribution": risk_dist,
        "total_vulns": len(vulnerabilities),
        "generated_at": datetime.now().isoformat(),
    }

    html_path = REPORT_DIR / f"{report_id}.html"
    json_path = REPORT_DIR / f"{report_id}.json"

    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(json.dumps(json_data, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "report_id": report_id,
        "html_path": str(html_path),
        "json_path": str(json_path),
        "total_vulns": len(vulnerabilities),
        "risk_distribution": risk_dist,
    }
