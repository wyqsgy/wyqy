import json
import os
import time
from typing import Dict, List, Optional
from app.config import AI_CONFIG
from app.utils.logger import get_logger

logger = get_logger("ai_engine")


class AIAnalysisEngine:
    def __init__(self):
        self.config = AI_CONFIG
        self.client = None
        self._init_client()

    def _init_client(self):
        if not self.config["enabled"]:
            return
        try:
            import httpx
            self.http_client = httpx.Client(
                base_url=self.config["api_base"],
                timeout=self.config["timeout"],
                headers={
                    "Authorization": f"Bearer {self.config['api_key']}",
                    "Content-Type": "application/json",
                },
            )
        except Exception as e:
            logger.error(f"AI client init failed: {e}")

    def analyze_fingerprint(self, fingerprint_data: Dict) -> Dict:
        if not self._is_available():
            return self._fallback_fingerprint(fingerprint_data)
        prompt = f"""你是一个资深安全专家。根据以下目标指纹信息，分析其技术栈并推荐最适合的漏洞检测模块。
指纹数据: {json.dumps(fingerprint_data, ensure_ascii=False, indent=2)}
请返回JSON格式:
{{
    "tech_stack": ["识别到的技术栈"],
    "recommended_modules": ["推荐的检测模块"],
    "risk_assessment": "风险评估",
    "attack_surface": "攻击面分析",
    "priority_targets": ["优先检测目标"]
}}"""
        return self._call_ai(prompt, "fingerprint_analysis")

    def analyze_vulnerability(self, vuln_data: Dict) -> Dict:
        if not self._is_available():
            return self._fallback_vuln_analysis(vuln_data)
        prompt = f"""你是一个资深安全专家。对以下漏洞进行深度分析。
漏洞数据: {json.dumps(vuln_data, ensure_ascii=False, indent=2)}
请返回JSON格式:
{{
    "confidence": 0-100的置信度评分,
    "is_false_positive": true/false,
    "exploitability": "可利用性评估",
    "impact": "影响范围评估",
    "remediation": "修复建议",
    "cvss_score": "CVSS评分",
    "attack_chain": "可能的攻击链",
    "evidence_quality": "证据质量评估"
}}"""
        return self._call_ai(prompt, "vuln_analysis")

    def adapt_payload(self, payload: str, context: Dict) -> Dict:
        if not self._is_available():
            return {"adapted_payloads": [payload]}
        prompt = f"""你是一个WAF绕过专家。根据以下上下文，将Payload变形以绕过WAF/过滤。
原始Payload: {payload}
上下文: {json.dumps(context, ensure_ascii=False)}
请返回JSON格式:
{{
    "adapted_payloads": ["变形后的Payload列表"],
    "techniques_used": ["使用的技术"],
    "explanation": "解释"
}}"""
        return self._call_ai(prompt, "payload_adaptation")

    def detect_false_positive(self, vuln_data: Dict, response_data: Dict) -> Dict:
        if not self._is_available():
            return {"is_false_positive": False, "confidence": 50}
        prompt = f"""你是一个漏洞验证专家。判断以下漏洞发现是否为误报。
漏洞信息: {json.dumps(vuln_data, ensure_ascii=False, indent=2)}
响应数据: {json.dumps(response_data, ensure_ascii=False, indent=2)[:1000]}
请返回JSON格式:
{{
    "is_false_positive": true/false,
    "confidence": 0-100,
    "reasoning": "判断依据",
    "suggestion": "建议"
}}"""
        return self._call_ai(prompt, "false_positive_detection")

    def generate_remediation(self, vuln_list: List[Dict]) -> Dict:
        if not self._is_available():
            return self._fallback_remediation(vuln_list)
        prompt = f"""你是一个安全修复专家。为以下漏洞列表生成详细的修复方案。
漏洞列表: {json.dumps(vuln_list, ensure_ascii=False, indent=2)[:2000]}
请返回JSON格式:
{{
    "priority_fix": ["按优先级排序的修复项"],
    "quick_wins": ["快速可实施的修复"],
    "long_term": ["长期安全加固建议"],
    "configuration_changes": ["配置变更建议"],
    "code_changes": ["代码层面修复建议"]
}}"""
        return self._call_ai(prompt, "remediation")

    def classify_target(self, url: str, response_data: Dict) -> Dict:
        if not self._is_available():
            return self._fallback_classify(response_data)
        prompt = f"""分析以下URL和响应数据，判断目标类型和可能存在的漏洞。
URL: {url}
响应状态码: {response_data.get('status_code', 'N/A')}
响应头: {json.dumps(dict(response_data.get('headers', {})), ensure_ascii=False)[:500]}
响应体(前500字符): {str(response_data.get('text', ''))[:500]}
请返回JSON格式:
{{
    "target_type": "目标类型(web/api/database/middleware/etc)",
    "technology": "技术栈",
    "potential_vulns": ["可能存在的漏洞类型"],
    "recommended_scans": ["推荐的扫描模块"],
    "risk_level": "预估风险等级"
}}"""
        return self._call_ai(prompt, "target_classification")

    def _call_ai(self, prompt: str, task_type: str) -> Dict:
        try:
            payload = {
                "model": self.config["model"],
                "messages": [
                    {"role": "system", "content": "你是一个专业的网络安全分析AI，只返回JSON格式数据。"},
                    {"role": "user", "content": prompt},
                ],
                "temperature": self.config["temperature"],
                "max_tokens": self.config["max_tokens"],
            }
            response = self.http_client.post("/chat/completions", json=payload)
            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                return self._parse_json_response(content)
            else:
                logger.error(f"AI API error: {response.status_code}")
                return {"error": f"API error: {response.status_code}"}
        except Exception as e:
            logger.error(f"AI call failed: {e}")
            return {"error": str(e)}

    def _parse_json_response(self, content: str) -> Dict:
        try:
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            return json.loads(content.strip())
        except json.JSONDecodeError:
            return {"raw_response": content}

    def _is_available(self) -> bool:
        return self.config["enabled"] and self.config.get("api_key") and hasattr(self, "http_client")

    def _fallback_fingerprint(self, data: Dict) -> Dict:
        return {
            "tech_stack": [fw["name"] for fw in data.get("framework", [])],
            "recommended_modules": [],
            "risk_assessment": "需要AI配置以获取深度分析",
            "attack_surface": "基础指纹识别已完成",
            "status": "fallback_mode",
        }

    def _fallback_vuln_analysis(self, data: Dict) -> Dict:
        return {
            "confidence": 70,
            "is_false_positive": False,
            "exploitability": "需要人工确认",
            "status": "fallback_mode",
        }

    def _fallback_remediation(self, vulns: List[Dict]) -> Dict:
        return {
            "priority_fix": [f"修复 {v.get('name', 'Unknown')}" for v in vulns[:5]],
            "quick_wins": ["更新软件版本", "启用安全头", "限制访问权限"],
            "long_term": ["实施WAF", "定期安全审计", "代码安全培训"],
            "status": "fallback_mode",
        }

    def _fallback_classify(self, data: Dict) -> Dict:
        return {
            "target_type": "unknown",
            "technology": "unknown",
            "status": "fallback_mode",
        }


ai_engine = AIAnalysisEngine()
