import json

import httpx

from .config import settings
from .rules import analyze_with_rules
from .schemas import AnalysisResult


SYSTEM_PROMPT = """你是SRC漏洞审核辅助分析器。只分析用户提供的已授权测试材料，不生成攻击扩散或破坏性建议。
你的任务是提取事实、指出证据缺口并给出人工复核建议，绝不能声称代替人工裁决。
严格输出单个JSON对象，字段必须符合给定schema。severity_suggestion只能为Info/Low/Medium/High/Critical；
review_suggestion只能为建议成立/需要进一步验证/证据不足；evidence_quality只能为low/medium/high。"""


async def analyze(title: str, asset: str, report: str, request: str, response: str, poc: str):
    baseline = analyze_with_rules(title, asset, report, request, response, poc)
    if not settings.llm_api_key:
        return baseline, "rules"

    payload_text = json.dumps({
        "title": title, "asset": asset, "report": report,
        "http_request": request, "http_response": response, "poc": poc,
        "rule_baseline": baseline.model_dump(),
        "required_schema": AnalysisResult.model_json_schema(),
    }, ensure_ascii=False)
    headers = {"Authorization": f"Bearer {settings.llm_api_key}", "Content-Type": "application/json"}
    body = {
        "model": settings.llm_model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": payload_text}],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            res = await client.post(settings.llm_base_url.rstrip("/") + "/chat/completions", headers=headers, json=body)
            res.raise_for_status()
            content = res.json()["choices"][0]["message"]["content"]
            llm_result = AnalysisResult.model_validate(json.loads(content))
            # 规则层拥有否决权：关键证据缺失时不能输出“建议成立”。
            merged_missing = list(dict.fromkeys(baseline.missing_evidence + llm_result.missing_evidence))
            llm_result.missing_evidence = merged_missing
            if merged_missing and llm_result.review_suggestion == "建议成立":
                llm_result.review_suggestion = "需要进一步验证"
            return llm_result, "llm+rules"
    except (httpx.HTTPError, KeyError, ValueError, TypeError):
        baseline.reasoning.append("模型接口不可用或响应无效，已安全回退至规则模式")
        return baseline, "fallback-rules"

