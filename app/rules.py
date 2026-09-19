import re

from .schemas import AnalysisResult


RULES = [
    ("SQL注入", [r"sql\s*注入", r"union\s+select", r"sleep\s*\(", r"报错注入", r"sqlmap"]),
    ("SSRF", [r"ssrf", r"127\.0\.0\.1", r"169\.254\.169\.254", r"file://", r"gopher://"]),
    ("命令执行", [r"命令执行", r"rce", r"runtime\.exec", r"/bin/(?:sh|bash)", r"cmd\.exe"]),
    ("文件上传", [r"文件上传", r"multipart/form-data", r"webshell", r"\.php(?:\s|$)", r"\.jsp(?:\s|$)"]),
    ("越权/IDOR", [r"越权", r"idor", r"水平权限", r"垂直权限", r"user_?id", r"account_?id"]),
    ("XSS", [r"xss", r"<script", r"onerror\s*=", r"javascript:"]),
    ("信息泄露", [r"信息泄露", r"敏感信息", r"access[_-]?key", r"password", r"身份证"]),
]


def analyze_with_rules(title: str, asset: str, report: str, request: str, response: str, poc: str) -> AnalysisResult:
    text = "\n".join([title, asset, report, request, response, poc])
    lowered = text.lower()
    vuln_type = "待分类"
    for name, patterns in RULES:
        if any(re.search(pattern, lowered, re.I) for pattern in patterns):
            vuln_type = name
            break

    params = []
    for match in re.findall(r"(?:[?&]|\b)([a-zA-Z_][\w-]{1,40})=", request + "\n" + asset):
        if match.lower() not in {"host", "cookie", "content-type"} and match not in params:
            params.append(match)

    missing, steps, remediation = [], [], []
    auth_required = bool(re.search(r"authorization:|cookie:", request, re.I)) or None
    evidence_score = sum(bool(x.strip()) for x in [request, response, poc])

    if vuln_type == "越权/IDOR":
        if not re.search(r"账号\s*[ab]|用户\s*[ab]|跨账号|未授权|另一(?:个)?用户", text, re.I):
            missing.append("缺少两个不同身份或未授权状态的前后对比证据")
        steps = ["使用账号A请求自身对象并保存响应", "将对象标识替换为账号B的数据", "对比状态码、响应体和敏感字段，确认是否越权"]
        remediation = ["服务端基于当前身份校验对象归属", "避免仅依赖前端隐藏或可枚举ID"]
    elif vuln_type == "SQL注入":
        if not re.search(r"时间差|回显|报错|布尔|sqlmap", text, re.I):
            missing.append("缺少稳定回显、布尔差异、报错或时间差证据")
        steps = ["建立正常请求基线", "单变量修改疑似参数并重复验证", "确认差异可重复且排除网络抖动"]
        remediation = ["使用参数化查询", "限制数据库账户权限并统一异常处理"]
    elif vuln_type == "XSS":
        if not re.search(r"执行|弹窗|dom|存储型|截图", text, re.I):
            missing.append("仅有输入回显不足以证明脚本可在目标上下文执行")
        steps = ["确认输入进入HTML、属性或脚本的具体上下文", "使用无害Payload验证执行", "确认触发范围和受影响用户"]
        remediation = ["按输出上下文编码", "使用CSP降低利用影响"]
    elif vuln_type == "SSRF":
        if not re.search(r"dnslog|回连|内网|metadata|响应", text, re.I):
            missing.append("缺少服务器端请求、回连或内网资源访问证据")
        steps = ["使用自有回连域名验证服务端请求", "测试协议、重定向和地址解析限制", "在授权范围内验证可达资源"]
        remediation = ["采用目标白名单并禁用危险协议", "解析后校验IP并阻断内网及云元数据地址"]
    elif vuln_type == "文件上传":
        if not re.search(r"访问成功|执行成功|解析|返回\s*200", text, re.I):
            missing.append("缺少上传后文件可访问或可执行的证据")
        steps = ["确认服务端保存路径和文件名", "验证文件是否可公开访问", "使用无害文件确认是否被脚本引擎解析"]
        remediation = ["服务端重命名并校验真实文件类型", "上传目录禁用执行权限并与Web根目录隔离"]
    else:
        missing.append("缺少可重复验证步骤和正常/异常请求对比")
        steps = ["保留正常请求作为基线", "每次只改变一个变量", "重复验证并记录完整请求、响应和影响"]
        remediation = ["根据确认后的根因实施服务端修复", "修复后执行回归测试"]

    review = "证据不足" if evidence_score < 2 else ("需要进一步验证" if missing else "建议成立")
    quality = "low" if evidence_score < 2 else ("medium" if missing else "high")
    severity = "High" if vuln_type in {"SQL注入", "命令执行", "文件上传"} else "Medium"
    if review == "证据不足":
        severity = "Low"

    return AnalysisResult(
        vulnerability_type=vuln_type,
        affected_asset=asset,
        key_parameters=params[:10],
        auth_required=auth_required,
        evidence_quality=quality,
        missing_evidence=missing,
        impact="可能存在与该漏洞类型相关的安全影响，需结合实际数据与权限边界确认",
        severity_suggestion=severity,
        review_suggestion=review,
        verification_steps=steps,
        remediation=remediation,
        reasoning=[f"规则识别漏洞类型：{vuln_type}", f"当前证据完整度：{quality}", "结论为辅助建议，最终结果需人工复核"],
    )

