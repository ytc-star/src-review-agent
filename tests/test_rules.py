from app.rules import analyze_with_rules


def test_idor_without_two_accounts_is_not_accepted():
    result = analyze_with_rules("用户资料越权", "/api/profile", "修改user_id可查看资料", "GET /api/profile?user_id=2 HTTP/1.1\nCookie: x", "200 OK", "")
    assert result.vulnerability_type == "越权/IDOR"
    assert result.review_suggestion != "建议成立"
    assert result.missing_evidence


def test_sqli_detected():
    result = analyze_with_rules("SQL注入", "/search", "存在时间差", "GET /search?q=1%27+and+sleep(5)", "200 OK", "重复三次均延迟5秒")
    assert result.vulnerability_type == "SQL注入"
    assert result.severity_suggestion == "High"

