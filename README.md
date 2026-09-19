# SRC 漏洞辅助研判工作台

一个适合个人服务器部署和面试展示的 MVP：将漏洞报告、HTTP 请求/响应和 PoC 整理为结构化研判建议，并明确保留人工最终裁决。

## 已实现

- 管理员登录与会话保护
- 漏洞材料录入、100KB 单报告限制
- 越权、SQL 注入、XSS、SSRF、文件上传、命令执行、信息泄露规则识别
- 证据质量、缺失证据、验证步骤、风险等级与修复建议
- OpenAI-compatible 模型分析，异常时自动回退规则模式
- 历史记录与人工最终状态/等级/备注
- SQLite 持久化、Docker Compose、健康检查、基础测试

## 5 分钟启动

```bash
cp .env.example .env
# 修改 .env 中的 APP_SECRET、ADMIN_PASSWORD；模型相关变量可暂时留空
docker compose up -d --build
curl http://127.0.0.1:8000/health
```

浏览器访问 `http://服务器IP:8000`。默认 Compose 只监听 `127.0.0.1`，生产环境请通过 Nginx 反向代理并启用 HTTPS。

如果只是局域网临时演示，可将 `docker-compose.yml` 中的端口改为 `8000:8000`，并确保防火墙仅允许可信来源。

## 接入模型

在 `.env` 配置：

```env
LLM_BASE_URL=https://your-provider.example/v1
LLM_API_KEY=your-key
LLM_MODEL=your-model
```

接口需兼容 `POST /chat/completions`。未配置 Key 或接口报错时，系统会回退至规则模式，报告详情页会显示当前分析模式。

## Nginx 示例

```nginx
server {
    listen 443 ssl http2;
    server_name review.example.com;

    client_max_body_size 1m;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

启用 HTTPS 后，将 `app/main.py` 的 SessionMiddleware 参数 `https_only` 改为 `True`。公网部署还应在 Nginx 加限速/IP 白名单，避免提交真实敏感凭据，并定期备份 `data/reviews.db`。

## 本地开发与测试

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
pytest -q
```

## 面试演示脚本

1. 创建“用户资料接口疑似水平越权”报告。
2. 只提交单账号请求，展示系统提示“缺少两个身份前后对比证据”。
3. 解释规则层为何不能因模型自信就直接判定漏洞成立。
4. 保存人工结论和备注，展示 Agent 建议与人工裁决分离。
5. 说明模型不可用时自动降级，避免审核流程被第三方接口阻塞。

简历表述应使用“辅助研判 MVP / 个人工程实践”，不要描述成生产级自动审核平台。

