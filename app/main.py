import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .analyzer import analyze
from .config import settings
from .database import Review, get_db, init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="SRC漏洞辅助研判工作台", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.app_secret, same_site="lax", https_only=False)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def require_login(request: Request):
    if not request.session.get("user"):
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ok = secrets.compare_digest(username, settings.admin_username) and secrets.compare_digest(password, settings.admin_password)
    if not ok:
        return templates.TemplateResponse(request, "login.html", {"error": "用户名或密码错误"}, status_code=401)
    request.session["user"] = username
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_login)])
def dashboard(request: Request, db: Session = Depends(get_db)):
    reviews = db.scalars(select(Review).order_by(desc(Review.created_at)).limit(10)).all()
    total = db.scalar(select(func.count(Review.id))) or 0
    pending = db.scalar(select(func.count(Review.id)).where(Review.human_status == "待复核")) or 0
    return templates.TemplateResponse(request, "dashboard.html", {"reviews": reviews, "total": total, "pending": pending})


@app.get("/reviews/new", response_class=HTMLResponse, dependencies=[Depends(require_login)])
def new_review(request: Request):
    return templates.TemplateResponse(request, "new.html", {})


@app.post("/reviews", dependencies=[Depends(require_login)])
async def create_review(
    title: str = Form(...), asset: str = Form(""), report: str = Form(...),
    http_request: str = Form(""), http_response: str = Form(""), poc: str = Form(""),
    db: Session = Depends(get_db),
):
    if len("".join([title, asset, report, http_request, http_response, poc])) > 100_000:
        raise HTTPException(413, "单份报告总长度不能超过100KB")
    result, mode = await analyze(title, asset, report, http_request, http_response, poc)
    row = Review(title=title[:200], asset=asset[:500], report=report, http_request=http_request,
                 http_response=http_response, poc=poc, analysis=result.model_dump(), mode=mode)
    db.add(row)
    db.commit()
    return RedirectResponse(f"/reviews/{row.id}", status_code=303)


@app.get("/reviews/{review_id}", response_class=HTMLResponse, dependencies=[Depends(require_login)])
def detail(review_id: int, request: Request, db: Session = Depends(get_db)):
    row = db.get(Review, review_id)
    if not row:
        raise HTTPException(404)
    return templates.TemplateResponse(request, "detail.html", {"r": row, "a": row.analysis})


@app.post("/reviews/{review_id}/human", dependencies=[Depends(require_login)])
def human_review(review_id: int, human_status: str = Form(...), human_severity: str = Form(""),
                 human_note: str = Form(""), db: Session = Depends(get_db)):
    row = db.get(Review, review_id)
    if not row:
        raise HTTPException(404)
    if human_status not in {"待复核", "漏洞成立", "证据不足", "不予认定"}:
        raise HTTPException(400, "无效状态")
    if human_severity not in {"", "Info", "Low", "Medium", "High", "Critical"}:
        raise HTTPException(400, "无效等级")
    row.human_status, row.human_severity, row.human_note = human_status, human_severity, human_note[:5000]
    db.commit()
    return RedirectResponse(f"/reviews/{row.id}", status_code=303)

