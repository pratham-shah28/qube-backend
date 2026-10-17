from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import text

from app.config import Settings, get_settings
from app.db import make_engine, request_engine
from app.routers import admin, auth, devices, me, taps
from app.security import RateLimiter


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="Qube API", version="0.1.0")
    app.state.settings = settings
    app.state.engine = make_engine(settings.db_url)
    app.state.request_engine = request_engine(app.state.engine)
    app.state.rate_limiter = RateLimiter()

    for r in (auth.router, me.router, devices.router, taps.router, admin.router):
        app.include_router(r)

    @app.get("/health", tags=["ops"])
    def health(request: Request):
        with request.app.state.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok"}

    @app.get("/t", response_class=HTMLResponse, include_in_schema=False)
    def tag_landing():
        # Tag URLs point here. With the app installed, the OS opens the app via universal /
        # app links and this page is never shown. It deliberately does not verify the tap, so
        # a browser visit doesn't use up a counter value.
        return _LANDING_HTML

    return app


_LANDING_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Qube</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem;
line-height:1.5;color:#111;background:#fff}@media(prefers-color-scheme:dark){body{color:#eee;
background:#111}}</style></head>
<body><h1>This is a Qube focus zone</h1>
<p>Install the Qube app and join with the invite code from your organization, then tap
this tag again to start a focus session.</p></body></html>"""
