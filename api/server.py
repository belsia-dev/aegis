import asyncio
import json
import secrets
import time
from collections import defaultdict, deque
from typing import AsyncGenerator, Deque, Dict, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from core.config import Config
from core.logger import get_logger
from detection.engine import DetectionEngine
from detection.script_analyzer import ScriptAnalyzer
from response.actions import ResponseEngine

logger   = get_logger("api")
security = HTTPBasic()

_FAIL_WINDOW  = 60
_FAIL_MAX     = 10
_LOCKOUT_TIME = 300

class _RateLimiter:
    def __init__(self):
        self._fails:   Dict[str, Deque[float]] = defaultdict(lambda: deque())
        self._locked:  Dict[str, float]        = {}

    def check(self, remote: str) -> bool:

        now = time.monotonic()
        if remote in self._locked:
            if now < self._locked[remote]:
                return False
            del self._locked[remote]
        dq = self._fails[remote]
        while dq and dq[0] < now - _FAIL_WINDOW:
            dq.popleft()
        return True

    def record_fail(self, remote: str):
        now = time.monotonic()
        dq  = self._fails[remote]
        dq.append(now)
        if len(dq) >= _FAIL_MAX:
            self._locked[remote] = now + _LOCKOUT_TIME
            logger.warning(
                "API login rate-limit: IP locked out",
                extra={"ip": remote, "lockout_seconds": _LOCKOUT_TIME},
            )

_limiter = _RateLimiter()

class WebServer:

    def __init__(
        self,
        config:      Config,
        detection:   DetectionEngine,
        response:    ResponseEngine,
        traffic=None,
        script_guard=None,
    ):
        self._config       = config
        self._detection    = detection
        self._response     = response
        self._traffic      = traffic
        self._script_guard = script_guard
        self._analyzer     = ScriptAnalyzer()

        self._host     = config.api("host",         "127.0.0.1")
        self._port     = int(config.api("port",     8731))
        self._username = config.api("username",     "admin")
        self._password = config.api("password",     "changeme")
        self._origins  = config.api("cors_origins", [f"http://localhost:8731"])
        self._app      = self._build_app()

    def _build_app(self) -> FastAPI:
        app = FastAPI(
            title="AEGIS", version="AEGIS",
            docs_url=None, redoc_url=None,
        )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=self._origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )
        app.state.server = self

        @app.get("/api/health", include_in_schema=False)
        async def health():
            return {"status": "ok", "ts": time.time(), "version": "AEGIS"}

        @app.get("/", response_class=HTMLResponse, include_in_schema=False)
        async def dashboard(creds: HTTPBasicCredentials = Depends(security)):
            self._auth(creds, request=None)
            return HTMLResponse(_DASHBOARD_HTML)

        @app.get("/api/events")
        async def get_events(
            limit: int = 50, offset: int = 0,
            creds: HTTPBasicCredentials = Depends(security),
        ):
            self._auth(creds)
            events = self._detection.recent_events(
                limit=min(limit, 500), offset=offset
            )
            return {"total": len(events), "offset": offset, "events": events}

        @app.get("/api/bans")
        async def get_bans(creds: HTTPBasicCredentials = Depends(security)):
            self._auth(creds)
            return {"bans": self._response.active_bans()}

        @app.post("/api/ban/{ip}")
        async def ban_ip(
            ip: str, creds: HTTPBasicCredentials = Depends(security)
        ):
            self._auth(creds)
            await self._response.manual_ban_ip(ip)
            logger.info("Manual ban via UI", extra={"ip": ip})
            return {"status": "banned", "ip": ip}

        @app.post("/api/unban/{ip}")
        async def unban(
            ip: str, creds: HTTPBasicCredentials = Depends(security)
        ):
            self._auth(creds)
            await self._response.unban_ip(ip)
            logger.info("Manual unban via UI", extra={"ip": ip})
            return {"status": "unbanned", "ip": ip}

        @app.post("/api/bans/refresh")
        async def refresh_bans(creds: HTTPBasicCredentials = Depends(security)):
            self._auth(creds)

            synced = await self._response.sync_bans_from_iptables()
            return {
                "status":       "refreshed",
                "synced_count": synced,
            }

        @app.get("/api/stats")
        async def get_stats(creds: HTTPBasicCredentials = Depends(security)):
            self._auth(creds)
            base: dict = {
                "ts":                  time.time(),
                "active_bans":         self._response.ban_count(),
                "tracked_ips":         len(self._detection.banned_ips()),
                "adaptive_multiplier": self._detection.adaptive_multiplier(),
                "dry_run":             self._config.dry_run,
                "firewall_backend":    self._config.firewall_backend,
            }
            if self._traffic:
                base["traffic"] = self._traffic.get_stats()
            return base

        @app.get("/api/offenders")
        async def get_offenders(
            n: int = 50,
            creds: HTTPBasicCredentials = Depends(security),
        ):
            self._auth(creds)
            return {"offenders": self._detection.top_offenders(min(n, 200))}

        @app.get("/api/traffic")
        async def get_traffic(creds: HTTPBasicCredentials = Depends(security)):
            self._auth(creds)
            if not self._traffic:
                return {"error": "traffic monitor not enabled"}
            return {
                "bandwidth":   self._traffic.get_bandwidth(),
                "connections": self._traffic.get_connections(limit=100),
                "history":     self._traffic.get_history(),
                "top_ips":     self._traffic.get_top_remote_ips(10),
                "stats":       self._traffic.get_stats(),
            }

        @app.get("/api/traffic/suspicious")
        async def get_suspicious(creds: HTTPBasicCredentials = Depends(security)):
            self._auth(creds)
            if not self._traffic:
                return {"suspicious": []}
            return {"suspicious": self._traffic.get_suspicious(50)}

        @app.post("/api/analyze")
        async def analyze_script(
            request: Request,
            creds: HTTPBasicCredentials = Depends(security),
        ):
            self._auth(creds)
            source = request.headers.get("X-Source", "api")
            body   = await request.body()
            script = body.decode("utf-8", errors="replace")
            if not script.strip():
                return {"safe": True, "score": 0, "findings": [], "layers": 0}
            loop   = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, self._analyzer.analyze, script, source
            )
            return result.to_dict()

        @app.get("/api/scripts")
        async def get_scripts(creds: HTTPBasicCredentials = Depends(security)):
            self._auth(creds)
            if not self._script_guard:
                return {"results": []}
            return {"results": self._script_guard.recent_results(50)}

        @app.get("/api/stream")
        async def stream(
            request: Request,
            creds: HTTPBasicCredentials = Depends(security),
        ):
            self._auth(creds)
            q = self._detection.subscribe_sse()

            async def _gen() -> AsyncGenerator[str, None]:
                try:
                    yield "event: connected\ndata: {}\n\n"
                    while True:
                        if await request.is_disconnected():
                            break
                        try:
                            ev = await asyncio.wait_for(q.get(), timeout=15.0)
                            yield f"event: alert\ndata: {json.dumps(ev, default=str)}\n\n"
                        except asyncio.TimeoutError:
                            yield ": heartbeat\n\n"
                finally:
                    self._detection.unsubscribe_sse(q)

            return StreamingResponse(
                _gen(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control":    "no-cache",
                    "X-Accel-Buffering":"no",
                },
            )

        return app

    def _auth(
        self,
        creds: HTTPBasicCredentials,
        request: Optional[Request] = None,
    ):
        remote = "unknown"
        if request:
            remote = request.client.host if request.client else "unknown"

        if not _limiter.check(remote):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again in 5 minutes.",
            )

        ok = (
            secrets.compare_digest(
                creds.username.encode("utf-8"), self._username.encode("utf-8")
            ) and
            secrets.compare_digest(
                creds.password.encode("utf-8"), self._password.encode("utf-8")
            )
        )
        if not ok:
            _limiter.record_fail(remote)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

    async def run(self):
        cfg = uvicorn.Config(
            app=self._app,
            host=self._host,
            port=self._port,
            log_level="warning",
            access_log=False,
            loop="none",
        )
        server = uvicorn.Server(cfg)
        logger.info("Web UI started",
                    extra={"host": self._host, "port": self._port})
        await server.serve()

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS — Security Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080c12;
  --surface:#0d1421;
  --surface2:#111928;
  --surface3:#161f2e;
  --border:#1e2d42;
  --border2:#243448;
  --accent:#3b9eff;
  --accent2:#1a7fe8;
  --danger:#f04747;
  --danger2:#c0392b;
  --warn:#f5a623;
  --warn2:#d4891d;
  --ok:#23d18b;
  --ok2:#1aaf72;
  --purple:#9b6bff;
  --cyan:#00d2ff;
  --pink:#ff4d8b;
  --text:#d4dff0;
  --text2:#8fa3be;
  --muted:#4d6480;
  --font:'Inter',system-ui,-apple-system,sans-serif;
  --mono:'JetBrains Mono','Fira Code',monospace;
  --glow-accent:0 0 20px rgba(59,158,255,.3);
  --glow-danger:0 0 20px rgba(240,71,71,.3);
  --glow-ok:0 0 20px rgba(35,209,139,.25);
}

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;min-height:100vh;overflow-x:hidden}
body::before{
  content:'';position:fixed;inset:0;
  background-image:radial-gradient(circle at 20% 20%,rgba(59,158,255,.04) 0,transparent 50%),
                   radial-gradient(circle at 80% 80%,rgba(155,107,255,.04) 0,transparent 50%);
  pointer-events:none;z-index:0;
}
header{
  background:rgba(13,20,33,.95);backdrop-filter:blur(12px);
  border-bottom:1px solid var(--border);
  padding:0 28px;height:60px;
  display:flex;align-items:center;gap:16px;
  position:sticky;top:0;z-index:200;
}
.logo{display:flex;align-items:center;gap:10px}
.logo svg{width:32px;height:32px}
.logo-text{font-size:18px;font-weight:700;letter-spacing:.5px;
           background:linear-gradient(135deg,var(--accent),var(--cyan));
           -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-ver{font-size:11px;color:var(--muted);font-weight:500;
          background:var(--surface3);padding:2px 6px;border-radius:4px;
          border:1px solid var(--border2);-webkit-text-fill-color:var(--muted)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--ok);
             box-shadow:var(--glow-ok);
             animation:pulse-dot 2.5s ease-in-out infinite}
@keyframes pulse-dot{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.3);opacity:.6}}

.live-badge{
  font-size:10px;font-weight:700;letter-spacing:1px;
  padding:3px 9px;border-radius:12px;
  background:rgba(35,209,139,.15);color:var(--ok);
  border:1px solid rgba(35,209,139,.3);
  text-transform:uppercase;
}
.live-badge.warn{background:rgba(240,71,71,.15);color:var(--danger);border-color:rgba(240,71,71,.3)}

#clock{margin-left:auto;font-size:12px;color:var(--muted);font-family:var(--mono)}
nav{
  background:rgba(13,20,33,.9);backdrop-filter:blur(8px);
  border-bottom:1px solid var(--border);
  padding:0 28px;display:flex;gap:2px;position:sticky;top:60px;z-index:100;
}
.tab{
  padding:13px 18px;cursor:pointer;font-size:13px;font-weight:500;
  color:var(--text2);border-bottom:2px solid transparent;
  transition:all .2s;display:flex;align-items:center;gap:6px;
}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-badge{
  font-size:10px;background:var(--danger);color:#fff;
  padding:1px 6px;border-radius:8px;font-weight:700;
}
#dry-run-banner{
  display:none;background:linear-gradient(90deg,var(--warn2),var(--warn));
  color:#000;text-align:center;padding:6px;font-weight:700;font-size:12px;
  letter-spacing:.3px;
}
.page{display:none;padding:24px 28px;max-width:1600px;margin:0 auto;position:relative;z-index:1}
.page.active{display:block}
.grid-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:20px;position:relative;overflow:hidden;transition:border-color .3s,transform .2s;
  cursor:default;
}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px)}
.stat-card::after{
  content:'';position:absolute;inset:0;border-radius:12px;
  background:linear-gradient(135deg,rgba(255,255,255,.02) 0,transparent 100%);
  pointer-events:none;
}
.stat-card .sc-label{font-size:10px;font-weight:700;color:var(--muted);
                     text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px;
                     display:flex;align-items:center;gap:6px}
.stat-card .sc-val{font-size:34px;font-weight:700;line-height:1;font-family:var(--mono)}
.stat-card .sc-sub{font-size:11px;color:var(--muted);margin-top:5px}
.sc-icon{font-size:16px}
.sc-r .sc-val{color:var(--danger)}
.sc-r{border-color:rgba(240,71,71,.2)}
.sc-y .sc-val{color:var(--warn)}
.sc-y{border-color:rgba(245,166,35,.2)}
.sc-g .sc-val{color:var(--ok)}
.sc-g{border-color:rgba(35,209,139,.2)}
.sc-b .sc-val{color:var(--accent)}
.sc-b{border-color:rgba(59,158,255,.2)}
.sc-p .sc-val{color:var(--purple)}
.sc-p{border-color:rgba(155,107,255,.2)}
.sc-c .sc-val{color:var(--cyan);font-size:22px}
.sc-c{border-color:rgba(0,210,255,.2)}
.adapt-bar{height:4px;border-radius:2px;background:var(--border2);margin-top:8px;overflow:hidden}
.adapt-fill{height:100%;border-radius:2px;background:var(--ok);transition:width .8s ease,background .6s}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:18px}
@media(max-width:1100px){.grid2,.grid3{grid-template-columns:1fr}}
.card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:20px;
}
.card-title{
  font-size:12px;font-weight:700;color:var(--text2);
  text-transform:uppercase;letter-spacing:.7px;margin-bottom:16px;
  display:flex;align-items:center;justify-content:space-between;
}
.card-title span{font-weight:400;font-size:11px;color:var(--muted);text-transform:none;letter-spacing:0}
.card.mb{margin-bottom:18px}
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{
  text-align:left;font-size:10px;font-weight:700;color:var(--muted);
  text-transform:uppercase;letter-spacing:.6px;
  padding:8px 12px;border-bottom:1px solid var(--border);white-space:nowrap;
}
td{
  padding:8px 12px;border-bottom:1px solid rgba(30,45,66,.5);
  font-size:12px;font-family:var(--mono);white-space:nowrap;
}
tr:last-child td{border:none}
tr:hover td{background:rgba(59,158,255,.03)}
.empty-row td{color:var(--muted);font-family:var(--font);padding:20px;text-align:center}
.pill{
  display:inline-flex;align-items:center;gap:4px;
  padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700;
  white-space:nowrap;
}
.pill-r{background:rgba(240,71,71,.15);color:var(--danger);border:1px solid rgba(240,71,71,.25)}
.pill-y{background:rgba(245,166,35,.15);color:var(--warn);border:1px solid rgba(245,166,35,.25)}
.pill-g{background:rgba(35,209,139,.15);color:var(--ok);border:1px solid rgba(35,209,139,.25)}
.pill-b{background:rgba(59,158,255,.15);color:var(--accent);border:1px solid rgba(59,158,255,.25)}
.pill-p{background:rgba(155,107,255,.15);color:var(--purple);border:1px solid rgba(155,107,255,.25)}
.pill-c{background:rgba(0,210,255,.12);color:var(--cyan);border:1px solid rgba(0,210,255,.25)}
.pill-muted{background:rgba(77,100,128,.15);color:var(--muted);border:1px solid rgba(77,100,128,.25)}
.feed{max-height:400px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
.fi{
  padding:9px 12px;border-bottom:1px solid rgba(30,45,66,.4);
  font-size:12px;font-family:var(--mono);display:flex;align-items:center;gap:8px;
  animation:fi-in .25s ease;transition:background .15s;
}
.fi:hover{background:rgba(59,158,255,.04)}
@keyframes fi-in{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:none}}
.fi .ts{color:var(--muted);min-width:76px;font-size:11px}
.fi .ev{min-width:0}
.fi .ip{color:var(--warn)}
.threat-ring{position:relative;width:100px;height:100px;margin:0 auto 12px}
.threat-ring svg{transform:rotate(-90deg)}
.threat-label{
  position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;font-weight:700;
}
.threat-level{font-size:20px;line-height:1}
.threat-text{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.btn{
  display:inline-flex;align-items:center;gap:6px;
  padding:7px 14px;border-radius:7px;cursor:pointer;
  font-size:12px;font-weight:600;border:none;transition:all .2s;
}
.btn:disabled{opacity:.5;cursor:default}
.btn-danger{background:var(--danger2);color:#fff}
.btn-danger:hover:not(:disabled){background:var(--danger)}
.btn-warn{background:transparent;border:1px solid var(--warn)!important;color:var(--warn)}
.btn-warn:hover:not(:disabled){background:rgba(245,166,35,.1)}
.btn-ok{background:transparent;border:1px solid var(--ok)!important;color:var(--ok)}
.btn-ok:hover:not(:disabled){background:rgba(35,209,139,.1)}
.btn-ghost{background:var(--surface3);border:1px solid var(--border2)!important;color:var(--text2)}
.btn-ghost:hover:not(:disabled){background:var(--surface2);color:var(--text)}
.btn-primary{background:var(--accent2);color:#fff}
.btn-primary:hover:not(:disabled){background:var(--accent)}
.ban-form{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.inp{
  background:var(--bg);border:1px solid var(--border2);color:var(--text);
  padding:8px 12px;border-radius:7px;font-size:13px;font-family:var(--mono);
  flex:1;min-width:220px;transition:border-color .2s;
}
.inp:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,158,255,.1)}
.inp::placeholder{color:var(--muted)}
[data-tip]{position:relative}
[data-tip]:hover::after{
  content:attr(data-tip);position:absolute;bottom:calc(100%+6px);left:50%;
  transform:translateX(-50%);white-space:nowrap;
  background:#1a2535;border:1px solid var(--border2);
  color:var(--text);font-size:11px;padding:4px 8px;border-radius:5px;
  pointer-events:none;z-index:999;
}
.ch{position:relative;height:200px}
.ch-tall{position:relative;height:280px}
.bw-iface{margin-bottom:12px}
.bw-label{display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px}
.bw-track{height:6px;border-radius:3px;background:var(--border2);overflow:hidden;margin-bottom:2px}
.bw-fill-rx{height:100%;border-radius:3px;background:var(--ok);transition:width .6s}
.bw-fill-tx{height:100%;border-radius:3px;background:var(--accent);transition:width .6s}
.sr{
  background:var(--bg);border:1px solid var(--border2);
  border-radius:8px;padding:14px 16px;margin-bottom:10px;
}
.sr.unsafe{border-color:rgba(240,71,71,.4);background:rgba(240,71,71,.03)}
.sr.safe{border-color:rgba(35,209,139,.2)}
.sr-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.sr-finding{padding:3px 0;display:flex;gap:8px;font-size:11px;font-family:var(--mono)}
.decoded-pre{
  background:var(--surface2);border:1px solid var(--border);padding:10px 12px;
  border-radius:6px;font-size:11px;font-family:var(--mono);overflow-x:auto;
  max-height:180px;color:var(--warn);white-space:pre-wrap;margin-top:10px;
}
.conn-susp td:first-child::before{content:'⚠ ';color:var(--danger)}
.conn-susp{background:rgba(240,71,71,.04)}
#hosting-overlay{
  display:none;position:fixed;inset:0;
  background:rgba(4,8,16,.85);backdrop-filter:blur(4px);
  z-index:9999;align-items:flex-start;justify-content:center;padding-top:80px;
}
#hosting-overlay.on{display:flex}
#hosting-modal{
  background:var(--surface);border:2px solid var(--warn);
  border-radius:14px;max-width:680px;width:95%;
  padding:28px 32px;box-shadow:0 16px 64px rgba(0,0,0,.7),var(--glow-danger);
  max-height:75vh;overflow-y:auto;animation:modal-in .2s ease;
}
@keyframes modal-in{from{transform:translateY(-20px) scale(.97);opacity:0}to{transform:none scale(1);opacity:1}}
#hosting-modal h2{color:var(--warn);font-size:17px;margin-bottom:4px}
#hosting-modal .sub{color:var(--text2);font-size:12px;margin-bottom:20px}
.he{
  background:var(--bg);border:1px solid var(--border2);
  border-radius:8px;padding:14px 16px;margin-bottom:12px;
}
.he-ip{font-size:16px;font-weight:700;color:var(--warn);font-family:var(--mono)}
.he-org{font-size:13px;margin:4px 0;color:var(--text)}
.he-meta{font-size:11px;color:var(--muted);margin-bottom:10px}
.he-btns{display:flex;gap:8px}
.modal-dismiss{
  display:block;width:100%;margin-top:16px;
  background:none;border:1px solid var(--border2);
  color:var(--text2);padding:9px;border-radius:7px;
  cursor:pointer;font-size:13px;transition:all .2s;
}
.modal-dismiss:hover{background:var(--surface2);color:var(--text)}
.score-bar-wrap{display:flex;align-items:center;gap:8px;min-width:120px}
.score-bar-bg{flex:1;height:5px;background:var(--border2);border-radius:3px;overflow:hidden}
.score-bar-fill{height:100%;border-radius:3px;background:var(--ok);transition:width .6s}
#toast-container{position:fixed;bottom:24px;right:24px;z-index:9000;display:flex;flex-direction:column;gap:8px}
.toast{
  background:var(--surface3);border:1px solid var(--border2);
  border-radius:8px;padding:12px 16px;font-size:13px;min-width:250px;
  box-shadow:0 4px 20px rgba(0,0,0,.5);
  animation:toast-in .3s ease;
}
.toast.r{border-color:rgba(240,71,71,.5);background:rgba(240,71,71,.1)}
.toast.g{border-color:rgba(35,209,139,.5);background:rgba(35,209,139,.08)}
@keyframes toast-in{from{transform:translateX(20px);opacity:0}to{transform:none;opacity:1}}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
.ev-filter-row{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.ev-filter-row .inp{min-width:200px;max-width:300px;font-size:12px}
.flag{font-size:16px;vertical-align:middle;margin-right:2px}
</style>
</head>
<body>

<div id="hosting-overlay">
  <div id="hosting-modal">
    <h2>⚠ Hosting/Datacenter IP Alert</h2>
    <p class="sub">The following attacking IPs belong to hosting providers. Consider reporting the abuse.</p>
    <div id="hosting-list"></div>
    <button class="modal-dismiss" onclick="dismissAll()">✕ Dismiss all</button>
  </div>
</div>

<div id="toast-container"></div>
<div id="dry-run-banner">⚠ DRY-RUN MODE — Firewall rules are NOT being applied</div>

<header>
  <div class="logo">
    <svg viewBox="0 0 32 32" fill="none">
      <path d="M16 2L4 7v9c0 7.2 5.1 13.8 12 15.5C23 29.8 28 23.2 28 16V7L16 2z"
            fill="url(#sg)" stroke="rgba(59,158,255,.4)" stroke-width="1"/>
      <path d="M11 15.5l3 3 6-6" stroke="#23d18b" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round"/>
      <defs>
        <linearGradient id="sg" x1="4" y1="2" x2="28" y2="32">
          <stop offset="0%" stop-color="#0d1421"/>
          <stop offset="100%" stop-color="#111928"/>
        </linearGradient>
      </defs>
    </svg>
    <span class="logo-text">AEGIS</span>
  </div>
  <div class="status-dot" id="dot"></div>
  <span class="live-badge" id="live-badge">LIVE</span>
  <span id="clock"></span>
</header>

<nav>
  <div class="tab active" onclick="showTab('overview',this)">🛡 Overview</div>
  <div class="tab" onclick="showTab('traffic',this)">📡 Traffic</div>
  <div class="tab" onclick="showTab('bans',this)">🔒 Bans <span class="tab-badge" id="ban-badge" style="display:none"></span></div>
  <div class="tab" onclick="showTab('events',this)">📋 Events</div>
  <div class="tab" onclick="showTab('scripts',this)">🔍 Script Guard</div>
</nav>
<div id="tab-overview" class="page active">
  <div class="grid-stats">
    <div class="stat-card sc-r">
      <div class="sc-label"><span class="sc-icon">🔴</span>Active Bans</div>
      <div class="sc-val" id="s-bans">—</div>
      <div class="sc-sub">IPs currently blocked</div>
    </div>
    <div class="stat-card sc-y">
      <div class="sc-label"><span class="sc-icon">👁</span>Tracked IPs</div>
      <div class="sc-val" id="s-tracked">—</div>
      <div class="sc-sub">In scoring engine</div>
    </div>
    <div class="stat-card sc-b">
      <div class="sc-label"><span class="sc-icon">🌐</span>Connections</div>
      <div class="sc-val" id="s-conns">—</div>
      <div class="sc-sub">Active network</div>
    </div>
    <div class="stat-card sc-r">
      <div class="sc-label"><span class="sc-icon">⚡</span>Suspicious</div>
      <div class="sc-val" id="s-susp">—</div>
      <div class="sc-sub">Flagged outbound</div>
    </div>
    <div class="stat-card sc-g">
      <div class="sc-label"><span class="sc-icon">▼</span>RX</div>
      <div class="sc-val" id="s-rx" style="font-size:22px">—</div>
      <div class="sc-sub">Inbound bandwidth</div>
    </div>
    <div class="stat-card sc-b">
      <div class="sc-label"><span class="sc-icon">▲</span>TX</div>
      <div class="sc-val" id="s-tx" style="font-size:22px">—</div>
      <div class="sc-sub">Outbound bandwidth</div>
    </div>
    <div class="stat-card sc-c">
      <div class="sc-label"><span class="sc-icon">🔥</span>Firewall</div>
      <div class="sc-val" id="s-fw">—</div>
      <div class="sc-sub">Backend</div>
    </div>
    <div class="stat-card sc-p">
      <div class="sc-label"><span class="sc-icon">🧠</span>Adaptive Threat</div>
      <div class="sc-val" id="s-adapt" style="font-size:24px">—</div>
      <div class="adapt-bar"><div class="adapt-fill" id="adapt-fill"></div></div>
      <div class="sc-sub" id="s-adapt-label">Multiplier</div>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <div class="card-title">⚡ Live Threat Feed <span id="feed-count"></span></div>
      <div class="feed" id="feed"><div style="color:var(--muted);padding:12px;font-size:13px">Waiting for events…</div></div>
    </div>
    <div class="card">
      <div class="card-title">🎯 Top Offenders <span>Score 0–100</span></div>
      <div class="ch"><canvas id="scoreChart"></canvas></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">⚠ Suspicious Outbound Connections</div>
    <div class="tbl-wrap">
    <table>
      <thead><tr><th>Time</th><th>Local</th><th>Remote</th><th>Port</th><th>Proto</th><th>State</th></tr></thead>
      <tbody id="susp-tbody"><tr class="empty-row"><td colspan="6">✓ No suspicious connections detected</td></tr></tbody>
    </table>
    </div>
  </div>
</div>
<div id="tab-traffic" class="page">
  <div id="bw-section" class="card mb">
    <div class="card-title">📡 Interface Bandwidth</div>
    <div id="bw-ifaces"></div>
  </div>
  <div class="grid2">
    <div class="card">
      <div class="card-title">📈 Bandwidth History</div>
      <div class="ch-tall"><canvas id="trafficChart"></canvas></div>
    </div>
    <div class="card">
      <div class="card-title">🌐 Top Remote IPs</div>
      <table>
        <thead><tr><th>#</th><th>IP</th><th>Connections</th><th>Action</th></tr></thead>
        <tbody id="top-ips-tbody"></tbody>
      </table>
    </div>
  </div>
  <div class="card">
    <div class="card-title">🔌 Active Connections
      <span id="conn-count"></span>
    </div>
    <div class="tbl-wrap">
    <table>
      <thead><tr><th>Local</th><th>Remote</th><th>Protocol</th><th>State</th></tr></thead>
      <tbody id="conn-tbody"><tr class="empty-row"><td colspan="4">Loading…</td></tr></tbody>
    </table>
    </div>
  </div>
</div>
<div id="tab-bans" class="page">
  <div class="card mb">
    <div class="card-title">🔒 Ban Management</div>
    <div class="ban-form">
      <input class="inp" id="ban-ip" type="text" placeholder="IP or CIDR to ban (e.g. 1.2.3.4)"
             onkeydown="if(event.key==='Enter')doBan()">
      <button class="btn btn-danger" onclick="doBan()">🔒 Ban IP</button>
      <button class="btn btn-ghost" onclick="doRefresh(this)" data-tip="Import IPs already in iptables AEGIS chain">⟳ Sync from iptables</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Active Bans <span id="bans-count"></span></div>
    <div class="tbl-wrap">
    <table>
      <thead><tr><th>IP</th><th>Since</th><th>Expires / Status</th><th>Reason</th><th>Remaining</th><th>Actions</th></tr></thead>
      <tbody id="bans-tbody"><tr class="empty-row"><td colspan="6">Loading…</td></tr></tbody>
    </table>
    </div>
  </div>
</div>
<div id="tab-events" class="page">
  <div class="card">
    <div class="card-title">📋 Recent Events</div>
    <div class="ev-filter-row">
      <input class="inp" id="ev-filter" placeholder="Filter by IP, event type, user…" oninput="evOffset=0;loadEvents(0)">
      <select class="inp" id="ev-sev-filter" style="max-width:160px" onchange="evOffset=0;loadEvents(0)">
        <option value="">All severities</option>
        <option value="high">High (≥70)</option>
        <option value="med">Medium (40–69)</option>
        <option value="low">Low (&lt;40)</option>
      </select>
      <span style="color:var(--muted);font-size:12px" id="ev-page"></span>
    </div>
    <div class="tbl-wrap">
    <table>
      <thead><tr><th>Time</th><th>Event</th><th>IP</th><th>User</th><th>Score</th><th>Log Type</th><th>Actions</th></tr></thead>
      <tbody id="ev-tbody"></tbody>
    </table>
    </div>
    <div style="margin-top:14px;display:flex;gap:10px;align-items:center">
      <button class="btn btn-ghost" onclick="loadEvents(evOffset-50)">◀ Prev</button>
      <button class="btn btn-ghost" onclick="loadEvents(evOffset+50)">Next ▶</button>
    </div>
  </div>
</div>
<div id="tab-scripts" class="page">
  <div class="card mb">
    <div class="card-title">🔍 Analyze Script Manually</div>
    <textarea id="script-input" rows="7"
      style="width:100%;background:var(--bg);border:1px solid var(--border2);color:var(--text);
             padding:12px;border-radius:7px;font-family:var(--mono);font-size:12px;resize:vertical"
      placeholder="Paste a bash script, Python snippet, command line, or URL to analyze for threats…"></textarea>
    <div style="margin-top:10px;display:flex;gap:10px;align-items:center">
      <button class="btn btn-primary" onclick="analyzeScript()">🔍 Analyze</button>
      <button class="btn btn-ghost" onclick="document.getElementById('script-input').value=''">Clear</button>
      <span style="font-size:11px;color:var(--muted)">Supports: bash, Python, Perl, PHP, obfuscated scripts, base64 payloads</span>
    </div>
    <div id="analysis-result" style="margin-top:16px"></div>
  </div>
  <div class="card">
    <div class="card-title">🚨 Recent Script Interceptions
      <span id="script-count"></span>
    </div>
    <div id="scripts-list"></div>
  </div>
</div>

<footer style="text-align:center;padding:24px;color:var(--muted);font-size:11px;position:relative;z-index:1">
  AEGIS — Adaptive Engine for Guardian Intelligence &amp; Security — All times UTC
</footer>

<script>
let evOffset=0, scoreChart=null, trafficChart=null;
const hostingAlerts=new Map();
let feedItems=0;
function tick(){
  document.getElementById('clock').textContent=
    new Date().toISOString().replace('T',' ').slice(0,19)+' UTC';
}
tick();setInterval(tick,1000);
function toast(msg,cls='',dur=3500){
  const el=document.createElement('div');
  el.className='toast '+(cls||'');
  el.textContent=msg;
  document.getElementById('toast-container').prepend(el);
  setTimeout(()=>el.remove(),dur);
}
function showTab(name,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  (el||document.querySelector('.tab')).classList.add('active');
  if(name==='traffic') loadTraffic();
  if(name==='scripts') loadScripts();
  if(name==='bans')    loadBans();
  if(name==='events')  loadEvents(0);
}
const ts=e=>e?new Date(e*1000).toISOString().replace('T',' ').slice(0,19):'—';
const sc=v=>v>=70?'pill-r':v>=40?'pill-y':'pill-g';
const fmt=b=>{if(b>1e9)return(b/1e9).toFixed(2)+' GB/s';if(b>1e6)return(b/1e6).toFixed(1)+' MB/s';if(b>1e3)return(b/1e3).toFixed(1)+' KB/s';return Math.round(b)+' B/s';};
const pill=(t,c)=>`<span class="pill ${c}">${t}</span>`;
const ttl=t=>t?Math.floor(t/60)+'m '+Math.floor(t%60)+'s':'—';
async function loadStats(){
  try{
    const r=await fetch('/api/stats');if(!r.ok)return;
    const d=await r.json();
    document.getElementById('s-bans').textContent=d.active_bans??'—';
    document.getElementById('s-tracked').textContent=d.tracked_ips??'—';
    document.getElementById('s-fw').textContent=(d.firewall_backend||'?').toUpperCase();
    const mult=d.adaptive_multiplier||1;
    document.getElementById('s-adapt').textContent=mult.toFixed(1)+'×';
    document.getElementById('s-adapt-label').textContent=
      mult>=1.8?'🔴 CRITICAL THREAT SURGE':mult>=1.3?'🟡 ELEVATED THREAT':'✓ Normal';
    const fill=document.getElementById('adapt-fill');
    fill.style.width=Math.min(100,Math.round((mult-1)*100))+'%';
    fill.style.background=mult>=1.8?'var(--danger)':mult>=1.3?'var(--warn)':'var(--ok)';
    if(d.dry_run)document.getElementById('dry-run-banner').style.display='block';
    const bb=document.getElementById('ban-badge');
    if(d.active_bans>0){bb.textContent=d.active_bans;bb.style.display='inline-block';}
    else bb.style.display='none';
    if(d.traffic){
      document.getElementById('s-conns').textContent=d.traffic.total_connections??0;
      document.getElementById('s-susp').textContent=d.traffic.suspicious_active??0;
      document.getElementById('s-rx').textContent=fmt(d.traffic.total_rx_bps??0);
      document.getElementById('s-tx').textContent=fmt(d.traffic.total_tx_bps??0);
    }
  }catch(e){}
}
async function loadSuspicious(){
  try{
    const r=await fetch('/api/traffic/suspicious');if(!r.ok)return;
    const {suspicious}=await r.json();
    const tb=document.getElementById('susp-tbody');
    if(!suspicious.length){
      tb.innerHTML='<tr class="empty-row"><td colspan="6">✓ No suspicious connections</td></tr>';return;
    }
    tb.innerHTML=suspicious.slice(0,20).map(c=>`
      <tr class="conn-susp">
        <td>${ts(c.ts)}</td>
        <td>${c.local||'—'}</td>
        <td style="color:var(--danger)">${c.remote||'—'}</td>
        <td>${pill(c.remote_port,'pill-r')}</td>
        <td>${pill(c.proto,'pill-b')}</td>
        <td>${c.state}</td>
      </tr>`).join('');
  }catch(e){}
}
async function loadBans(){
  try{
    const r=await fetch('/api/bans');if(!r.ok)return;
    const {bans}=await r.json();
    document.getElementById('bans-count').textContent=bans.length+' total';
    const tb=document.getElementById('bans-tbody');
    if(!bans.length){tb.innerHTML='<tr class="empty-row"><td colspan="6">✓ No active bans</td></tr>';return;}
    tb.innerHTML=bans.map(b=>`
      <tr>
        <td style="color:var(--warn)">${b.ip}</td>
        <td>${ts(b.ban_time)}</td>
        <td>${b.permanent?pill('PERMANENT','pill-r'):ts(b.ban_until)}</td>
        <td>${pill(b.reason||'?','pill-muted')}</td>
        <td>${b.permanent?'∞':ttl(b.remaining_seconds)}</td>
        <td><button class="btn btn-warn" style="padding:3px 10px" onclick="doUnban('${b.ip}')">Unban</button></td>
      </tr>`).join('');
  }catch(e){}
}

async function doBan(){
  const ip=document.getElementById('ban-ip').value.trim();
  if(!ip){toast('Enter an IP address first','r');return;}
  if(!confirm('Permanently ban '+ip+'?'))return;
  try{
    const r=await fetch('/api/ban/'+encodeURIComponent(ip),{method:'POST'});
    if(r.ok){document.getElementById('ban-ip').value='';loadBans();loadStats();toast('Banned '+ip,'r');}
    else toast('Ban failed: '+(await r.text()),'r');
  }catch(e){toast('Error: '+e.message,'r');}
}
async function doUnban(ip){
  if(!confirm('Unban '+ip+'?'))return;
  try{
    const r=await fetch('/api/unban/'+ip,{method:'POST'});
    if(r.ok){loadBans();loadStats();toast('Unbanned '+ip,'g');}
    else toast('Unban failed','r');
  }catch(e){toast('Error','r');}
}
async function doRefresh(btn){
  btn.textContent='⟳ Syncing…';btn.disabled=true;
  try{
    const r=await fetch('/api/bans/refresh',{method:'POST'});
    if(r.ok){
      const d=await r.json();
      btn.textContent='✓ Synced '+d.synced_count;
      toast('Synced '+d.synced_count+' IPs from iptables','g');
      loadBans();loadStats();
    }else{btn.textContent='⚠ Failed';toast('Sync failed','r');}
  }catch(e){btn.textContent='⚠ Error';}
  setTimeout(()=>{btn.textContent='⟳ Sync from iptables';btn.disabled=false;},3000);
}
async function loadEvents(offset){
  if(offset<0)offset=0;evOffset=offset;
  const filter=document.getElementById('ev-filter').value.trim();
  const sevF=document.getElementById('ev-sev-filter').value;
  try{
    const r=await fetch('/api/events?limit=50&offset='+offset);if(!r.ok)return;
    const {events}=await r.json();
    let filtered=filter?events.filter(e=>JSON.stringify(e).toLowerCase().includes(filter.toLowerCase())):events;
    if(sevF==='high') filtered=filtered.filter(e=>(e.score||0)>=70);
    else if(sevF==='med') filtered=filtered.filter(e=>(e.score||0)>=40&&(e.score||0)<70);
    else if(sevF==='low') filtered=filtered.filter(e=>(e.score||0)<40);
    document.getElementById('ev-page').textContent=`${offset}–${offset+filtered.length} of ${events.length}`;
    const tb=document.getElementById('ev-tbody');
    if(!filtered.length){tb.innerHTML='<tr class="empty-row"><td colspan="7">No events</td></tr>';return;}
    tb.innerHTML=filtered.map(e=>`
      <tr>
        <td>${ts(e.ts)}</td>
        <td>${pill(e.event_type||'?','pill-b')}</td>
        <td style="color:var(--warn)">${e.ip||'—'}</td>
        <td>${e.user||'—'}</td>
        <td>${e.score!=null?pill(e.score,sc(e.score)):'—'}</td>
        <td>${pill(e.log_type||'?','pill-muted')}</td>
        <td>${e.ip?`<button class="btn btn-warn" style="padding:2px 8px;font-size:11px" onclick="banFromEvent('${e.ip}')">Ban</button>`:''}</td>
      </tr>`).join('');
  }catch(err){}
}
async function banFromEvent(ip){
  if(!confirm('Ban '+ip+'?'))return;
  try{
    await fetch('/api/ban/'+encodeURIComponent(ip),{method:'POST'});
    toast('Banned '+ip,'r');loadStats();loadBans();
  }catch(e){}
}
async function loadTraffic(){
  try{
    const r=await fetch('/api/traffic');if(!r.ok)return;
    const d=await r.json();
    const bwSec=document.getElementById('bw-ifaces');
    const bw=d.bandwidth||{};
    bwSec.innerHTML=Object.entries(bw).map(([iface,v])=>`
      <div class="bw-iface">
        <div class="bw-label">
          <span style="color:var(--text);font-weight:600">${iface}</span>
          <span><span style="color:var(--ok)">▼ ${fmt(v.rx_bps)}</span> &nbsp; <span style="color:var(--accent)">▲ ${fmt(v.tx_bps)}</span></span>
        </div>
        <div class="bw-track"><div class="bw-fill-rx" style="width:${Math.min(100,(v.rx_bps/5e6)*100)}%"></div></div>
        <div class="bw-track"><div class="bw-fill-tx" style="width:${Math.min(100,(v.tx_bps/5e6)*100)}%"></div></div>
      </div>`).join('') || '<div style="color:var(--muted)">No interface data</div>';
    const hist=d.history||[];
    const labels=hist.map(h=>new Date(h.ts*1000).toISOString().slice(11,19));
    const rx=hist.map(h=>h.rx),tx=hist.map(h=>h.tx);
    if(trafficChart){
      trafficChart.data.labels=labels;
      trafficChart.data.datasets[0].data=rx;
      trafficChart.data.datasets[1].data=tx;
      trafficChart.update('none');
    }else{
      const ctx=document.getElementById('trafficChart').getContext('2d');
      trafficChart=new Chart(ctx,{
        type:'line',
        data:{labels,datasets:[
          {label:'RX',data:rx,borderColor:'#23d18b',backgroundColor:'rgba(35,209,139,.08)',fill:true,tension:.35,pointRadius:0,borderWidth:1.5},
          {label:'TX',data:tx,borderColor:'#3b9eff',backgroundColor:'rgba(59,158,255,.08)',fill:true,tension:.35,pointRadius:0,borderWidth:1.5},
        ]},
        options:{
          responsive:true,maintainAspectRatio:false,animation:{duration:0},
          plugins:{legend:{labels:{color:'#8fa3be',font:{size:11}}}},
          scales:{
            x:{ticks:{color:'#4d6480',font:{size:10},maxTicksLimit:8},grid:{color:'#1e2d42'}},
            y:{ticks:{color:'#4d6480',font:{size:10},callback:v=>fmt(v)},grid:{color:'#1e2d42'}},
          }
        }
      });
    }
    const ti=document.getElementById('top-ips-tbody');
    ti.innerHTML=(d.top_ips||[]).map((t,i)=>`
      <tr>
        <td style="color:var(--muted)">${i+1}</td>
        <td style="color:var(--warn)">${t.ip}</td>
        <td>${t.connections}</td>
        <td><button class="btn btn-warn" style="padding:2px 8px;font-size:11px" onclick="banFromEvent('${t.ip}')">Ban</button></td>
      </tr>`).join('')||'<tr class="empty-row"><td colspan="4">No data</td></tr>';
    const conns=d.connections||[];
    document.getElementById('conn-count').textContent=conns.length+' connections';
    const ct=document.getElementById('conn-tbody');
    if(!conns.length){ct.innerHTML='<tr class="empty-row"><td colspan="4">No active connections</td></tr>';return;}
    ct.innerHTML=conns.slice(0,100).map(c=>`
      <tr class="${c.suspicious?'conn-susp':''}">
        <td>${c.local}</td>
        <td style="color:${c.suspicious?'var(--danger)':'var(--text)'}">${c.remote}${c.suspicious?' ⚠':''}</td>
        <td>${pill(c.proto,'pill-b')}</td>
        <td>${pill(c.state,c.state==='ESTABLISHED'?'pill-g':c.state==='LISTEN'?'pill-b':'pill-y')}</td>
      </tr>`).join('');
  }catch(e){}
}
async function loadChart(){
  try{
    const r=await fetch('/api/offenders?n=15');if(!r.ok)return;
    const {offenders}=await r.json();
    const labels=offenders.map(o=>o.ip),vals=offenders.map(o=>o.score);
    const colors=vals.map(v=>v>=70?'rgba(240,71,71,.8)':v>=40?'rgba(245,166,35,.8)':'rgba(35,209,139,.7)');
    if(scoreChart){
      scoreChart.data.labels=labels;
      scoreChart.data.datasets[0].data=vals;
      scoreChart.data.datasets[0].backgroundColor=colors;
      scoreChart.update();return;
    }
    const ctx=document.getElementById('scoreChart').getContext('2d');
    scoreChart=new Chart(ctx,{
      type:'bar',
      data:{labels,datasets:[{label:'Threat Score',data:vals,backgroundColor:colors,borderRadius:5,borderSkipped:false}]},
      options:{
        responsive:true,maintainAspectRatio:false,
        plugins:{legend:{display:false}},
        scales:{
          x:{ticks:{color:'#4d6480',font:{size:9},maxRotation:45},grid:{color:'#1e2d42'}},
          y:{min:0,max:100,ticks:{color:'#4d6480',font:{size:10}},grid:{color:'#1e2d42'}},
        }
      }
    });
  }catch(e){}
}
async function loadScripts(){
  try{
    const r=await fetch('/api/scripts');if(!r.ok)return;
    const {results}=await r.json();
    document.getElementById('script-count').textContent=results.length+' results';
    const list=document.getElementById('scripts-list');
    if(!results.length){list.innerHTML='<div style="color:var(--muted);padding:12px">No interceptions yet ✓</div>';return;}
    list.innerHTML=results.map(s=>`
      <div class="sr ${s.safe?'safe':'unsafe'}">
        <div class="sr-head">
          <span>
            ${s.safe?pill('✓ SAFE','pill-g'):pill('⚠ BLOCKED','pill-r')}
            <span style="color:var(--muted);font-size:11px;margin-left:10px">${ts(s.ts)}</span>
            ${s.pid?`<span style="color:var(--muted);font-size:11px"> · PID ${s.pid}</span>`:''}
            ${s.parent?`<span style="color:var(--muted);font-size:11px"> via ${s.parent}</span>`:''}
          </span>
          <span>
            ${pill('score '+s.score,s.score>=60?'pill-r':s.score>=30?'pill-y':'pill-g')}
            ${s.layers>0?pill(s.layers+' layers','pill-p'):''}
          </span>
        </div>
        <div style="font-size:11px;color:var(--muted);font-family:var(--mono)">
          SHA256: ${(s.sha256||'').slice(0,24)}… · ${s.source||'?'}
        </div>
        ${s.findings&&s.findings.length?`
        <div style="margin-top:8px">
          ${s.findings.slice(0,6).map(f=>`
            <div class="sr-finding">
              <span style="color:${f.severity>=60?'var(--danger)':f.severity>=30?'var(--warn)':'var(--muted)'}">[${f.category}]</span>
              <span style="color:var(--text2)">${f.detail}</span>
              <span style="color:var(--muted)">sev:${f.severity}</span>
            </div>`).join('')}
        </div>`:''
      }
      </div>`).join('');
  }catch(e){}
}

async function analyzeScript(){
  const script=document.getElementById('script-input').value.trim();
  if(!script){toast('Paste a script first');return;}
  const rd=document.getElementById('analysis-result');
  rd.innerHTML='<div style="color:var(--muted)">⏳ Analyzing…</div>';
  try{
    const r=await fetch('/api/analyze',{
      method:'POST',headers:{'Content-Type':'text/plain','X-Source':'manual'},body:script,
    });
    const d=await r.json();
    rd.innerHTML=`
      <div class="sr ${d.safe?'safe':'unsafe'}">
        <div class="sr-head">
          <strong style="font-size:15px;color:${d.safe?'var(--ok)':'var(--danger)'}">${d.safe?'✓ SAFE':'⚠ UNSAFE'}</strong>
          <span>
            ${pill('score '+d.score,d.score>=60?'pill-r':d.score>=30?'pill-y':'pill-g')}
            ${d.layers>0?pill(d.layers+' obfuscation layers decoded','pill-p'):''}
          </span>
        </div>
        ${d.findings&&d.findings.length?`
        <div style="margin-top:10px">
          ${d.findings.map(f=>`
            <div class="sr-finding">
              <span style="color:${f.severity>=60?'var(--danger)':f.severity>=30?'var(--warn)':'var(--muted)'}">
                ${f.severity>=70?'🔴':f.severity>=40?'🟡':'🟠'} [${f.category}] sev:${f.severity}
              </span>
              <span>${f.detail}</span>
            </div>`).join('')}
        </div>`:`<div style="color:var(--ok);font-size:12px;margin-top:8px">✓ No dangerous patterns found.</div>`}
        ${d.deobfuscated?`
          <div style="color:var(--muted);font-size:11px;margin-top:12px">Decoded (${d.layers} layer${d.layers!==1?'s':''}):</div>
          <div class="decoded-pre">${d.deobfuscated.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>`:''
        }
      </div>`;
    toast(d.safe?'Script appears safe':'⚠ Unsafe script detected',d.safe?'g':'r');
  }catch(e){rd.innerHTML='<div style="color:var(--danger)">Analysis failed: '+e.message+'</div>';}
}
function showHostingAlert(e){
  if(hostingAlerts.has(e.ip))return;
  hostingAlerts.set(e.ip,e);renderHostingModal();
}
function renderHostingModal(){
  const ov=document.getElementById('hosting-overlay');
  if(!hostingAlerts.size){ov.classList.remove('on');return;}
  ov.classList.add('on');
  const list=document.getElementById('hosting-list');
  list.innerHTML='';
  hostingAlerts.forEach((e,ip)=>{
    const div=document.createElement('div');div.className='he';
    div.innerHTML=`
      <div class="he-ip">${ip}</div>
      <div class="he-org">${e.ipinfo_org||'Unknown org'}</div>
      <div class="he-meta">
        ${e.country?'Country: '+e.country:''}
        ${e.ipinfo_city?' · '+e.ipinfo_city:''}
        ${e.abuse_score!=null?' · AbuseIPDB: '+e.abuse_score+'%':''}
        · Score: ${e.score??'—'}
      </div>
      <div class="he-btns">
        <button class="btn btn-danger" onclick="banHosting('${ip}')">🔒 Ban</button>
        <button class="btn btn-ok" onclick="dismissHosting('${ip}')">✓ Reported</button>
      </div>`;
    list.appendChild(div);
  });
}
async function banHosting(ip){
  await fetch('/api/ban/'+encodeURIComponent(ip),{method:'POST'});
  toast('Banned '+ip,'r');loadStats();loadBans();dismissHosting(ip);
}
function dismissHosting(ip){hostingAlerts.delete(ip);renderHostingModal();}
function dismissAll(){hostingAlerts.clear();renderHostingModal();}
function connectSSE(){
  const es=new EventSource('/api/stream');
  const dot=document.getElementById('dot'),badge=document.getElementById('live-badge');
  es.addEventListener('alert',e=>{
    const ev=JSON.parse(e.data);
    prependFeed(ev);
    if(ev.is_hosting&&ev.ip)showHostingAlert(ev);
  });
  es.addEventListener('connected',()=>{
    dot.style.background='var(--ok)';
    badge.textContent='LIVE';badge.className='live-badge';
  });
  es.onerror=()=>{
    dot.style.background='var(--danger)';
    badge.textContent='RECONNECTING';badge.className='live-badge warn';
    setTimeout(connectSSE,5000);es.close();
  };
}

function prependFeed(ev){
  const feed=document.getElementById('feed');
  const item=document.createElement('div');
  item.className='fi';
  const sev=ev.severity>=70?'🔴':ev.severity>=40?'🟡':'🟢';
  const isBan=ev.score>=70;
  const isScript=ev.event_type==='script_blocked';
  item.innerHTML=
    `<span class="ts">${ts(ev.ts)}</span>`+
    `<span>${sev}</span>`+
    `<span class="ev">${pill(ev.event_type||'?','pill-b')}</span>`+
    (ev.ip?`<span class="ip">${ev.ip}</span>`:'')+
    (ev.user?` <span style="color:var(--muted)">👤${ev.user}</span>`:'')+
    (ev.score!=null?` ${pill(ev.score,sc(ev.score))}`:'')+
    (ev.is_hosting?` ${pill('HOSTING','pill-y')}`:'')+
    (isScript?` ${pill('SCRIPT BLOCKED','pill-r')}`:'')+
    (isBan?` ${pill('BAN TRIGGERED','pill-r')}`:'')+
    (ev.country?` <span class="flag">${countryFlag(ev.country)}</span>`:'');
  feed.prepend(item);
  feedItems++;
  document.getElementById('feed-count').textContent=feedItems+' events';
  while(feed.children.length>300)feed.lastChild.remove();
}

function countryFlag(cc){
  if(!cc||cc.length!==2)return'';
  const pts=[...cc.toUpperCase()].map(c=>c.codePointAt(0)+127397);
  return String.fromCodePoint(...pts);
}
function refreshAll(){
  loadStats();loadSuspicious();loadChart();
  const active=document.querySelector('.page.active')?.id;
  if(active==='tab-bans')loadBans();
  if(active==='tab-events')loadEvents(evOffset);
  if(active==='tab-traffic')loadTraffic();
  if(active==='tab-scripts')loadScripts();
}
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;
  const tabs=['overview','traffic','bans','events','scripts'];
  const idx=parseInt(e.key)-1;
  if(idx>=0&&idx<tabs.length){
    const el=document.querySelectorAll('.tab')[idx];
    showTab(tabs[idx],el);
  }
});
refreshAll();
setInterval(refreshAll,10000);
connectSSE();
</script>
</body>
</html>"""
