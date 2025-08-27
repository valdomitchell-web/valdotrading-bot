# app.py
from __future__ import annotations

from flask import g
import math
import json
import os
import queue
import threading
import time
import requests
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_DOWN

from dotenv import load_dotenv
from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, session, stream_with_context, url_for
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from binance.client import Client
from binance.exceptions import BinanceAPIException
from werkzeug.security import generate_password_hash
from secrets import token_urlsafe
from threading import Event, Thread

# =========================
# Load env & Flask config
# =========================
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-fallback')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # e.g. postgresql://user:pass@localhost:5432/Thone
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

load_dotenv(override=False)  # don't override Render env vars with .env

def env_true(name, default="false"):
    return str(os.getenv(name, default)).strip().lower() in ("1", "true", "yes", "y", "on")

app.config["USE_US"]  = env_true("BINANCE_US")          # False => .com, True => .us
app.config["TESTNET"] = env_true("BINANCE_TESTNET")     # True => testnet

# --- Nonce-based CSP (drop-in) ---
def _csp_nonce():
    # one nonce per response
    if not hasattr(g, "csp_nonce"):
        g.csp_nonce = token_urlsafe(16)
    return g.csp_nonce

@app.context_processor
def inject_csp_nonce():
    # makes {{ csp_nonce }} available in Jinja templates
    return {"csp_nonce": _csp_nonce()}

@app.after_request
def set_csp(resp):
    nonce = _csp_nonce()
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "   # allow only self + this nonce
        "style-src 'self' 'unsafe-inline'; "     # keep simple; see note below
        "img-src 'self' data:; "
        "connect-src 'self'; "                   # fetch/SSE to your own origin
        "frame-ancestors 'none'; "
        "base-uri 'self'; object-src 'none'; form-action 'self'"
    )
    return resp
# --- end CSP ---


@app.get("/debug/env")
def debug_env():
    return jsonify(
        ok=True,
        tld=("us" if app.config["USE_US"] else "com"),
        testnet=app.config["TESTNET"],
        raw_BINANCE_US=os.getenv("BINANCE_US"),
        raw_BINANCE_TESTNET=os.getenv("BINANCE_TESTNET"),
    )

# optional helper used wherever you build the Binance client
def make_client():
    return Client(
        os.getenv("BINANCE_API_KEY"),
        os.getenv("BINANCE_API_SECRET"),
        tld=("us" if app.config["USE_US"] else "com"),
        testnet=app.config["TESTNET"],
    )
    
# Shared secret for TradingView (or any webhook caller)
TRADINGVIEW_WEBHOOK_SECRET = os.getenv("TRADINGVIEW_WEBHOOK_SECRET")

@app.route("/healthz")
def healthz():
    return "ok", 200

# =========================
# Feature flags & defaults
# =========================
ENABLE_AUTO_BRACKET = os.getenv("ENABLE_AUTO_BRACKET", "false").lower() == "true"
DEFAULT_TP_PCT = float(os.getenv("DEFAULT_TP_PCT", "0.01"))
DEFAULT_SL_PCT = float(os.getenv("DEFAULT_SL_PCT", "0.005"))
DEFAULT_SL_EXTRA = float(os.getenv("DEFAULT_SL_EXTRA", "0.001"))

# Risk config
RISK_COOLDOWN_SECONDS = int(os.getenv("RISK_COOLDOWN_SECONDS", "2"))
MAX_POSITION_USD = float(os.getenv("MAX_POSITION_USD", "0"))  # 0 = disabled
BASE_QUOTE = os.getenv("BASE_QUOTE", "USDT")

# Internal API key auth for Postman / signals
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY")

# Binance client helpers
BINANCE_API_KEY    = os.getenv("BINANCE_API_KEY")
BINANCE_API_SECRET = os.getenv("BINANCE_API_SECRET")
BINANCE_TLD        = os.getenv("BINANCE_TLD", "com")
IS_TESTNET         = os.getenv("BINANCE_IS_TESTNET", "false").lower() == "true"

if not BINANCE_API_KEY or not BINANCE_API_SECRET:
    raise RuntimeError("Missing BINANCE_API_KEY / BINANCE_API_SECRET in .env")

# Risk & rate-limit toggles
ENABLE_RISK_CHECK     = os.getenv("ENABLE_RISK_CHECK", "true").lower() == "true"
AUTO_ADJUST_SELL      = os.getenv("AUTO_ADJUST_SELL", "true").lower() == "true"
MAX_DAILY_SELL_USDT   = float(os.getenv("MAX_DAILY_SELL_USDT", "500"))
MIN_COOLDOWN_SEC      = int(os.getenv("MIN_COOLDOWN_SEC", "30"))
MIN_BASE_SELL         = float(os.getenv("MIN_BASE_SELL", "0.0"))

# Auto-sync flags
AUTO_SYNC_ENABLED_ENV = os.getenv("AUTO_SYNC_ENABLED", "false").lower() == "true"
AUTO_SYNC_INTERVAL_S  = int(os.getenv("AUTO_SYNC_INTERVAL_S", "8"))  # seconds

# Optional webhook for notifications (in addition to SSE)
NOTIFY_URL = os.getenv("NOTIFY_URL")  # e.g. https://hooks.example/abc123

# =========================
# Binance client
# =========================
def get_binance_client() -> Client:
    client = Client(BINANCE_API_KEY, BINANCE_API_SECRET, tld=BINANCE_TLD, testnet=IS_TESTNET)
    try:
        server_time = client.get_server_time()["serverTime"]  # ms
        local_ms = int(time.time() * 1000)
        client.TIME_OFFSET = server_time - local_ms
        print(f"[Binance] TIME_OFFSET set to {client.TIME_OFFSET} ms")
    except Exception as e:
        print("[Binance] Could not set TIME_OFFSET:", e)
    return client

def get_symbol_filters(client: Client, symbol: str):
    info = client.get_symbol_info(symbol.upper())
    if not info:
        raise ValueError(f"Symbol {symbol} not found")
    lot = next(f for f in info["filters"] if f["filterType"] == "LOT_SIZE")
    pricef = next(f for f in info["filters"] if f["filterType"] == "PRICE_FILTER")
    notional_filter = next(f for f in info["filters"] if f["filterType"] in ("NOTIONAL", "MIN_NOTIONAL"))
    return {
        "stepSize": Decimal(lot["stepSize"]),
        "minQty": Decimal(lot["minQty"]),
        "tickSize": Decimal(pricef["tickSize"]),
        "minNotional": Decimal(notional_filter.get("minNotional") or "0.0"),
    }

def get_binance_price(symbol: str) -> float | None:
    try:
        c = get_binance_client()
        p = c.get_symbol_ticker(symbol=symbol.upper())["price"]
        return float(p)
    except Exception:
        return None

def quantize_to_step(qty: Decimal, step: Decimal) -> Decimal:
    if step == 0:
        return qty
    return (qty // step) * step  # floor

def round_to_tick(price: Decimal, tick: Decimal) -> Decimal:
    if tick == 0:
        return price
    return (price // tick) * tick  # floor

def convert_quote_to_base(symbol: str, quote_amount: float) -> float:
    c = get_binance_client()
    f = get_symbol_filters(c, symbol)
    step = f["stepSize"]
    price = Decimal(c.get_symbol_ticker(symbol=symbol)["price"])
    base_raw = Decimal(str(quote_amount)) / price
    base_qty = (base_raw // step) * step
    return float(base_qty)

def max_sellable_base(symbol: str) -> tuple[Decimal, dict]:
    c = get_binance_client()
    f = get_symbol_filters(c, symbol)
    step = f["stepSize"]
    minQty = f["minQty"]
    minNotional = f["minNotional"]
    price = Decimal(c.get_symbol_ticker(symbol=symbol)["price"])
    base = symbol[:-4] if symbol.endswith("USDT") else symbol  # simple heuristic

    acct = c.get_account()
    free_base = Decimal("0")
    for b in acct["balances"]:
        if b["asset"] == base:
            free_base = Decimal(b["free"])
            break

    floored = (free_base // step) * step
    if floored < minQty:
        return Decimal("0"), {"reason": f"below minQty {minQty}"}
    notional = floored * price
    if notional < minNotional:
        return Decimal("0"), {"reason": f"below minNotional {minNotional}"}
    return floored, {"price": str(price), "free_base": str(free_base)}

def place_live_market_order(symbol: str, side: str, amount: float, use_quote=False):
    c = get_binance_client()
    side = side.upper()
    f = get_symbol_filters(c, symbol)
    price = Decimal(c.get_symbol_ticker(symbol=symbol)["price"])
    step = f["stepSize"]
    minQty = f["minQty"]
    minNotional = f["minNotional"]

    if use_quote:
        quote_qty = Decimal(str(amount))
        if quote_qty < minNotional:
            raise ValueError(f"quoteOrderQty too small; minNotional={minNotional}")
        return c.create_order(
            symbol=symbol, side=side, type=Client.ORDER_TYPE_MARKET,
            quoteOrderQty=str(quote_qty), recvWindow=10000
        )
    else:
        base_qty = quantize_to_step(Decimal(str(amount)), step)
        if base_qty < minQty:
            raise ValueError(f"Quantity below minQty={minQty}")
        notional = base_qty * price
        if notional < minNotional:
            raise ValueError(f"Notional {notional} below minNotional={minNotional}")
        return c.create_order(
            symbol=symbol, side=side, type=Client.ORDER_TYPE_MARKET,
            quantity=str(base_qty), recvWindow=10000
        )

# ================ Models ================
class Position(db.Model):
    __tablename__ = 'position'
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), index=True, nullable=False)
    side = db.Column(db.String(10), nullable=False)  # 'LONG' for spot buys
    qty = db.Column(db.Float, nullable=False, default=0.0)
    avg_price = db.Column(db.Float, nullable=False, default=0.0)
    opened_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    closed_at = db.Column(db.DateTime)
    status = db.Column(db.String(16), default='OPEN')  # OPEN / CLOSED
    realized_pnl = db.Column(db.Float, default=0.0)

class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    binance_id = db.Column(db.String(64))
    symbol = db.Column(db.String(20), index=True)
    side = db.Column(db.String(10))
    type = db.Column(db.String(32))
    status = db.Column(db.String(24), default='NEW')
    qty = db.Column(db.Float, default=0.0)
    price = db.Column(db.Float)
    stop_price = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    position_id = db.Column(db.Integer, db.ForeignKey('position.id'))

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)

class Trade(db.Model):
    __tablename__ = "trade"
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), nullable=False)
    side = db.Column(db.String(10), nullable=False)      # BUY / SELL
    amount = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    stop_loss = db.Column(db.Float, nullable=True)
    take_profit = db.Column(db.Float, nullable=True)
    is_open = db.Column(db.Boolean, default=True)
    source = db.Column(db.String(20), nullable=True)

class TrailingCfg(db.Model):
    __tablename__ = "trailing_cfg"
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), unique=True, index=True, nullable=False)
    active = db.Column(db.Boolean, default=False)
    armed = db.Column(db.Boolean, default=False)
    high_water = db.Column(db.Float, default=0.0)
    trail_pct = db.Column(db.Float, default=0.0)  # e.g. 0.01 = 1%
    arm_pct = db.Column(db.Float, default=0.0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Ensure all tables exist when the app boots under Gunicorn
with app.app_context():
    # Touch models so SQLAlchemy registers them
    _ = (User.__table__, Trade.__table__, Position.__table__)
    db.create_all()


# --- DB bootstrap (runs once on startup) ---

def _bootstrap_db_once():
    try:
        with app.app_context():
            # If your models live in other modules, import them here
            # from models import User, Trade, Position
            db.create_all()

            admin = User.query.filter_by(username='admin').first()
            if not admin:
                pwd = os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")
                db.session.add(User(username="admin",
                                    password_hash=generate_password_hash(pwd)))
                db.session.commit()
                app.logger.info("DB ready: admin user created")
            else:
                app.logger.info("DB ready: tables exist")
    except Exception as e:
        # very important: clear a failed transaction so future queries work
        db.session.rollback()
        app.logger.exception("DB bootstrap failed: %s", e)

_bootstrap_db_once()
# --- end bootstrap ---

# === Auto-trader config/helpers ===
# If you haven’t added this helper yet:
def env_true(name, default="false"):
    return str(os.getenv(name, default)).strip().lower() in ("1","true","yes","y","on")

USE_US   = env_true("BINANCE_US", "false")
TESTNET  = env_true("BINANCE_TESTNET", "false")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")  # set this in Render

AUTO_SYMBOLS = [s.strip().upper() for s in os.getenv("AUTO_SYMBOLS", "BTCUSDT").split(",") if s.strip()]
AUTO_INTERVAL = os.getenv("AUTO_INTERVAL", "5m")  # 1m/3m/5m/15m/1h…
AUTO_RISK_USDT = float(os.getenv("AUTO_RISK_USDT", "20"))  # USDT per trade
AUTO_COOLDOWN_SEC = int(os.getenv("AUTO_COOLDOWN_SEC", "300"))  # after any trade per symbol
EMA_FAST = int(os.getenv("EMA_FAST", "9"))
EMA_SLOW = int(os.getenv("EMA_SLOW", "21"))
RSI_LEN  = int(os.getenv("RSI_LEN", "14"))
BUY_RSI_MAX  = float(os.getenv("BUY_RSI_MAX", "60"))  # require momentum not overbought
SELL_RSI_MIN = float(os.getenv("SELL_RSI_MIN", "40"))  # avoid panic exits in chop

# single-runner state
_auto = {"thread": None, "stop": Event(), "enabled": False, "last": None, "err": None, "last_trade_ts": {}}

from binance.client import Client
from binance.exceptions import BinanceAPIException

def make_client():
    return Client(
        os.getenv("BINANCE_API_KEY"),
        os.getenv("BINANCE_API_SECRET"),
        tld=("us" if USE_US else "com"),
        testnet=TESTNET,
    )

def round_step(qty, step):
    d = Decimal(str(qty)); s = Decimal(str(step))
    return float((d // s) * s)

def symbol_filters(client, symbol):
    info = client.get_symbol_info(symbol)
    lot = next(f["stepSize"] for f in info["filters"] if f["filterType"] == "LOT_SIZE")
    min_notional = None
    for f in info["filters"]:
        if f["filterType"] in ("NOTIONAL", "MIN_NOTIONAL"):
            min_notional = float(f.get("minNotional") or f.get("minNotional", 0))
    return Decimal(str(lot)), (min_notional or 5.0)

def ema(series, n):
    k = 2/(n+1)
    out=[]; e=None
    for v in series:
        e = v if e is None else (v - e)*k + e
        out.append(e)
    return out

def rsi(closes, n=14):
    rsis=[None]*len(closes)
    if len(closes) < n+1: return rsis
    gains=0.0; losses=0.0
    for i in range(1, n+1):
        ch = closes[i]-closes[i-1]
        gains += max(ch, 0); losses += max(-ch, 0)
    avg_g = gains/n; avg_l = losses/n
    rsis[n] = 100.0 if avg_l==0 else 100 - 100/(1 + (avg_g/avg_l))
    for i in range(n+1, len(closes)):
        ch = closes[i]-closes[i-1]
        up = max(ch, 0.0); dn = max(-ch, 0.0)
        avg_g = (avg_g*(n-1) + up)/n
        avg_l = (avg_l*(n-1) + dn)/n
        rsis[i] = 100.0 if avg_l==0 else 100 - 100/(1 + (avg_g/avg_l))
    return rsis

def last_close_and_indicators(klines):
    closes = [float(k[4]) for k in klines]
    efast = ema(closes, EMA_FAST)
    eslow = ema(closes, EMA_SLOW)
    r = rsi(closes, RSI_LEN)
    return closes, efast, eslow, r

def crossed_up(a_prev, a_now, b_prev, b_now):   # a crosses above b
    return a_prev is not None and b_prev is not None and a_prev <= b_prev and a_now > b_now

def crossed_down(a_prev, a_now, b_prev, b_now): # a crosses below b
    return a_prev is not None and b_prev is not None and a_prev >= b_prev and a_now < b_now

def can_trade(symbol):
    last = _auto["last_trade_ts"].get(symbol, 0)
    return (time.time() - last) >= AUTO_COOLDOWN_SEC

def record_trade_ts(symbol):
    _auto["last_trade_ts"][symbol] = time.time()

def auto_loop():
    client = make_client()
    app.logger.info("[AUTO] started | symbols=%s interval=%s risk=%.2f USDT", AUTO_SYMBOLS, AUTO_INTERVAL, AUTO_RISK_USDT)
    try:
        # cache filters
        flt = {s: symbol_filters(client, s) for s in AUTO_SYMBOLS}
    except Exception as e:
        _auto["err"] = f"filters: {e}"
        app.logger.exception("[AUTO] symbol_filters error")
        return

    while not _auto["stop"].is_set():
        _auto["last"] = datetime.utcnow().isoformat()
        for sym in AUTO_SYMBOLS:
            try:
                if not can_trade(sym):
                    continue

                kl = client.get_klines(symbol=sym, interval=AUTO_INTERVAL, limit=120)
                if not kl or len(kl) < max(EMA_SLOW, RSI_LEN) + 2:
                    continue

                closes, ef, es, r = last_close_and_indicators(kl)
                p1, p2 = ef[-2], ef[-1]
                q1, q2 = es[-2], es[-1]
                rsi_now = r[-1] if r[-1] is not None else 50.0

                bull_x = crossed_up(p1, p2, q1, q2)
                bear_x = crossed_down(p1, p2, q1, q2)

                # balances
                acct = client.get_account()
                bals = {b["asset"]: float(b["free"]) for b in acct["balances"]}
                base = sym.replace("USDT","")
                base_bal = bals.get(base, 0.0)
                price = float(client.get_symbol_ticker(symbol=sym)["price"])
                lot_step, min_notional = flt[sym]

                # BUY: EMA fast cross up, RSI below cap, and not already holding significant base
                if bull_x and rsi_now <= BUY_RSI_MAX and base_bal * price < min_notional:
                    qty_raw = AUTO_RISK_USDT / price
                    qty = round_step(qty_raw, lot_step)
                    if qty * price >= min_notional and qty > 0:
                        o = client.create_order(symbol=sym, side="BUY", type="MARKET", quantity=qty)
                        record_trade_ts(sym)
                        filled_qty = sum(float(f["qty"]) for f in o.get("fills", [])) or qty
                        avg_price = (
                            sum(float(f["price"])*float(f["qty"]) for f in o.get("fills", [])) / filled_qty
                            if o.get("fills") else price
                        )
                        # persist to DB for dashboard
                        try:
                            db.session.add(Trade(symbol=sym, side="BUY", amount=filled_qty, price=avg_price,
                                                 timestamp=datetime.utcnow(), is_open=False, source="auto"))
                            db.session.commit()
                        except Exception:
                            db.session.rollback()
                        app.logger.info("[AUTO] BUY %s qty=%.8f @ %.2f | rsi=%.1f", sym, filled_qty, avg_price, rsi_now)

                # SELL: EMA fast cross down, RSI above floor, and we hold base
                elif bear_x and rsi_now >= SELL_RSI_MIN and base_bal * price >= min_notional:
                    qty = round_step(base_bal, lot_step)
                    if qty * price >= min_notional and qty > 0:
                        o = client.create_order(symbol=sym, side="SELL", type="MARKET", quantity=qty)
                        record_trade_ts(sym)
                        filled_qty = sum(float(f["qty"]) for f in o.get("fills", [])) or qty
                        avg_price = (
                            sum(float(f["price"])*float(f["qty"]) for f in o.get("fills", [])) / filled_qty
                            if o.get("fills") else price
                        )
                        try:
                            db.session.add(Trade(symbol=sym, side="SELL", amount=filled_qty, price=avg_price,
                                                 timestamp=datetime.utcnow(), is_open=False, source="auto"))
                            db.session.commit()
                        except Exception:
                            db.session.rollback()
                        app.logger.info("[AUTO] SELL %s qty=%.8f @ %.2f | rsi=%.1f", sym, filled_qty, avg_price, rsi_now)

            except BinanceAPIException as e:
                _auto["err"] = str(e)
                app.logger.warning("[AUTO] %s error: %s", sym, e)
            except Exception as e:
                _auto["err"] = str(e)
                app.logger.exception("[AUTO] %s exception", sym)

        # small sleep (don’t hammer API). 30s is safe for 1m+ intervals.
        _auto["stop"].wait(30)

    app.logger.info("[AUTO] stopped")

def require_admin():
    # allow if session login exists OR header token matches ADMIN_TOKEN
    if session.get("logged_in") or session.get("user_id"):
        return True
    token = request.headers.get("X-Admin-Token")
    return ADMIN_TOKEN and token == ADMIN_TOKEN

@app.get("/auto/status")
def auto_status():
    return jsonify(ok=True, running=(_auto["thread"] and _auto["thread"].is_alive()),
                   enabled=_auto["enabled"], last=_auto["last"], err=_auto["err"])

@app.post("/auto/start")
def auto_start():
    if not require_admin():
        return jsonify(ok=False, error="auth"), 401
    if _auto["thread"] and _auto["thread"].is_alive():
        _auto["enabled"] = True
        return jsonify(ok=True, running=True)
    _auto["stop"].clear()
    _auto["enabled"] = True
    th = Thread(target=auto_loop, daemon=True)
    _auto["thread"] = th
    th.start()
    return jsonify(ok=True, running=True)

@app.post("/auto/stop")
def auto_stop():
    if not require_admin():
        return jsonify(ok=False, error="auth"), 401
    _auto["enabled"] = False
    _auto["stop"].set()
    return jsonify(ok=True)

@app.post("/debug/test_buy")
def debug_test_buy():
    if not require_admin():
        return jsonify(ok=False, error="auth"), 401
    if not TESTNET:
        return jsonify(ok=False, error="not testnet"), 400

    data = request.get_json(silent=True) or {}
    sym  = (data.get("symbol") or "BTCUSDT").upper()
    usdt = float(data.get("usdt") or 20)

    c = make_client()
    price = float(c.get_symbol_ticker(symbol=sym)["price"])
    lot_step, min_notional = symbol_filters(c, sym)
    qty = round_step(usdt / price, lot_step)

    if qty <= 0 or qty * price < min_notional:
        return jsonify(ok=False, error="qty too small"), 400

    try:
        o = c.create_order(symbol=sym, side="BUY", type="MARKET", quantity=qty)
        return jsonify(ok=True, status=o.get("status"), qty=qty)
    except BinanceAPIException as e:
        return jsonify(ok=False, error=str(e)), 400

# ============== Auth helpers ==============
def is_authorized(req) -> bool:
    # Existing API key path
    header_key = req.headers.get("X-API-KEY")
    if INTERNAL_API_KEY and header_key and header_key == INTERNAL_API_KEY:
        return True

    # NEW: accept TradingView secret via header, JSON body, or URL query
    if TRADINGVIEW_WEBHOOK_SECRET:
        if req.headers.get("X-Webhook-Secret") == TRADINGVIEW_WEBHOOK_SECRET:
            return True
        body = req.get_json(silent=True) or {}
        if body.get("secret") == TRADINGVIEW_WEBHOOK_SECRET:
            return True
        if req.args.get("secret") == TRADINGVIEW_WEBHOOK_SECRET:
            return True

    # Fallback: logged-in session for the dashboard
    return 'user_id' in session

def infer_source_from_request(req, default='manual'):
    body = req.get_json(silent=True) or {}
    # If caller explicitly sets source, honor it
    s = (body.get('source') or '').strip()
    if s:
        return s
    # If our shared secret is present (header, body, or query), mark as webhook
    if TRADINGVIEW_WEBHOOK_SECRET and (
        req.headers.get("X-Webhook-Secret") == TRADINGVIEW_WEBHOOK_SECRET
        or body.get("secret") == TRADINGVIEW_WEBHOOK_SECRET
        or req.args.get("secret") == TRADINGVIEW_WEBHOOK_SECRET
    ):
        return 'webhook'
    return default


# ============== Risk / guardrails ==============
_last_signal_at: dict[str, float] = {}  # symbol -> epoch seconds

def mark_signal(symbol: str):
    _last_signal_at[symbol.upper()] = time.time()

def since_last_signal(symbol: str) -> float:
    t = _last_signal_at.get(symbol.upper())
    return 1e9 if t is None else (time.time() - t)

def account_free_balances(client: Client) -> dict[str, float]:
    acct = client.get_account()
    return {b['asset']: float(b['free']) for b in acct['balances']}

def open_exposure_usd(symbol: str) -> float:
    sym = symbol.upper()
    pos = Position.query.filter_by(symbol=sym, status='OPEN').first()
    if not pos:
        return 0.0
    price = get_binance_price(sym) or pos.avg_price or 0.0
    return float(pos.qty or 0.0) * float(price)

def guess_base_asset(symbol: str) -> str:
    if symbol.endswith('USDT'):
        return symbol[:-4]
    return symbol

def get_free_balance(asset: str) -> float:
    acct = get_binance_client().get_account()
    for b in acct.get('balances', []):
        if b.get('asset') == asset:
            try:
                return float(b.get('free') or 0.0)
            except Exception:
                return 0.0
    return 0.0

def todays_sell_notional_usdt(symbol: str) -> float:
    start_of_day = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    rows = (Trade.query
            .filter(Trade.symbol == symbol.upper(),
                    Trade.side == 'SELL',
                    Trade.timestamp >= start_of_day)
            .all())
    return sum((r.amount or 0.0) * (r.price or 0.0) for r in rows)

def pre_trade_check(symbol: str, side: str, use_quote: bool, amount: float) -> tuple[bool,str]:
    sym = symbol.upper()

    # cooldown per symbol
    if since_last_signal(sym) < RISK_COOLDOWN_SECONDS:
        return False, f"cooldown {RISK_COOLDOWN_SECONDS}s not elapsed"

    c = get_binance_client()
    f = get_symbol_filters(c, sym)
    step = f["stepSize"]
    min_notional = f["minNotional"]
    price = Decimal(c.get_symbol_ticker(symbol=sym)["price"])
    bals = account_free_balances(c)

    base_asset = sym.replace(BASE_QUOTE, "") if sym.endswith(BASE_QUOTE) else sym
    quote_asset = BASE_QUOTE

    side = side.upper()
    if side == 'BUY':
        if use_quote:
            quote_amt = Decimal(str(amount))
            if quote_amt < min_notional:
                return False, f"quote amount {quote_amt} < minNotional {min_notional}"
            free_quote = Decimal(str(bals.get(quote_asset, 0.0)))
            if quote_amt > free_quote:
                return False, f"insufficient {quote_asset} balance {free_quote}"
            est_base = quantize_to_step(quote_amt / price, step)
            if est_base <= 0:
                return False, "resulting base qty too small after step"
        else:
            base_qty = quantize_to_step(Decimal(str(amount)), step)
            if base_qty <= 0:
                return False, "base quantity too small after step"
            notional = base_qty * price
            if notional < min_notional:
                return False, f"notional {notional} < minNotional {min_notional}"
            free_quote = Decimal(str(bals.get(quote_asset, 0.0)))
            if notional > free_quote:
                return False, f"insufficient {quote_asset} balance {free_quote}"
        # exposure cap
        if MAX_POSITION_USD > 0:
            current_expo = open_exposure_usd(sym)
            add_expo = float(Decimal(str(amount)) if use_quote else (Decimal(str(amount)) * price))
            if current_expo + add_expo > MAX_POSITION_USD:
                return False, f"exceeds MAX_POSITION_USD {MAX_POSITION_USD}"
        return True, "ok"

    if side == 'SELL':
        base_qty = quantize_to_step(Decimal(str(amount)), step)
        if base_qty <= 0:
            return False, "base quantity too small after step"
        free_base = Decimal(str(bals.get(base_asset, 0.0)))
        if base_qty > free_base:
            return False, f"insufficient {base_asset} balance {free_base}"
        if base_qty < Decimal(str(MIN_BASE_SELL)):
            return False, f"below MIN_BASE_SELL {MIN_BASE_SELL}"
        # daily cap
        px = float(price)
        today = todays_sell_notional_usdt(sym)
        planned = today + float(base_qty) * px
        if planned > MAX_DAILY_SELL_USDT:
            return False, f"daily sell cap exceeded: planned {planned:.2f} > {MAX_DAILY_SELL_USDT}"
        return True, "ok"

    return False, "invalid side"

def get_or_create_trail(symbol: str) -> "TrailingCfg":
    row = TrailingCfg.query.filter_by(symbol=symbol.upper()).first()
    if not row:
        row = TrailingCfg(symbol=symbol.upper(), active=False)
        db.session.add(row)
        db.session.commit()
    return row

def set_trailing(symbol: str, active: bool, trail_pct: float | None = None, arm_pct: float | None = None):
    row = get_or_create_trail(symbol)
    row.active = active
    if trail_pct is not None: row.trail_pct = float(trail_pct)
    if arm_pct is not None: row.arm_pct = float(arm_pct)
    if not active:
        row.armed = False
        row.high_water = 0.0
    db.session.commit()
    return row

# ============== OCO helpers ==============
def compute_bracket_prices(fill_price: float,
                           tp_pct: float | None,
                           sl_pct: float | None,
                           sl_extra: float = 0.001):
    tp_price = tp_stop = sl_price = sl_stop = None
    if tp_pct is not None:
        tp_price = fill_price * (1 + tp_pct)
        tp_stop  = tp_price
    if sl_pct is not None:
        sl_stop  = fill_price * (1 - sl_pct)
        sl_price = sl_stop * (1 - (sl_extra or 0.0))
    return tp_price, tp_stop, sl_price, sl_stop

def place_oco_order(symbol, side, quantity,
                    tp_price=None, tp_stop=None,
                    sl_price=None, sl_stop=None,
                    tp_type='TAKE_PROFIT_LIMIT',
                    sl_type='STOP_LOSS_LIMIT',
                    tif='GTC'):
    c = get_binance_client()
    assert side in ('BUY', 'SELL')
    qty_str = format(quantity, 'f')
    if tp_price is not None and tp_stop is None: tp_stop = tp_price
    if sl_price is not None and sl_stop is None: sl_stop = sl_price
    params = {
        'symbol': symbol, 'side': side, 'quantity': qty_str,
        'aboveType': tp_type, 'belowType': sl_type,
    }
    if tp_type in ('LIMIT_MAKER', 'TAKE_PROFIT_LIMIT'):
        if tp_price is None: raise ValueError("abovePrice required")
        params['abovePrice'] = str(tp_price)
    if tp_type in ('TAKE_PROFIT', 'TAKE_PROFIT_LIMIT', 'STOP_LOSS', 'STOP_LOSS_LIMIT'):
        if tp_stop is None: raise ValueError("aboveStopPrice required")
        params['aboveStopPrice'] = str(tp_stop)
    if tp_type in ('TAKE_PROFIT_LIMIT', 'STOP_LOSS_LIMIT'):
        params['aboveTimeInForce'] = tif
    if sl_type in ('LIMIT_MAKER', 'TAKE_PROFIT_LIMIT', 'STOP_LOSS_LIMIT'):
        if sl_price is None: raise ValueError("belowPrice required")
        params['belowPrice'] = str(sl_price)
    if sl_type in ('TAKE_PROFIT', 'TAKE_PROFIT_LIMIT', 'STOP_LOSS', 'STOP_LOSS_LIMIT'):
        if sl_stop is None: raise ValueError("belowStopPrice required")
        params['belowStopPrice'] = str(sl_stop)
    if sl_type in ('TAKE_PROFIT_LIMIT', 'STOP_LOSS_LIMIT'):
        params['belowTimeInForce'] = tif
    return c._request_api('post', 'orderList/oco', True, data=params)

def place_oco_sell(symbol: str, qty, tp_price, sl_trigger, sl_limit):
    c = get_binance_client()
    return c.create_oco_order(
        symbol=symbol,
        side=Client.SIDE_SELL,
        quantity=str(qty),
        price=str(tp_price),
        stopPrice=str(sl_trigger),
        stopLimitPrice=str(sl_limit),
        stopLimitTimeInForce="GTC",
        recvWindow=10000
    )

# ============== Position / Order helpers ==============
def weighted_from_fills(fills):
    if not fills:
        return None, None
    try:
        total_qty = sum(float(f['qty']) for f in fills)
        if total_qty <= 0:
            return 0.0, None
        total_val = sum(float(f['qty']) * float(f['price']) for f in fills)
        return total_qty, (total_val / total_qty)
    except Exception:
        return None, None

def ensure_position_on_buy(symbol: str, filled_qty: float, fill_price: float):
    pos = Position.query.filter_by(symbol=symbol, status='OPEN').first()
    if pos:
        prev_qty = float(pos.qty or 0.0)
        new_qty  = prev_qty + float(filled_qty or 0.0)
        if new_qty > 0:
            pos.avg_price = ((pos.avg_price or 0.0) * prev_qty + float(fill_price or 0.0) * float(filled_qty or 0.0)) / new_qty
            pos.qty = new_qty
    else:
        pos = Position(symbol=symbol, side='LONG', qty=float(filled_qty or 0.0), avg_price=float(fill_price or 0.0), status='OPEN')
        db.session.add(pos)
    db.session.commit()
    return pos

def record_order_row(order: dict, side: str, symbol: str, qty: float, price: float, position_id: int | None):
    try:
        binance_id = str(order.get('orderId') or order.get('clientOrderId') or '')
        otype      = order.get('type') or 'UNKNOWN'
        status     = order.get('status') or 'NEW'
        row = Order.query.filter_by(binance_id=binance_id).first()
        if not row:
            row = Order(
                binance_id=binance_id, symbol=symbol, side=side, type=otype,
                status=status, qty=float(qty or 0.0), price=float(price or 0.0),
                position_id=position_id
            )
            db.session.add(row)
        else:
            row.status = status
            row.qty    = float(qty or row.qty or 0.0)
            row.price  = float(price or row.price or 0.0)
        db.session.commit()
    except Exception:
        db.session.rollback()

def close_position_if_filled_sells(symbol: str):
    pos = Position.query.filter_by(symbol=symbol, status='OPEN').first()
    if not pos:
        return
    sell_orders = Order.query.filter_by(position_id=pos.id, side='SELL', status='FILLED').all()
    closed_qty  = sum(float(o.qty or 0.0) for o in sell_orders)
    if closed_qty + 1e-12 >= float(pos.qty or 0.0) and float(pos.qty or 0.0) > 0:
        total_val = sum(float(o.qty or 0.0) * float(o.price or 0.0) for o in sell_orders)
        avg_exit  = (total_val / closed_qty) if closed_qty > 0 else pos.avg_price
        pnl       = (avg_exit - float(pos.avg_price or 0.0)) * float(pos.qty or 0.0)
        pos.realized_pnl = float(pnl)
        pos.status       = 'CLOSED'
        pos.closed_at    = datetime.utcnow()
        db.session.commit()
        try:
            opens = Trade.query.filter_by(symbol=symbol, is_open=True).all()
            for t in opens:
                t.is_open = False
            db.session.commit()
        except Exception:
            db.session.rollback()

# ============== SSE (Realtime UI) ==============
class EventBroker:
    def __init__(self):
        self._subscribers = set()

    def subscribe(self) -> queue.Queue:
        q = queue.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        try:
            self._subscribers.remove(q)
        except KeyError:
            pass

    def publish(self, event_name: str, data: dict):
        dead = []
        payload = {"event": event_name, "data": data}
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

broker = EventBroker()

def sse_format(event_name: str, data: dict) -> str:
    return f"event: {event_name}\ndata: {json.dumps(data)}\n\n"

def notify_event(event_name: str, data: dict | None = None):
    """
    Pushes to SSE subscribers AND (optionally) POSTs to NOTIFY_URL if set.
    """
    payload = data or {}
    # SSE
    try:
        broker.publish(event_name, payload)
    except Exception:
        pass
    # Optional webhook
    if NOTIFY_URL:
        try:
            requests.post(
                NOTIFY_URL,
                json={"event": event_name, "time": datetime.utcnow().isoformat() + "Z", **payload},
                timeout=5
            )
        except Exception:
            pass

@app.route('/events')
def events():
    q = broker.subscribe()

    @stream_with_context
    def gen():
        yield sse_format("hello", {"ok": True})
        last_beat = time.time()
        try:
            while True:
                if time.time() - last_beat > 15:
                    yield sse_format("heartbeat", {"ts": time.time()})
                    last_beat = time.time()
                try:
                    item = q.get(timeout=1.0)
                except queue.Empty:
                    continue
                yield sse_format(item["event"], item["data"])
        except GeneratorExit:
            pass
        finally:
            broker.unsubscribe(q)

    return Response(gen(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })

# ============== Sync (open orders / positions) ==============
LAST_SYNC_AT   = None
LAST_SYNC_OK   = None
LAST_SYNC_ERR  = None
_AUTO_SYNC_ENABLED   = AUTO_SYNC_ENABLED_ENV
_SYNC_THREAD_STARTED = False

def sync_open_core(symbol: str | None = None) -> dict:
    c = get_binance_client()
    updated = 0
    closed_positions = 0

    # 1) Live open orders (optionally per-symbol)
    try:
        open_orders = c.get_open_orders(symbol=symbol) if symbol else c.get_open_orders()
    except Exception:
        open_orders = []

    for o in open_orders:
        try:
            binance_id = str(o.get('orderId') or o.get('clientOrderId') or '')
            row = Order.query.filter_by(binance_id=binance_id).first()
            if not row:
                row = Order(
                    binance_id=binance_id,
                    symbol=o.get('symbol', ''),
                    side=o.get('side', 'UNKNOWN'),
                    type=o.get('type', 'UNKNOWN'),
                    status=o.get('status', 'NEW'),
                    qty=float(o.get('origQty') or 0.0),
                    price=float(o.get('price') or 0.0),
                    stop_price=float(o.get('stopPrice') or 0.0),
                )
                db.session.add(row)
            else:
                row.status = o.get('status', row.status)
                row.price = float(o.get('price') or row.price or 0.0)
                row.stop_price = float(o.get('stopPrice') or row.stop_price or 0.0)
            updated += 1
        except Exception:
            db.session.rollback()
    db.session.commit()

    # tell UI
    try:
        notify_event("open_orders_refreshed", {
            "count": len(open_orders),
            "symbols": list({o.get('symbol') for o in open_orders if o.get('symbol')})
        })
    except Exception:
        pass

    # 2) Symbols to refresh from recent orders
    if symbol:
        symbols_to_refresh = [symbol.upper()]
    else:
        pos_syms = [p.symbol for p in Position.query.filter_by(status='OPEN').all()]
        oo_syms = list({o.get('symbol') for o in open_orders if o.get('symbol')})
        symbols_to_refresh = list({*(s.upper() for s in pos_syms), *oo_syms})

    for sym in symbols_to_refresh:
        try:
            recents = c.get_all_orders(symbol=sym, limit=50)
        except Exception:
            recents = []
        for r in recents:
            try:
                bid = str(r.get('orderId') or r.get('clientOrderId') or '')
                row = Order.query.filter_by(binance_id=bid).first()
                if row:
                    row.status = r.get('status', row.status)
                    if r.get('price'):
                        row.price = float(r['price'])
                    if r.get('stopPrice'):
                        row.stop_price = float(r['stopPrice'])
                    if r.get('origQty'):
                        row.qty = float(r['origQty'])
            except Exception:
                db.session.rollback()
        db.session.commit()

        # 3) Auto-close if filled SELLs cover the open position
        pos = Position.query.filter_by(symbol=sym, status='OPEN').first()
        if pos:
            sell_filled = Order.query.filter_by(symbol=sym, side='SELL', status='FILLED').all()
            total_sell_qty = sum(float(o.qty or 0.0) for o in sell_filled)

            if total_sell_qty + 1e-12 >= float(pos.qty or 0.0) and float(pos.qty or 0.0) > 0:
                total_val = sum(float(o.qty or 0.0) * float(o.price or 0.0) for o in sell_filled)
                avg_exit = (total_val / total_sell_qty) if total_sell_qty > 0 else pos.avg_price
                pnl = (avg_exit - float(pos.avg_price or 0.0)) * float(pos.qty or 0.0)

                pos.realized_pnl = float(pnl)
                pos.status = 'CLOSED'
                pos.closed_at = datetime.utcnow()
                db.session.commit()
                closed_positions += 1

                try:
                    for t in Trade.query.filter_by(symbol=sym, is_open=True).all():
                        t.is_open = False
                    db.session.commit()
                except Exception:
                    db.session.rollback()

                try:
                    notify_event("position_auto_closed", {
                        "symbol": sym,
                        "qty": float(pos.qty or 0.0),
                        "avg_entry": float(pos.avg_price or 0.0),
                        "realized_pnl": float(pnl)
                    })
                except Exception:
                    pass

    return {
        "ok": True,
        "open_orders_seen": len(open_orders),
        "symbols_refreshed": symbols_to_refresh,
        "rows_updated": updated,
        "positions_closed": closed_positions,
    }

def _auto_sync_loop():
    global LAST_SYNC_AT, LAST_SYNC_OK, LAST_SYNC_ERR
    with app.app_context():
        while True:
            try:
                if _AUTO_SYNC_ENABLED:
                    sync_open_core()
                    LAST_SYNC_AT = datetime.utcnow()
                    LAST_SYNC_OK = True
                    LAST_SYNC_ERR = None
                # else idle
            except Exception as e:
                LAST_SYNC_AT = datetime.utcnow()
                LAST_SYNC_OK = False
                LAST_SYNC_ERR = str(e)
            time.sleep(AUTO_SYNC_INTERVAL_S)

def start_auto_sync_thread_once():
    global _SYNC_THREAD_STARTED
    if _SYNC_THREAD_STARTED:
        return
    t = threading.Thread(target=_auto_sync_loop, daemon=True)
    t.start()
    _SYNC_THREAD_STARTED = True

# Start background (honors _AUTO_SYNC_ENABLED flag)
start_auto_sync_thread_once()

def _trailing_manager_loop():
    """
    Poll open positions and apply trailing logic:
      - If active and NOT armed: arm when price >= avg_price*(1+arm_pct). Start tracking high_water.
      - If armed: update high_water when price makes new highs.
                 exit when price drops by trail_pct from high_water.
    """
    with app.app_context():
        while True:
            try:
                # scan open positions
                open_positions = Position.query.filter_by(status='OPEN').all()
                if not open_positions:
                    time.sleep(3)
                    continue

                for pos in open_positions:
                    sym = pos.symbol.upper()
                    cfg = TrailingCfg.query.filter_by(symbol=sym, active=True).first()
                    if not cfg:
                        continue  # nothing to do

                    price = get_binance_price(sym)
                    if not price or price <= 0:
                        continue

                    entry = float(pos.avg_price or 0.0)
                    if entry <= 0:
                        continue

                    # arm threshold
                    arm_trigger = entry * (1.0 + float(cfg.arm_pct or 0.0))
                    # trailing trigger from high watermark
                    drop_trigger = (1.0 - float(cfg.trail_pct or 0.0))

                    # not armed yet -> arm when price >= arm_trigger
                    if not cfg.armed:
                        if price >= arm_trigger:
                            cfg.armed = True
                            cfg.high_water = price
                            db.session.commit()
                            notify_event("trailing_armed", {"symbol": sym, "armed_at": price})
                        continue

                    # armed: bump high water on new highs
                    if price > (cfg.high_water or 0.0):
                        cfg.high_water = price
                        db.session.commit()
                        continue

                    # armed: check trailing drop from high_water
                    if cfg.high_water and price <= cfg.high_water * drop_trigger:
                        # exit 100% market SELL (respect step)
                        try:
                            filters = get_symbol_filters(get_binance_client(), sym)
                            step = filters["stepSize"]
                            qty = Decimal(str(pos.qty or 0.0))
                            sell_qty = quantize_to_step(qty, step)
                            if sell_qty > 0:
                                # risk check
                                ok, reason = pre_trade_check(sym, 'SELL', False, float(sell_qty))
                                if not ok:
                                    notify_event("trailing_blocked", {"symbol": sym, "reason": reason})
                                else:
                                    c = get_binance_client()
                                    order = c.create_order(
                                        symbol=sym,
                                        side=Client.SIDE_SELL,
                                        type=Client.ORDER_TYPE_MARKET,
                                        quantity=str(sell_qty),
                                        recvWindow=10000
                                    )
                                    # log best-effort trade
                                    try:
                                        db.session.add(Trade(symbol=sym, side='SELL', amount=float(sell_qty),
                                                             price=float(price), timestamp=datetime.utcnow(),
                                                             is_open=False))
                                        db.session.commit()
                                    except Exception:
                                        db.session.rollback()

                                    # mark config off and cleanup
                                    cfg.active = False
                                    cfg.armed = False
                                    cfg.high_water = 0.0
                                    db.session.commit()

                                    # close position (uses your existing logic) + sync
                                    close_position_if_filled_sells(sym)
                                    try:
                                        sync_open_core(symbol=sym)
                                    except Exception:
                                        pass

                                    notify_event("trailing_exit", {"symbol": sym, "qty": str(sell_qty), "price": str(price)})
                        except Exception as e:
                            db.session.rollback()
                            notify_event("trailing_error", {"symbol": sym, "error": str(e)})
                time.sleep(3)
            except Exception as e:
                # keep the loop alive
                print("[trailing_manager] error:", e)
                time.sleep(3)

# start trailing loop once
threading.Thread(target=_trailing_manager_loop, daemon=True).start()

# ============== Diagnostics / utils routes ==============
@app.route('/binance_diag')
def binance_diag():
    try:
        c = get_binance_client()
        ping = c.ping()
        time_srv = c.get_server_time()
        acct = c.get_account()
        btcusdt = c.get_symbol_info("BTCUSDT")
        return jsonify({
            "ok": True,
            "ping": ping,
            "serverTime": time_srv,
            "accountKeys": {"canTrade": acct.get("canTrade"), "permissions": acct.get("permissions")},
            "BTCUSDT_found": btcusdt is not None,
            "is_testnet": IS_TESTNET,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/precheck', methods=['POST'])
def precheck():
    data = request.get_json(silent=True) or {}
    symbol = (data.get('symbol') or '').upper()
    amount = data.get('amount')
    use_quote = bool(data.get('use_quote', False))
    if not symbol or amount is None:
        return jsonify({"ok": False, "error": "symbol and amount required"}), 400
    try:
        ok, reason = pre_trade_check(symbol, 'BUY', use_quote, float(amount))
        return jsonify({"ok": ok, "reason": reason})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/precheck2', methods=['POST'])
def precheck2():
    if not is_authorized(request):
        return jsonify({'error':'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    symbol    = (data.get('symbol') or '').upper()
    side      = (data.get('side') or '').upper()
    amount    = data.get('amount')
    use_quote = bool(data.get('use_quote', False))
    if not symbol or side not in ('BUY','SELL') or amount is None:
        return jsonify({"ok": False, "error": "symbol, side, amount required"}), 400
    try:
        ok, reason = pre_trade_check(symbol, side, use_quote, float(amount))
        resp = {"ok": ok, "reason": reason}
        if side == 'SELL':
            allowed, meta = max_sellable_base(symbol)
            resp.update({
                "max_sellable_after_filters": str(allowed),
                **({k:v for k,v in meta.items()} if isinstance(meta, dict) else {})
            })
        return jsonify(resp)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/balance')
def balance():
    try:
        c = get_binance_client()
        acct = c.get_account()
        bals = {}
        for b in acct['balances']:
            free = Decimal(b['free'])
            if free > 0:
                pretty = free.quantize(Decimal('0.00000001'), rounding=ROUND_DOWN)
                bals[b['asset']] = {
                    "exact": str(free.normalize()),
                    "pretty": str(pretty)
                }
        return jsonify({"ok": True, "balances": bals})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/sync_open', methods=['POST'])
def sync_open_post():
    if not is_authorized(request):
        return jsonify({'error': 'Unauthorized'}), 401
    payload = request.get_json(silent=True) or {}
    symbol = (payload.get('symbol') or '').upper() or None
    try:
        res = sync_open_core(symbol=symbol)
        global LAST_SYNC_AT, LAST_SYNC_OK, LAST_SYNC_ERR
        LAST_SYNC_AT = datetime.utcnow()
        LAST_SYNC_OK = True
        LAST_SYNC_ERR = None
        return jsonify(res)
    except Exception as e:
        LAST_SYNC_AT = datetime.utcnow()
        LAST_SYNC_OK = False
        LAST_SYNC_ERR = str(e)
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/sync_open', methods=['GET'])
def sync_open_get():
    return redirect(url_for('dashboard'))

@app.route('/sync_toggle', methods=['POST'])
def sync_toggle():
    if not is_authorized(request):
        return jsonify({'error': 'Unauthorized'}), 401
    payload = request.get_json(silent=True) or {}
    enabled = bool(payload.get('enabled', False))
    global _AUTO_SYNC_ENABLED
    _AUTO_SYNC_ENABLED = enabled
    start_auto_sync_thread_once()
    return jsonify({"ok": True, "enabled": _AUTO_SYNC_ENABLED, "interval_s": AUTO_SYNC_INTERVAL_S})

@app.route('/sync_status')
def sync_status():
    return jsonify({
        "enabled": _AUTO_SYNC_ENABLED,
        "last_ok": LAST_SYNC_OK,
        "last_at": LAST_SYNC_AT.isoformat() if LAST_SYNC_AT else None,
        "last_error": LAST_SYNC_ERR,
        "interval_s": AUTO_SYNC_INTERVAL_S
    })

# ---- Single, unified trailing status route (remove duplicates) ----
@app.route('/trail/status', methods=['GET'])
def trail_status():
    if not is_authorized(request):
        return jsonify({'error': 'Unauthorized'}), 401

    rows = TrailingCfg.query.all()
    out = []
    for r in rows:
        stop_now = None
        try:
            if r.armed and (r.high_water or 0) > 0 and (r.trail_pct or 0) > 0:
                stop_now = float(r.high_water) * (1.0 - float(r.trail_pct))
        except Exception:
            stop_now = None

        out.append({
            "symbol": r.symbol,
            "active": bool(r.active),
            "armed": bool(r.armed),
            "high_water": float(r.high_water or 0.0),
            "trail_pct": float(r.trail_pct or 0.0),
            "arm_pct": float(r.arm_pct or 0.0),
            "stop_now": (None if stop_now is None else float(stop_now)),
        })

    return jsonify({"ok": True, "rows": out})

# --- one-time DB bootstrap (disable/remove after use) ---
ADMIN_SETUP_TOKEN = os.getenv("ADMIN_SETUP_TOKEN")
ADMIN_INITIAL_PASSWORD = os.getenv("ADMIN_INITIAL_PASSWORD", "ChangeMe123!")

@app.route("/admin_bootstrap", methods=["GET","POST"])
def admin_bootstrap():
    # token can come from ?token=... or {"token": "..."} body
    token = request.args.get("token") or ((request.get_json(silent=True) or {}).get("token"))
    if not ADMIN_SETUP_TOKEN or token != ADMIN_SETUP_TOKEN:
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    try:
        db.create_all()
        created = False
        if not User.query.filter_by(username="admin").first():
            pw_hash = generate_password_hash(ADMIN_INITIAL_PASSWORD)
            db.session.add(User(username="admin", password_hash=pw_hash))
            db.session.commit()
            created = True
        return jsonify({"ok": True, "db_initialized": True, "admin_created": created})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/sync_trades", methods=["POST"])
def sync_trades():
    # Are we being called from fetch()?
    is_fetch = request.headers.get("X-Requested-With") == "fetch"

    # Require login
    authed = session.get("user_id") or session.get("logged_in")
    if not authed:
        if is_fetch:
            return jsonify(ok=False, error="auth_required"), 401
        return redirect(url_for("login"))

    use_us  = os.getenv("BINANCE_US", "false").lower() == "true"
    testnet = os.getenv("BINANCE_TESTNET", "false").lower() == "true"
    api_key = os.getenv("BINANCE_API_KEY")
    api_sec = os.getenv("BINANCE_API_SECRET")

    client = Client(api_key, api_sec, tld=("us" if use_us else "com"), testnet=testnet)

    # Symbols to import
    raw = os.getenv("TRADE_SYMBOLS", "BTCUSDT")
    symbols = [s.strip().upper() for s in raw.split(",") if s.strip()]

    # Import from last DB trade (minus 5 min) or last 7 days if none
    last_ts = db.session.query(func.max(Trade.timestamp)).scalar()
    since = (last_ts - timedelta(minutes=5)) if last_ts else (datetime.utcnow() - timedelta(days=7))
    since_ms = int(since.timestamp() * 1000)

    inserted = 0
    try:
        for sym in symbols:
            try:
                fills = client.get_my_trades(symbol=sym, startTime=since_ms, recvWindow=60000)
            except BinanceAPIException as e:
                current_app.logger.error("sync_trades %s: %s", sym, e)
                continue

            for f in fills:
                ts = datetime.utcfromtimestamp(f["time"] / 1000.0)
                side = "BUY" if f.get("isBuyer") else "SELL"
                qty = float(f["qty"])
                price = float(f["price"])

                # idempotency check
                exists = Trade.query.filter_by(symbol=sym, timestamp=ts, price=price, amount=qty).first()
                if exists:
                    continue

                db.session.add(Trade(
                    symbol=sym,
                    side=side,
                    amount=qty,
                    price=price,
                    timestamp=ts,
                    is_open=False,
                    source="import"
                ))
                inserted += 1

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        if is_fetch:
            return jsonify(ok=False, error=str(e)), 500
        flash(f"Sync failed: {e}", "danger")
        return redirect(url_for("dashboard"))

    if is_fetch:
        return jsonify(ok=True, imported=inserted)

    flash(f"Imported {inserted} trade(s) from exchange.)", "success")
    return redirect(url_for("dashboard"))

# ============== Trading endpoints ==============
@app.route('/live_trade', methods=['POST'])
def live_trade():
    if not is_authorized(request):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    symbol    = (data.get('symbol') or '').upper()
    side      = (data.get('side') or '').upper()
    use_quote = bool(data.get('use_quote', False))
    quantity  = data.get('amount') or data.get('quantity')

    # NEW: determine trade source
    source = infer_source_from_request(request, default='manual')


    if not symbol or side not in ('BUY', 'SELL') or quantity is None:
        return jsonify({'status': 'error', 'message': 'symbol, side, and amount/quantity are required'}), 400

    try:
        req_amt = float(quantity)
    except Exception:
        return jsonify({'status': 'error', 'message': 'amount/quantity must be numeric'}), 400

    ok, reason = pre_trade_check(symbol, side, use_quote, req_amt)
    if not ok:
        return jsonify({"status": "error", "message": f"risk block: {reason}"}), 400

    mark_signal(symbol)

    # OCO branch
    if data.get('oco'):
        oco = data['oco']
        tp_type = (oco.get('aboveType') or oco.get('tp_type') or 'TAKE_PROFIT_LIMIT').upper()
        sl_type = (oco.get('belowType') or oco.get('sl_type') or 'STOP_LOSS_LIMIT').upper()
        tp_price = oco.get('abovePrice') or oco.get('tp_price')
        tp_stop  = oco.get('aboveStopPrice') or oco.get('tp_stop')
        sl_price = oco.get('belowPrice') or oco.get('sl_price')
        sl_stop  = oco.get('belowStopPrice') or oco.get('sl_stop')
        try:
            qty = convert_quote_to_base(symbol, float(quantity)) if use_quote else float(quantity)
            res = place_oco_order(
                symbol=symbol, side=side, quantity=qty,
                tp_price=tp_price, tp_stop=tp_stop,
                sl_price=sl_price, sl_stop=sl_stop,
                tp_type=tp_type, sl_type=sl_type, tif='GTC'
            )
            return jsonify({'status': 'success', 'message': 'OCO placed', 'binance': res})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 400

    # Market order branch
    try:
        c = get_binance_client()
        if side == 'SELL':
            req_qty = Decimal(str(quantity))
            allowed, meta = max_sellable_base(symbol)
            if allowed == 0:
                return jsonify({"status": "error",
                                "message": f"Nothing sellable right now ({meta.get('reason','')})."}), 400
            sell_qty = req_qty
            if req_qty > allowed:
                if AUTO_ADJUST_SELL:
                    sell_qty = allowed
                else:
                    return jsonify({
                        "status": "error",
                        "message": (f"risk block: insufficient {symbol[:-4]} balance {meta.get('free_base')}. "
                                    f"Max sellable (after step/minNotional) is {allowed}.")
                    }), 400
            order = c.create_order(
                symbol=symbol, side=Client.SIDE_SELL, type=Client.ORDER_TYPE_MARKET,
                quantity=str(sell_qty), recvWindow=10000
            )
        else:
            if use_quote:
                order = c.create_order(
                    symbol=symbol, side=Client.SIDE_BUY, type=Client.ORDER_TYPE_MARKET,
                    quoteOrderQty=str(float(quantity)), recvWindow=10000
                )
            else:
                order = place_live_market_order(symbol, 'BUY', float(quantity), use_quote=False)

        fqty, fprice = weighted_from_fills(order.get('fills') or [])
        if fqty is None or fqty == 0.0:
            try:
                fprice = float(get_binance_price(symbol)) if fprice is None else fprice
                # If still unknown qty, fallback to request (approx)
                fqty = float(quantity) if not use_quote else 0.0
            except Exception:
                fprice = fprice or 0.0

        # Trade row (NEW: include source)
        try:
            db.session.add(Trade(
                symbol=symbol, side=side,
                amount=float(fqty or 0.0), price=float(fprice or 0.0),
                timestamp=datetime.utcnow(), is_open=(side == 'BUY'),
                source=source  # <-- NEW
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()

        pos_id = None
        if side == 'BUY' and fqty and fprice:
            pos = ensure_position_on_buy(symbol, fqty, fprice)
            pos_id = pos.id

        record_order_row(order, side, symbol, float(fqty or 0.0), float(fprice or 0.0), pos_id)

        if side == 'SELL':
            close_position_if_filled_sells(symbol)

        return jsonify({"status": "success", "order": order})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/signal', methods=['POST'])
def signal():
    print("TV webhook hit:", request.headers.get("User-Agent"), request.get_data(as_text=True))

    if not is_authorized(request):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    symbol    = (data.get('symbol') or '').upper()
    side      = (data.get('side') or '').upper()
    amount    = data.get('amount')
    use_quote = bool(data.get('use_quote', False))
    oco_req   = data.get('oco') or {}

    tp_pct    = float(data.get('tp_pct', DEFAULT_TP_PCT))
    sl_pct    = float(data.get('sl_pct', DEFAULT_SL_PCT))
    sl_extra  = float(data.get('sl_extra', DEFAULT_SL_EXTRA))

    # NEW: determine trade source
    source = infer_source_from_request(request, default='signal')

    if not symbol or side not in ('BUY', 'SELL') or amount is None:
        return jsonify({"status": "error", "message": "symbol, side, amount required"}), 400

    try:
        req_amt = float(amount)
    except Exception:
        return jsonify({"status": "error", "message": "amount must be numeric"}), 400

    ok, reason = pre_trade_check(symbol, side, use_quote, req_amt)
    if not ok:
        return jsonify({"status": "error", "message": f"risk block: {reason}"}), 400

    mark_signal(symbol)

    try:
        c = get_binance_client()
        f = get_symbol_filters(c, symbol)
        tick = f["tickSize"]
        step = f["stepSize"]
        last = Decimal(c.get_symbol_ticker(symbol=symbol)["price"])

        # SELL branch
        if side == 'SELL':
            req_qty = Decimal(str(amount))
            allowed, meta = max_sellable_base(symbol)
            if allowed == 0:
                return jsonify({
                    "status": "error",
                    "message": f"Nothing sellable right now ({meta.get('reason','below exchange minimums')})."
                }), 400
            sell_qty = req_qty
            if req_qty > allowed:
                if AUTO_ADJUST_SELL:
                    sell_qty = allowed
                else:
                    return jsonify({
                        "status": "error",
                        "message": (f"risk block: insufficient {symbol[:-4]} balance {meta.get('free_base')}. "
                                    f"Max sellable (after step/minNotional) is {allowed}.")
                    }), 400
            order = c.create_order(
                symbol=symbol, side=Client.SIDE_SELL, type=Client.ORDER_TYPE_MARKET,
                quantity=str(sell_qty), recvWindow=10000
            )
            fqty, fprice = weighted_from_fills(order.get('fills') or [])
            if fprice is None: fprice = float(last)
            if fqty   is None: fqty   = float(sell_qty)

            # Trade row (NEW: include source)
            try:
                db.session.add(Trade(
                    symbol=symbol, side='SELL', amount=float(fqty), price=float(fprice),
                    is_open=False, source=source  # <-- NEW
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()

            record_order_row(order, 'SELL', symbol, float(fqty), float(fprice), position_id=None)
            close_position_if_filled_sells(symbol)
            return jsonify({"status": "success", "order": order})

        # BUY branch
        if use_quote:
            order = c.create_order(
                symbol=symbol, side=Client.SIDE_BUY, type=Client.ORDER_TYPE_MARKET,
                quoteOrderQty=str(float(amount)), recvWindow=10000
            )
        else:
            base_qty = Decimal(str(amount))
            base_qty = (base_qty // step) * step
            if base_qty <= 0:
                return jsonify({"status": "error", "message": "BUY base amount too small after step rounding"}), 400
            order = c.create_order(
                symbol=symbol, side=Client.SIDE_BUY, type=Client.ORDER_TYPE_MARKET,
                quantity=str(base_qty), recvWindow=10000
            )

        filled_qty, filled_price = weighted_from_fills(order.get("fills") or [])
        if filled_price is None:
            filled_price = float(last)
        if filled_qty is None:
            if use_quote:
                approx = Decimal(str(amount)) / Decimal(str(filled_price))
                filled_qty = float((approx // step) * step)
            else:
                filled_qty = float(base_qty)

        # Trade row (NEW: include source)
        try:
            db.session.add(Trade(
                symbol=symbol, side='BUY',
                amount=float(filled_qty), price=float(filled_price),
                timestamp=datetime.utcnow(), is_open=True,
                source=source  # <-- NEW
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()

        pos = ensure_position_on_buy(symbol, filled_qty, filled_price)
        record_order_row(order, 'BUY', symbol, float(filled_qty), float(filled_price), pos.id)

        # instant toast for buy
        notify_event("entry_filled", {"symbol": symbol, "qty": float(filled_qty), "price": float(filled_price)})

        # OCO: explicit or auto
        oco_response = None
        explicit = any(k in oco_req for k in ("abovePrice", "aboveStopPrice", "belowPrice", "belowStopPrice"))

        if explicit:
            tp_type = (oco_req.get('aboveType') or 'TAKE_PROFIT_LIMIT').upper()
            sl_type = (oco_req.get('belowType') or 'STOP_LOSS_LIMIT').upper()
            tp_price = oco_req.get('abovePrice')
            tp_stop  = oco_req.get('aboveStopPrice') or tp_price
            sl_price = oco_req.get('belowPrice')
            sl_stop  = oco_req.get('belowStopPrice') or sl_price
            try:
                oco_response = place_oco_order(
                    symbol=symbol, side='SELL', quantity=float(filled_qty),
                    tp_price=tp_price, tp_stop=tp_stop,
                    sl_price=sl_price, sl_stop=sl_stop,
                    tp_type=tp_type, sl_type=sl_type, tif='GTC'
                )
            except Exception as e:
                oco_response = {"error": str(e)}
        elif ENABLE_AUTO_BRACKET:
            fp = Decimal(str(filled_price))
            tp_p   = round_to_tick(fp * Decimal(1 + tp_pct), tick)
            sl_tr  = round_to_tick(fp * Decimal(1 - sl_pct), tick)
            sl_lim = round_to_tick(sl_tr * Decimal(1 - sl_extra), tick)
            try:
                oco_response = place_oco_order(
                    symbol=symbol, side='SELL', quantity=float(filled_qty),
                    tp_price=float(tp_p), tp_stop=float(tp_p),
                    sl_price=float(sl_lim), sl_stop=float(sl_tr),
                    tp_type='TAKE_PROFIT_LIMIT', sl_type='STOP_LOSS_LIMIT', tif='GTC'
                )
            except Exception as e:
                oco_response = {"error": str(e)}

        # Save OCO legs if present
        try:
            if isinstance(oco_response, dict) and 'orders' in oco_response:
                for leg in oco_response.get('orders', []):
                    record_order_row(
                        order=leg, side='SELL', symbol=symbol,
                        qty=0.0, price=float(leg.get('price') or 0.0),
                        position_id=pos.id if pos else None
                    )
        except Exception:
            db.session.rollback()

        if oco_response and not (isinstance(oco_response, dict) and "error" in oco_response):
            notify_event("oco_attached", {"symbol": symbol, "qty": float(filled_qty)})

        return jsonify({
            "status": "success",
            "entry_order": order,
            "filled_qty": f"{float(filled_qty):.8f}",
            "fill_price": f"{float(filled_price):.8f}",
            "oco_order": oco_response or "no_bracket_attached"
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/order_cancel', methods=['POST'])
def order_cancel():
    if not is_authorized(request):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    binance_id = str(data.get('binance_id') or '').strip()
    symbol     = (data.get('symbol') or '').upper()

    if not binance_id or not symbol:
        return jsonify({"ok": False, "error": "symbol and binance_id required"}), 400

    row = Order.query.filter_by(binance_id=binance_id).first()

    def _finish_sync(msg_obj, http_code=200):
        # best-effort refresh & timestamps
        try:
            sync_open_core(symbol=symbol)
        except Exception:
            pass
        return jsonify(msg_obj), http_code

    try:
        c = get_binance_client()
        # Try cancel by orderId
        res = c.cancel_order(symbol=symbol, orderId=int(binance_id), recvWindow=10000)

        # Mark local row
        if row:
            row.status = 'CANCELED'
            db.session.commit()

        return _finish_sync({"ok": True, "result": res})
    except BinanceAPIException as e:
        code = getattr(e, 'code', None)
        msg  = str(e)
        # Unknown / not open / not found -> treat as already closed; reconcile from remote history
        if code in (-2011, -2013) or 'Unknown order' in msg or 'order not found' in msg:
            try:
                c = get_binance_client()
                # check recent orders for the true status
                recents = c.get_all_orders(symbol=symbol, limit=50)
                remote_status = None
                for r in recents:
                    if str(r.get('orderId')) == binance_id:
                        remote_status = r.get('status')
                        break

                # Update local row conservatively
                if row:
                    row.status = (remote_status or 'CANCELED')
                    db.session.commit()

                note = ("Order already closed on exchange"
                        if remote_status and remote_status != 'NEW'
                        else "Order not found on exchange; marked closed locally")
                return _finish_sync({"ok": True, "already": True, "status": remote_status or 'CANCELED', "note": note})
            except Exception:
                # As a last resort, mark closed locally so the UI doesn’t get stuck
                try:
                    if row:
                        row.status = 'CANCELED'
                        db.session.commit()
                except Exception:
                    db.session.rollback()
                return _finish_sync({"ok": True, "already": True, "status": "CANCELED",
                                     "note": "Exchange lookup failed; closed locally."})
        # Any other API error -> bubble up
        return jsonify({"ok": False, "error": f"Binance API error {code}: {msg}"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 400
    
@app.route('/order_cancel_all', methods=['POST'])
def order_cancel_all():
    if not is_authorized(request):
        return jsonify({'error':'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    symbol = (data.get('symbol') or '').upper()
    if not symbol:
        return jsonify({"ok": False, "error": "symbol required"}), 400
    try:
        c = get_binance_client()
        res = c.cancel_open_orders(symbol=symbol, recvWindow=10000)
        # Mark locals closed
        for o in Order.query.filter_by(symbol=symbol).filter(Order.status.in_(['NEW','PARTIALLY_FILLED'])).all():
            o.status = 'CANCELED'
        db.session.commit()
        try:
            sync_open_core(symbol=symbol)
        except Exception:
            pass
        return jsonify({"ok": True, "result": res})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/position_close', methods=['POST'])
def position_close():
    if not is_authorized(request):
        return jsonify({'error': 'Unauthorized'}), 401
    data   = request.get_json(silent=True) or {}
    symbol = (data.get('symbol') or '').upper()
    pct    = float(data.get('percent', 100.0))
    if not symbol or pct <= 0:
        return jsonify({"ok": False, "error": "symbol and positive percent required"}), 400
    pos = Position.query.filter_by(symbol=symbol, status='OPEN').first()
    if not pos or (pos.qty or 0.0) <= 0:
        return jsonify({"ok": False, "error": "no open position"}), 400
    try:
        qty_total = Decimal(str(pos.qty or 0.0))
        sell_qty  = quantize_to_step(qty_total * Decimal(pct/100.0), get_symbol_filters(get_binance_client(), symbol)["stepSize"])
        if sell_qty <= 0:
            return jsonify({"ok": False, "error": "amount too small after step rounding"}), 400
        ok, reason = pre_trade_check(symbol, 'SELL', False, float(sell_qty))
        if not ok:
            return jsonify({"ok": False, "error": f"risk block: {reason}"}), 400
        c = get_binance_client()
        order = c.create_order(symbol=symbol, side=Client.SIDE_SELL,
                               type=Client.ORDER_TYPE_MARKET,
                               quantity=str(sell_qty), recvWindow=10000)
        try:
            price = float(get_binance_price(symbol) or pos.avg_price or 0.0)
            db.session.add(Trade(symbol=symbol, side='SELL', amount=float(sell_qty),
                                 price=price, timestamp=datetime.utcnow(), is_open=False))
            db.session.commit()
            notify_event("position_closed", {"symbol": symbol, "qty": float(sell_qty)})
        except Exception:
            db.session.rollback()
        close_position_if_filled_sells(symbol)
        return jsonify({"ok": True, "order": order})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/trail/set', methods=['POST'])
def trail_set():
    if not is_authorized(request):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    symbol = (data.get('symbol') or '').upper()
    active = bool(data.get('active', True))
    trail_pct = data.get('trail_pct')   # e.g. 0.01
    arm_pct = data.get('arm_pct')       # e.g. 0.005
    if not symbol:
        return jsonify({"ok": False, "error": "symbol required"}), 400
    try:
        row = set_trailing(symbol, active, trail_pct, arm_pct)
        state = {
            "symbol": row.symbol, "active": row.active,
            "trail_pct": row.trail_pct, "arm_pct": row.arm_pct,
            "armed": row.armed, "high_water": row.high_water
        }
        notify_event("trailing_updated", {"symbol": symbol, **state})
        return jsonify({"ok": True, "state": state})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 400

# ============== Auth & dashboard ==============
def load_trailing_cfg_dict() -> dict[str, dict]:
    d = {}
    for r in TrailingCfg.query.all():
        d[r.symbol] = {
            "active": bool(r.active),
            "armed": bool(r.armed),
            "high_water": float(r.high_water or 0.0),
            "trail_pct": float(r.trail_pct or 0.0),
            "arm_pct": float(r.arm_pct or 0.0),
        }
    return d

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Incorrect credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    trades = Trade.query.order_by(Trade.timestamp.desc()).limit(50).all()
    positions_open = Position.query.filter_by(status='OPEN').all()
    positions_closed = Position.query.filter_by(status='CLOSED').order_by(Position.closed_at.desc()).limit(50).all()
    orders_open = Order.query.filter(Order.status.in_(['NEW','PARTIALLY_FILLED'])).order_by(Order.created_at.desc()).limit(50).all()

    def current_price(sym):
        try:
            c = get_binance_client()
            return float(c.get_symbol_ticker(symbol=sym)['price'])
        except Exception:
            return 0.0

    realized = sum((p.realized_pnl or 0.0) for p in positions_closed)
    unrealized = sum((current_price(p.symbol) - (p.avg_price or 0.0)) * (p.qty or 0.0) for p in positions_open)

    return render_template(
        'dashboard.html',
        trades=trades,
        positions_open=positions_open,
        positions_closed=positions_closed,
        orders_open=orders_open,
        pnl_realized=realized,
        pnl_unrealized=unrealized,
        auto_sync_enabled=_AUTO_SYNC_ENABLED,
        auto_sync_interval=AUTO_SYNC_INTERVAL_S,
        trailing_cfg=load_trailing_cfg_dict()
    )
    
# ============== Paper trading monitor (unchanged) ==============
def monitor_trades():
    with app.app_context():
        while True:
            try:
                open_trades = Trade.query.filter_by(is_open=True).all()
                for t in open_trades:
                    current = get_binance_price(t.symbol)
                    if current is None:
                        continue
                    if t.stop_loss is not None:
                        if (t.side == "BUY" and current <= t.stop_loss) or (t.side == "SELL" and current >= t.stop_loss):
                            t.is_open = False
                    if t.is_open and t.take_profit is not None:
                        if (t.side == "BUY" and current >= t.take_profit) or (t.side == "SELL" and current <= t.take_profit):
                            t.is_open = False
                db.session.commit()
            except Exception as e:
                print("Monitor error:", e)
            time.sleep(10)

threading.Thread(target=monitor_trades, daemon=True).start()


# ============== App start ==============
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)




