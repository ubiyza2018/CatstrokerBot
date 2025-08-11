import os
import hmac
import json
import time
import base64
import hashlib
import secrets
import urllib.parse
from typing import Dict, Any, Optional, List, Tuple

import aiosqlite
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN") or ""
BACKEND_ORIGIN = os.getenv("BACKEND_ORIGIN") or ""
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN") or ""
SERVER_SECRET = (os.getenv("SERVER_SECRET") or secrets.token_hex(32)).encode()

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN не указан в .env")

# Игровой баланс
DEFAULT_PER_STROKE = 1
DEFAULT_MAX_ENERGY = 100
ENERGY_REGEN_PER_SEC = 0.5
DAILY_REWARD = 500
TAP_MIN_INTERVAL_SEC = 0.08

UPGRADES = {
    "paw_glove": {  # перчатка
        "name": "Перчатка любви",
        "desc": "Больше мурчиков за ласку",
        "base_cost": 150, "cost_mult": 1.75,
        "per_stroke_bonus": 1, "max_level": 100,
    },
    "cloud_pillow": {  # подушка
        "name": "Подушка из облаков",
        "desc": "Больше запаса лапки (энергии)",
        "base_cost": 200, "cost_mult": 1.7,
        "max_energy_bonus": 20, "max_level": 50,
    },
    "purr_modulator": {  # мур-модулятор
        "name": "Мурчикофон",
        "desc": "Пассивные мурчики в минуту",
        "base_cost": 300, "cost_mult": 1.8,
        "passive_per_min_bonus": 5, "max_level": 100,
    },
}

app = FastAPI(title="Catstroker API", version="1.0")

# CORS: разрешаем фронту дергать API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN] if FRONTEND_ORIGIN else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "db.sqlite"

async def init_db():
    conn = await aiosqlite.connect(DB_PATH)
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    await conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tg_id INTEGER UNIQUE NOT NULL,
        username TEXT,
        purrs INTEGER NOT NULL DEFAULT 0,
        energy REAL NOT NULL DEFAULT 100,
        max_energy INTEGER NOT NULL DEFAULT 100,
        per_stroke INTEGER NOT NULL DEFAULT 1,
        passive_rate_per_min REAL NOT NULL DEFAULT 0,
        last_energy_ts INTEGER NOT NULL DEFAULT 0,
        last_passive_ts INTEGER NOT NULL DEFAULT 0,
        last_stroke_ts INTEGER NOT NULL DEFAULT 0,
        last_daily_ts INTEGER NOT NULL DEFAULT 0,
        referrer_tg_id INTEGER,
        total_strokes INTEGER NOT NULL DEFAULT 0,
        created_ts INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_upgrades (
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        level INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, key),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    await conn.commit()
    await conn.close()

@app.on_event("startup")
async def on_startup():
    await init_db()

# -------- Utils --------

def now() -> int:
    return int(time.time())

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_token(user_id: int, exp: int) -> str:
    msg = f"{user_id}:{exp}".encode()
    sig = hmac.new(SERVER_SECRET, msg, hashlib.sha256).digest()
    return b64url(msg + b"." + sig)

def verify_token(token: str) -> Optional[int]:
    try:
        raw = b64url_decode(token)
        msg, sig = raw.split(b".", 1)
        expect = hmac.new(SERVER_SECRET, msg, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            return None
        user_id_str, exp_str = msg.decode().split(":")
        if int(exp_str) < now():
            return None
        return int(user_id_str)
    except Exception:
        return None

def calc_upgrade_cost(key: str, level: int) -> int:
    spec = UPGRADES[key]
    return int((spec["base_cost"] * (spec["cost_mult"] ** level) + 0.9999))

def validate_init_data(init_data: str) -> Dict[str, Any]:
    # Валидация по алгоритму Telegram WebApp
    # 1) Парсим URL-encoded initData в пары
    parsed = urllib.parse.parse_qs(init_data, strict_parsing=True)
    data = {k: v[0] for k, v in parsed.items()}
    if "hash" not in data:
        raise HTTPException(400, "hash missing")
    recv_hash = data.pop("hash")

    # 2) Строим data_check_string
    check_pairs = []
    for k in sorted(data.keys()):
        check_pairs.append(f"{k}={data[k]}")
    data_check_string = "\n".join(check_pairs).encode()

    # 3) secret_key = sha256(BOT_TOKEN)
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()

    # 4) our_hash = HMAC_SHA256(secret_key, data_check_string)
    our_hash = hmac.new(secret_key, data_check_string, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(our_hash, recv_hash):
        raise HTTPException(401, "initData invalid")

    # 5) Достаём user
    if "user" not in data:
        raise HTTPException(400, "user missing")
    user_json = data["user"]
    user = json.loads(user_json)
    return {"user": user, "raw": data}

# -------- Models --------

class AuthRequest(BaseModel):
    initData: str

class UpgradeRequest(BaseModel):
    key: str

class StrokeRequest(BaseModel):
    strokes: int = 1  # можно копить клики в очередь

# -------- DB helpers --------

async def get_conn():
    return await aiosqlite.connect(DB_PATH)

async def get_user_by_tg(conn, tg_id: int) -> Optional[aiosqlite.Row]:
    cur = await conn.execute("SELECT * FROM users WHERE tg_id = ?", (tg_id,))
    row = await cur.fetchone()
    await cur.close()
    return row

async def create_user(conn, tg_id: int, username: Optional[str], referrer_tg_id: Optional[int]) -> aiosqlite.Row:
    ts = now()
    await conn.execute("""
    INSERT INTO users (tg_id, username, purrs, energy, max_energy, per_stroke, passive_rate_per_min,
                       last_energy_ts, last_passive_ts, last_stroke_ts, last_daily_ts,
                       referrer_tg_id, total_strokes, created_ts)
    VALUES (?, ?, 0, ?, ?, ?, 0, ?, ?, 0, 0, ?, 0, ?)
    """, (tg_id, username, float(DEFAULT_MAX_ENERGY), DEFAULT_MAX_ENERGY,
          DEFAULT_PER_STROKE, ts, ts, referrer_tg_id, ts))
    await conn.commit()
    # Инициализируем апгрейды
    cur = await conn.execute("SELECT id FROM users WHERE tg_id = ?", (tg_id,))
    user_row = await cur.fetchone()
    await cur.close()
    for key in UPGRADES.keys():
        await conn.execute("INSERT OR IGNORE INTO user_upgrades (user_id, key, level) VALUES (?, ?, 0)", (user_row[0], key))
    await conn.commit()
    # Реферальный бонус (простая версия: только если реферер уже есть в БД)
    if referrer_tg_id:
        # +100 обоим
        await conn.execute("UPDATE users SET purrs = purrs + 100 WHERE tg_id IN (?, ?)", (tg_id, referrer_tg_id))
        await conn.commit()
    cur = await conn.execute("SELECT * FROM users WHERE tg_id = ?", (tg_id,))
    row = await cur.fetchone()
    await cur.close()
    return row

async def accrue(conn, user_row) -> Dict[str, Any]:
    # Применяем реген энергии и пассивный доход
    user = dict(zip([d[0] for d in (await conn.execute("PRAGMA table_info(users)")).description], user_row))
    # Получить поля по имени удобнее через SELECT ... AS, но сделаем проще:
    keys = ["id","tg_id","username","purrs","energy","max_energy","per_stroke","passive_rate_per_min",
            "last_energy_ts","last_passive_ts","last_stroke_ts","last_daily_ts","referrer_tg_id","total_strokes","created_ts"]
    user = dict(zip(keys, user_row))

    ts = now()
    updates = {}
    # Энергия
    if user["energy"] < user["max_energy"]:
        dt = max(0, ts - user["last_energy_ts"])
        if dt > 0:
            regen = dt * ENERGY_REGEN_PER_SEC
            new_energy = min(user["max_energy"], user["energy"] + regen)
            updates["energy"] = new_energy
            updates["last_energy_ts"] = ts
    # Пассив
    if user["passive_rate_per_min"] > 0:
        dt = max(0, ts - user["last_passive_ts"])
        if dt > 0:
            gain = int((user["passive_rate_per_min"] / 60.0) * dt)
            if gain > 0:
                updates["purrs"] = user["purrs"] + gain
                updates["last_passive_ts"] = ts

    if updates:
        sets = ", ".join([f"{k} = ?" for k in updates.keys()])
        await conn.execute(f"UPDATE users SET {sets} WHERE id = ?", (*updates.values(), user["id"]))
        await conn.commit()
        # обновим user
        cur = await conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],))
        user_row = await cur.fetchone()
        await cur.close()
        user = dict(zip(keys, user_row))
    return user

def public_state(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "purrs": user["purrs"],
        "energy": int(user["energy"]),
        "max_energy": user["max_energy"],
        "per_stroke": user["per_stroke"],
        "passive_per_min": int(user["passive_rate_per_min"]),
        "total_strokes": user["total_strokes"],
        "cooldowns": {
            "daily_available_in": max(0, 24*3600 - (now() - user["last_daily_ts"]))
        }
    }

async def auth_required(authorization: Optional[str] = Header(None)) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "no token")
    token = authorization.split(" ", 1)[1]
    user_id = verify_token(token)
    if not user_id:
        raise HTTPException(401, "invalid token")
    return user_id

# -------- Endpoints --------

@app.post("/api/auth")
async def api_auth(payload: AuthRequest):
    data = validate_init_data(payload.initData)
    tg_user = data["user"]
    tg_id = int(tg_user["id"])
    username = tg_user.get("username")
    referrer_tg_id = None  # реферал можно выставить заранее через /start у бота

    async with await get_conn() as conn:
        row = await get_user_by_tg(conn, tg_id)
        if not row:
            row = await create_user(conn, tg_id, username, referrer_tg_id)
        # обновим username, если поменялся
        await conn.execute("UPDATE users SET username = ? WHERE tg_id = ?", (username, tg_id))
        await conn.commit()
        # выдаём токен
        exp = now() + 24*3600*7
        token = sign_token(row[0], exp)  # row[0] = id
    return {"token": token}

@app.get("/api/state")
async def api_state(user_id: int = Depends(auth_required)):
    async with await get_conn() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cur.fetchone()
        await cur.close()
        if not row:
            raise HTTPException(404, "user not found")
        user = await accrue(conn, row)
    return public_state(user)

@app.post("/api/stroke")
async def api_stroke(req: StrokeRequest, user_id: int = Depends(auth_required)):
    count = max(1, min(50, req.strokes))  # антиизлишество
    ts = now()
    async with await get_conn() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cur.fetchone()
        await cur.close()
        if not row: raise HTTPException(404, "user not found")
        user = await accrue(conn, row)

        # простая антиспам-проверка интервала
        if ts - user["last_stroke_ts"] < TAP_MIN_INTERVAL_SEC:
            # не ругаемся, просто возвращаем стейт
            return public_state(user)

        # сколько удастся применить с учетом энергии
        can = min(int(user["energy"]), count)
        if can <= 0:
            return public_state(user)

        gain = can * user["per_stroke"]
        new_energy = user["energy"] - can
        await conn.execute("""
            UPDATE users
            SET purrs = purrs + ?, energy = ?, total_strokes = total_strokes + ?,
                last_stroke_ts = ?, last_energy_ts = ?
            WHERE id = ?
        """, (gain, new_energy, user["total_strokes"] + can, ts, ts, user_id))
        await conn.commit()

        cur = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        updated = await cur.fetchone(); await cur.close()
        user2 = await accrue(conn, updated)
    return public_state(user2)

@app.post("/api/upgrade")
async def api_upgrade(req: UpgradeRequest, user_id: int = Depends(auth_required)):
    key = req.key
    if key not in UPGRADES: raise HTTPException(400, "unknown upgrade")
    spec = UPGRADES[key]
    async with await get_conn() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cur.fetchone(); await cur.close()
        if not row: raise HTTPException(404, "user not found")
        user = await accrue(conn, row)

        cur = await conn.execute("SELECT level FROM user_upgrades WHERE user_id = ? AND key = ?", (user_id, key))
        got = await cur.fetchone(); await cur.close()
        level = got[0] if got else 0
        if level >= spec["max_level"]:
            raise HTTPException(400, "max level")

        cost = calc_upgrade_cost(key, level)
        if user["purrs"] < cost:
            raise HTTPException(400, f"need {cost - user['purrs']} purrs")

        await conn.execute("UPDATE users SET purrs = purrs - ? WHERE id = ?", (cost, user_id))
        await conn.execute("UPDATE user_upgrades SET level = ? WHERE user_id = ? AND key = ?", (level+1, user_id, key))

        # применяем эффект
        updates = {}
        if key == "paw_glove":
            updates["per_stroke"] = user["per_stroke"] + spec["per_stroke_bonus"]
        elif key == "cloud_pillow":
            updates["max_energy"] = user["max_energy"] + spec["max_energy_bonus"]
            updates["energy"] = min(updates["max_energy"], user["energy"] + spec["max_energy_bonus"])
        elif key == "purr_modulator":
            updates["passive_rate_per_min"] = user["passive_rate_per_min"] + spec["passive_per_min_bonus"]

        if updates:
            sets = ", ".join([f"{k} = ?" for k in updates.keys()])
            await conn.execute(f"UPDATE users SET {sets} WHERE id = ?", (*updates.values(), user_id))
        await conn.commit()

        cur = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        updated = await cur.fetchone(); await cur.close()
        user2 = await accrue(conn, updated)
    return {"state": public_state(user2), "upgrade": {"key": key, "level": level+1}}

@app.post("/api/daily")
async def api_daily(user_id: int = Depends(auth_required)):
    ts = now()
    async with await get_conn() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cur.fetchone(); await cur.close()
        if not row: raise HTTPException(404, "user not found")
        user = await accrue(conn, row)
        if ts - user["last_daily_ts"] < 24*3600:
            raise HTTPException(400, "already claimed")
        await conn.execute("UPDATE users SET purrs = purrs + ?, last_daily_ts = ? WHERE id = ?", (DAILY_REWARD, ts, user_id))
        await conn.commit()
        cur = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        updated = await cur.fetchone(); await cur.close()
        user2 = await accrue(conn, updated)
    return {"state": public_state(user2), "reward": DAILY_REWARD}

@app.get("/api/leaderboard")
async def api_leaderboard(limit: int = 10):
    async with await get_conn() as conn:
        cur = await conn.execute("""
            SELECT COALESCE(username, 'cat_' || substr(hex(tg_id), -6)) AS name, purrs
            FROM users ORDER BY purrs DESC LIMIT ?
        """, (limit,))
        rows = await cur.fetchall(); await cur.close()
    return [{"name": r[0], "purrs": r[1]} for r in rows]
