import os
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import aiosqlite
import time

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN") or "https://your-frontend.example.com"
DB_PATH = "backend/db.sqlite"

async def ensure_user_with_ref(tg_id: int, username: str | None, ref_tg_id: int | None):
    # только для записи рефера, если юзер ещё не создан
    async with await aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute("SELECT id FROM users WHERE tg_id = ?", (tg_id,))
        row = await cur.fetchone(); await cur.close()
        if row:
            # обновим username
            await conn.execute("UPDATE users SET username = ? WHERE tg_id = ?", (username, tg_id))
            await conn.commit()
            return
        ts = int(time.time())
        await conn.execute("""
        INSERT INTO users (tg_id, username, purrs, energy, max_energy, per_stroke, passive_rate_per_min,
                           last_energy_ts, last_passive_ts, last_stroke_ts, last_daily_ts,
                           referrer_tg_id, total_strokes, created_ts)
        VALUES (?, ?, 0, 100, 100, 1, 0, ?, ?, 0, 0, ?, 0, ?)
        """, (tg_id, username, ts, ts, ref_tg_id if ref_tg_id and ref_tg_id != tg_id else None, ts))
        await conn.commit()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    ref = None
    if context.args:
        # поддержка /start ref=12345
        arg = context.args[0]
        if arg.startswith("ref="):
            arg = arg.split("=", 1)[1]
        if arg.isdigit():
            ref = int(arg)
    await ensure_user_with_ref(user.id, user.username, ref)

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("😺 Открыть Catstroker", web_app=WebAppInfo(url=f"{FRONTEND_ORIGIN}/index.html"))]
    ])
    await update.message.reply_text(
        "Добро пожаловать в Catstroker! Гладь котика — собирай мурчики. Нажми кнопку ниже.",
        reply_markup=keyboard
    )

def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN отсутствует")
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
