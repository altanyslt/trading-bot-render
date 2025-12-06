"""
═══════════════════════════════════════════════════════════════
ALGORITMIK TRADING BOT - RENDER.COM FINAL FIXED VERSION v2
═══════════════════════════════════════════════════════════════
"""

import yfinance as yf
import pandas as pd
import ta
import warnings
import asyncio
import os
import time
from datetime import datetime
import pytz
from threading import Thread
from flask import Flask, jsonify
import logging
import requests

from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, JobQueue

warnings.filterwarnings('ignore')

# ═══════════════════════════════════════════════════════════════
# 1. LOGGING CONFIGURATION
# ═══════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# ═══════════════════════════════════════════════════════════════
# 2. FLASK KEEP-ALIVE
# ═══════════════════════════════════════════════════════════════
app = Flask(__name__)
app.config['START_TIME'] = time.time()

@app.route('/')
def home():
    return "Bot Calisiyor."

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    try:
        app.run(host='0.0.0.0', port=port, threaded=True, use_reloader=False)
    except: pass

def keep_alive():
    t = Thread(target=run_flask, daemon=True)
    t.start()

# ═══════════════════════════════════════════════════════════════
# 3. AYARLAR
# ═══════════════════════════════════════════════════════════════
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
SCAN_INTERVAL = 900 
MAX_SYMBOLS_PER_SCAN = 8
CACHE_TTL = 300
NIGHT_MODE_START = 23
NIGHT_MODE_END = 9

DEFAULT_FAVORITES = [
    "ASELS.IS", "THYAO.IS", "SASA.IS", "BTC-USD", "ETH-USD", "XU100.IS",
    "GARAN.IS", "BIMAS.IS", "AAPL", "NVDA", "TSLA"
]

scan_stats = {'total': 0, 'signals_sent': 0, 'last_scan': None, 'errors': 0}

# ═══════════════════════════════════════════════════════════════
# 4. TRADING BRAIN
# ═══════════════════════════════════════════════════════════════
class TradingBrain:
    def __init__(self):
        self.timeframes = {
            '1d': {'period': '1y', 'interval': '1d', 'weight': 40},
            '4h': {'period': '6mo', 'interval': '60m', 'weight': 60}
        }
        self.cache = {}
        self.cache_ttl = CACHE_TTL
    
    def clean_cache(self):
        now = time.time()
        self.cache = {k: v for k, v in self.cache.items() if now - v[1] < self.cache_ttl * 2}
    
    def get_data(self, symbol, timeframe):
        # TİRE DÜZELTME
        symbol = symbol.replace('—', '-').replace('–', '-') 
        
        cache_key = f"{symbol}_{timeframe}"
        now = time.time()
        
        if cache_key in self.cache:
            data, timestamp = self.cache[cache_key]
            if now - timestamp < self.cache_ttl: return data
        
        try:
            config = self.timeframes[timeframe]
            
            # --- GÜÇLENDİRİLMİŞ ANTI-BLOCK AYARLARI ---
            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive"
            })
            
            df = yf.download(
                symbol, period=config['period'], interval=config['interval'], 
                progress=False, auto_adjust=False, threads=False, timeout=20, session=session
            )
            
            if isinstance(df.columns, pd.MultiIndex): df.columns = df.columns.get_level_values(0)
            
            if df.empty or len(df) < 20: 
                # Hata logunu sessize al (spam olmasın diye)
                return None
            
            self.cache[cache_key] = (df, now)
            return df
        except Exception as e:
            logger.error(f"❌ Veri hatası ({symbol}): {e}")
            return None

    def calculate_indicators(self, df):
        if df is None: return None
        try:
            close = df['Close']
            df['rsi'] = ta.momentum.RSIIndicator(close, window=14).rsi()
            macd = ta.trend.MACD(close)
            df['macd'] = macd.macd()
            df['macd_signal'] = macd.macd_signal()
            bb = ta.volatility.BollingerBands(close)
            df['bb_pct'] = bb.bollinger_pband()
            return df
        except: return None

    def analyze_symbol_score_only(self, symbol):
        total_score = 0
        valid = False
        for tf, config in self.timeframes.items():
            df = self.get_data(symbol, tf)
            df = self.calculate_indicators(df)
            if df is not None:
                valid = True
                curr = df.iloc[-1]
                prev = df.iloc[-2]
                score = 0
                
                # RSI
                if curr['rsi'] <= 30: score += 2
                elif curr['rsi'] >= 70: score -= 2
                
                # MACD Cross
                if curr['macd'] > curr['macd_signal'] and prev['macd'] <= prev['macd_signal']: score += 2
                elif curr['macd'] < curr['macd_signal'] and prev['macd'] >= prev['macd_signal']: score -= 2
                elif curr['macd'] > curr['macd_signal']: score += 1
                else: score -= 1
                
                # Bollinger
                if curr['bb_pct'] < 0.1: score += 1
                elif curr['bb_pct'] > 0.9: score -= 1
                
                total_score += score * (config['weight'] / 100)
        
        return round(total_score, 2) if valid else None

    def analyze_symbol_detailed(self, symbol):
        symbol = symbol.replace('—', '-').replace('–', '-')
        score = self.analyze_symbol_score_only(symbol)
        if score is None: return f"❌ <b>{symbol}</b>: Veri alınamadı (Yahoo Engeli)."
        
        icon = "⚪"
        if score >= 2.0: icon = "🚀"
        elif score >= 1.0: icon = "🟢"
        elif score <= -2.0: icon = "📉"
        elif score <= -1.0: icon = "🔴"
        
        return f"{icon} <b>{symbol}</b>\n🎯 Skor: <b>{score:+.2f}</b>"

brain = TradingBrain()

# ═══════════════════════════════════════════════════════════════
# 5. BOT KOMUTLARI
# ═══════════════════════════════════════════════════════════════

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if 'favorites' not in context.user_data: context.user_data['favorites'] = DEFAULT_FAVORITES.copy()
    
    await update.message.reply_text(
        "🦅 <b>Trading Bot Aktif!</b>\n"
        "Otomatik tarama motoru çalışıyor.", 
        parse_mode='HTML'
    )
    
    # JOBQUEUE FIX: Artık hata vermeyecek
    if context.job_queue:
        current_jobs = context.job_queue.get_jobs_by_name(f'auto_scan_{chat_id}')
        for job in current_jobs: job.schedule_removal()
        
        context.job_queue.run_repeating(
            otomatik_tarama, interval=SCAN_INTERVAL, first=10, 
            chat_id=chat_id, name=f'auto_scan_{chat_id}', data=context.user_data
        )
    else:
        # Fallback (Yedek plan)
        await update.message.reply_text("⚠️ Otomatik motor başlatılamadı, manuel mod aktif.")

async def otomatik_tarama(context: ContextTypes.DEFAULT_TYPE):
    job = context.job
    favorites = job.data.get('favorites', DEFAULT_FAVORITES)
    now = datetime.now(pytz.timezone('Europe/Istanbul'))
    if NIGHT_MODE_START <= now.hour or now.hour < NIGHT_MODE_END: return

    scan_stats['total'] += 1
    logger.info(f"⏰ Otomatik tarama başladı ({len(favorites)} sembol)")
    
    alerts = []
    for idx, symbol in enumerate(favorites[:MAX_SYMBOLS_PER_SCAN]):
        try:
            if idx > 0: await asyncio.sleep(2)
            loop = asyncio.get_running_loop()
            score = await loop.run_in_executor(None, brain.analyze_symbol_score_only, symbol)
            
            if score and score >= 2.0: alerts.append(f"🚀 <b>{symbol}</b>: ALIM ({score})")
            elif score and score <= -2.0: alerts.append(f"📉 <b>{symbol}</b>: SATIM ({score})")
        except: continue
    
    if alerts:
        await context.bot.send_message(job.chat_id, text="🚨 <b>SİNYAL</b>\n" + "\n".join(alerts), parse_mode='HTML')

async def analiz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.message.reply_text("❌ Örn: /analiz ASELS.IS")
    
    symbol = context.args[0].upper().replace('—', '-').replace('–', '-')
    msg = await update.message.reply_text(f"🔍 {symbol} analiz ediliyor...")
    
    try:
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, brain.analyze_symbol_detailed, symbol)
        await msg.edit_text(res, parse_mode='HTML')
    except Exception as e:
        await msg.edit_text(f"❌ Hata: {e}")

async def favori_ekle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return
    symbol = context.args[0].upper().replace('—', '-').replace('–', '-')
    if 'favorites' not in context.user_data: context.user_data['favorites'] = []
    
    if symbol not in context.user_data['favorites']:
        context.user_data['favorites'].append(symbol)
        await update.message.reply_text(f"✅ {symbol} eklendi.")
    else:
        await update.message.reply_text(f"ℹ️ {symbol} zaten listede.")

async def favori_liste(update: Update, context: ContextTypes.DEFAULT_TYPE):
    favs = context.user_data.get('favorites', [])
    await update.message.reply_text(f"📋 <b>Liste:</b>\n" + ", ".join(favs), parse_mode='HTML')

async def durum(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime = int((time.time() - app.config['START_TIME']) / 60)
    await update.message.reply_text(f"⏱ Uptime: {uptime} dk | Tarama: {scan_stats['total']}")

async def yardim(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Komutlar: /start, /analiz, /favori, /liste, /durum")

# ═══════════════════════════════════════════════════════════════
# 6. MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════
def main():
    keep_alive()
    
    if not TOKEN:
        logger.error("❌ Token yok!")
        return

    # JobQueue'yu BURADA MANUEL OLUŞTURUYORUZ (KESİN ÇÖZÜM)
    app_builder = ApplicationBuilder().token(TOKEN)
    # JobQueue'yu explicitly ekliyoruz
    app_builder.job_queue(JobQueue()) 
    application = app_builder.build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("analiz", analiz))
    application.add_handler(CommandHandler("favori", favori_ekle))
    application.add_handler(CommandHandler("liste", favori_liste))
    application.add_handler(CommandHandler("durum", durum))
    application.add_handler(CommandHandler("yardim", yardim))
    
    logger.info("✅ Bot başlatılıyor...")
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()
