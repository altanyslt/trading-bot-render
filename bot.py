"""
═══════════════════════════════════════════════════════════════
ALGORITMIK TRADING BOT - RENDER.COM OPTIMIZED VERSION
═══════════════════════════════════════════════════════════════
Özellikler:
- Multi-timeframe analiz (1d + 4h)
- RSI, MACD, Bollinger Band indikatörleri
- Otomatik tarama (15 dakika aralıkla)
- Telegram entegrasyonu
- Cache mekanizması (5 dakika TTL)
- Flask Keep-Alive (Render sleep önleme)
- Hata toleranslı yapı
- Memory leak koruması
- Async/Sync hybrid architecture

Gereksinimler:
- Python 3.9+
- Render.com ücretsiz plan
- Telegram Bot Token
- UptimeRobot (keep-alive için)
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
import requests  # ← YENİ: User-Agent için gerekli

from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

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

# Flask loglarını kapat (gürültü önleme)
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# ═══════════════════════════════════════════════════════════════
# 2. FLASK KEEP-ALIVE MECHANISM
# ═══════════════════════════════════════════════════════════════
app = Flask(__name__)
app.config['START_TIME'] = time.time()

@app.route('/')
def home():
    """Ana endpoint - Bot durumu"""
    uptime_seconds = time.time() - app.config['START_TIME']
    uptime_minutes = int(uptime_seconds / 60)
    uptime_hours = int(uptime_minutes / 60)
    
    return f"""
    <html>
    <head><title>Trading Bot Status</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h1>🤖 Trading Bot is Running</h1>
        <p><strong>Status:</strong> <span style="color: green;">ACTIVE</span></p>
        <p><strong>Uptime:</strong> {uptime_hours}h {uptime_minutes % 60}m</p>
        <p><strong>Scan Counter:</strong> {scan_stats.get('total', 0)}</p>
        <p><strong>Last Scan:</strong> {scan_stats.get('last_scan', 'Not started')}</p>
        <p><strong>Signals Sent:</strong> {scan_stats.get('signals_sent', 0)}</p>
    </body>
    </html>
    """

@app.route('/health')
def health():
    """Health check endpoint (UptimeRobot için)"""
    return jsonify({
        'status': 'ok',
        'uptime': int(time.time() - app.config['START_TIME']),
        'timestamp': datetime.now().isoformat(),
        'scans': scan_stats.get('total', 0)
    })

@app.route('/stats')
def stats():
    """İstatistikler endpoint"""
    return jsonify(scan_stats)

def run_flask():
    """Flask sunucusunu başlat"""
    port = int(os.environ.get("PORT", 8080))
    try:
        app.run(host='0.0.0.0', port=port, threaded=True, use_reloader=False)
    except Exception as e:
        logger.error(f"Flask hatası: {e}")

def keep_alive():
    """Keep-Alive thread başlatıcı"""
    t = Thread(target=run_flask, daemon=True)
    t.start()
    logger.info(f"✅ Flask Keep-Alive başlatıldı (Port: {os.environ.get('PORT', 8080)})")

# ═══════════════════════════════════════════════════════════════
# 3. GLOBAL SETTINGS & CONSTANTS
# ═══════════════════════════════════════════════════════════════
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
SCAN_INTERVAL = 900  # 15 dakika (Render free plan için optimal)
MAX_SYMBOLS_PER_SCAN = 8  # CPU koruması
CACHE_TTL = 300  # 5 dakika cache yaşam süresi
NIGHT_MODE_START = 23  # Gece modu başlangıç saati
NIGHT_MODE_END = 9  # Gece modu bitiş saati

# Default favori listesi
DEFAULT_FAVORITES = [
    "ASELS.IS", "THYAO.IS", "SASA.IS", 
    "BTC-USD", "ETH-USD", "XU100.IS","TAVHL.IS","ENJSA.IS","FROTO.IS","GARAN.IS","MGROS.IS","BIMAS.IS","SDTTR.IS","AAPL","NVDA","KCHOL.IS","ENKAI.IS",
    "TUPRS.IS","GUBRF.IS","TTRAK.IS","TOASO.IS","TABGD.IS","GOOGL","MSFT","AMZN","META","TSLA","ADSK","INTC","ADBE","QCOM","BA","KO"
]

# İstatistik takibi
scan_stats = {
    'total': 0,
    'signals_sent': 0,
    'last_scan': None,
    'errors': 0
}

# ═══════════════════════════════════════════════════════════════
# 4. TRADING BRAIN CLASS
# ═══════════════════════════════════════════════════════════════
class TradingBrain:
    """
    Ana analiz motoru
    - Multi-timeframe analiz
    - Cache mekanizması
    - Hata toleranslı yapı
    """
    
    def __init__(self):
        self.timeframes = {
            '1d': {'period': '1y', 'interval': '1d', 'weight': 40},
            '4h': {'period': '6mo', 'interval': '60m', 'weight': 60}
        }
        self.cache = {}  # {key: (data, timestamp)}
        self.cache_ttl = CACHE_TTL
        logger.info("✅ TradingBrain initialized")
    
    def clean_cache(self):
        """Eski cache kayıtlarını temizle (memory leak önleme)"""
        now = time.time()
        before = len(self.cache)
        self.cache = {
            k: v for k, v in self.cache.items() 
            if now - v[1] < self.cache_ttl * 2  # 2x TTL sonra temizle
        }
        after = len(self.cache)
        if before != after:
            logger.debug(f"🗑️ Cache temizlendi: {before} → {after}")
    
    def get_data(self, symbol, timeframe):
        """
        Veri çekme fonksiyonu - ANTI-BLOCK VERSION
        - Cache kontrolü
        - User-Agent spoofing (Yahoo Finance engel bypass)
        - Timeout koruması
        - Hata yönetimi
        """
        cache_key = f"{symbol}_{timeframe}"
        now = time.time()
        
        # Cache kontrolü
        if cache_key in self.cache:
            data, timestamp = self.cache[cache_key]
            if now - timestamp < self.cache_ttl:
                logger.debug(f"📦 Cache hit: {cache_key}")
                return data
        
        try:
            config = self.timeframes[timeframe]
            
            # 🛡️ ANTI-BLOCK: User-Agent Spoofing
            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            })
            
            logger.debug(f"🌐 API request: {symbol} ({timeframe})")
            
            # KRITIK: threads=False Render için zorunlu!
            df = yf.download(
                symbol, 
                period=config['period'], 
                interval=config['interval'], 
                progress=False, 
                auto_adjust=False, 
                threads=False,  # Render CPU çakışma önleme
                timeout=15,     # Timeout artırıldı
                session=session # Sahte browser kimliği
            )
            
            # Multi-index kontrolü
            if isinstance(df.columns, pd.MultiIndex): 
                df.columns = df.columns.get_level_values(0)
            
            # Veri validasyonu
            if df.empty or len(df) < 20: 
                logger.warning(f"⚠️ Yetersiz veri: {symbol} ({len(df)} bar)")
                return None
            
            # Cache'e kaydet
            self.cache[cache_key] = (df, now)
            logger.debug(f"💾 Cache saved: {cache_key}")
            
            return df
            
        except Exception as e:
            logger.error(f"❌ Veri hatası ({symbol} - {timeframe}): {str(e)[:100]}")
            return None
    
    def calculate_indicators(self, df):
        """
        Teknik indikatör hesaplama
        - RSI (14)
        - MACD (12, 26, 9)
        - Bollinger Bands (20, 2)
        """
        if df is None or len(df) < 20: 
            return None
        
        try:
            close = df['Close']
            
            # RSI
            df['rsi'] = ta.momentum.RSIIndicator(close, window=14).rsi()
            
            # MACD
            macd = ta.trend.MACD(close, window_slow=26, window_fast=12, window_sign=9)
            df['macd'] = macd.macd()
            df['macd_signal'] = macd.macd_signal()
            
            # Bollinger Bands
            bb = ta.volatility.BollingerBands(close, window=20, window_dev=2)
            df['bb_pct'] = bb.bollinger_pband()
            
            return df
            
        except Exception as e:
            logger.error(f"❌ İndikatör hatası: {str(e)[:100]}")
            return None
    
    def analyze_symbol_score_only(self, symbol):
        """
        Sadece skor hesaplama (otomatik tarama için)
        Return: float score veya None (hata durumunda)
        """
        total_score = 0
        valid_data = False
        
        for tf_name, config in self.timeframes.items():
            df = self.get_data(symbol, tf_name)
            df = self.calculate_indicators(df)
            
            if df is None or len(df) < 2:
                continue
            
            valid_data = True
            curr = df.iloc[-1]
            prev = df.iloc[-2]
            score = 0
            
            # RSI Analizi
            rsi = curr.get('rsi')
            if pd.notna(rsi):
                if rsi <= 30: 
                    score += 2  # Aşırı satım
                elif rsi >= 70: 
                    score -= 2  # Aşırı alım
            
            # MACD Kesişim Analizi
            macd_val = curr.get('macd')
            macd_sig = curr.get('macd_signal')
            prev_macd = prev.get('macd')
            prev_sig = prev.get('macd_signal')
            
            if all(pd.notna(x) for x in [macd_val, macd_sig, prev_macd, prev_sig]):
                # Golden Cross (pozitif kesişim)
                if macd_val > macd_sig and prev_macd <= prev_sig:
                    score += 2
                # Death Cross (negatif kesişim)
                elif macd_val < macd_sig and prev_macd >= prev_sig:
                    score -= 2
                # Basit pozisyon
                elif macd_val > macd_sig:
                    score += 1
                else:
                    score -= 1
            
            # Bollinger Band Analizi
            bb_pct = curr.get('bb_pct')
            if pd.notna(bb_pct):
                if bb_pct < 0.1: 
                    score += 1  # Alt banda yakın
                elif bb_pct > 0.9: 
                    score -= 1  # Üst banda yakın
            
            # Ağırlıklı skor
            weighted_score = score * (config['weight'] / 100)
            total_score += weighted_score
            
            logger.debug(f"  {symbol} {tf_name}: {score} (weighted: {weighted_score:.2f})")
        
        if not valid_data:
            return None
        
        return round(total_score, 2)
    
    def analyze_symbol_detailed(self, symbol):
        """
        Detaylı analiz (manuel komut için)
        Return: string (formatlanmış mesaj)
        """
        score = self.analyze_symbol_score_only(symbol)
        
        if score is None:
            return f"❌ <b>{symbol}</b>\n\nVeri alınamadı veya yetersiz veri."
        
        # Karar belirleme
        if score >= 2.5:
            decision = "🚀 GÜÇLÜ ALIM"
            emoji = "🚀"
        elif score >= 1.0:
            decision = "🟢 ALIM"
            emoji = "🟢"
        elif score <= -2.5:
            decision = "📉 GÜÇLÜ SATIM"
            emoji = "📉"
        elif score <= -1.0:
            decision = "🔴 SATIM"
            emoji = "🔴"
        else:
            decision = "⚪ BEKLE"
            emoji = "⚪"
        
        return (
            f"📊 <b>{symbol}</b>\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🎯 Skor: <b>{score:+.2f}</b>\n"
            f"{emoji} Karar: <b>{decision}</b>\n\n"
            f"<i>⚠️ Yatırım tavsiyesi değildir!</i>"
        )

# Brain instance oluştur
brain = TradingBrain()

# ═══════════════════════════════════════════════════════════════
# 5. TELEGRAM BOT COMMANDS
# ═══════════════════════════════════════════════════════════════

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bot başlatma komutu"""
    chat_id = update.effective_chat.id
    user_name = update.effective_user.first_name
    
    logger.info(f"🚀 /start komutu - User: {user_name} (ID: {chat_id})")
    
    # Favori listeyi başlat
    if 'favorites' not in context.user_data: 
        context.user_data['favorites'] = DEFAULT_FAVORITES.copy()
    
    await update.message.reply_text(
        f"👋 Merhaba <b>{user_name}!</b>\n\n"
        f"🦅 <b>Trading Bot Aktif</b>\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"✅ 7/24 otomatik tarama başladı\n"
        f"⏰ Her {SCAN_INTERVAL//60} dakikada bir analiz\n"
        f"🎯 Güçlü sinyallerde bildirim gelecek\n\n"
        f"📋 <b>Komutlar:</b>\n"
        f"• /analiz [SEMBOL] - Manuel analiz\n"
        f"• /favori [SEMBOL] - Listeye ekle\n"
        f"• /liste - Favori semboller\n"
        f"• /durum - Bot durumu\n"
        f"• /yardim - Yardım menüsü\n\n"
        f"💡 <b>Örnek:</b> /analiz THYAO.IS",
        parse_mode='HTML'
    )
    
    # Mevcut job'ları temizle (çift başlatma önleme)
    current_jobs = context.job_queue.get_jobs_by_name(f'auto_scan_{chat_id}')
    for job in current_jobs: 
        job.schedule_removal()
    
    # Otomatik taramayı başlat
    context.job_queue.run_repeating(
        otomatik_tarama, 
        interval=SCAN_INTERVAL, 
        first=10,  # 10 saniye sonra ilk tarama
        chat_id=chat_id, 
        name=f'auto_scan_{chat_id}',
        data=context.user_data
    )
    
    logger.info(f"✅ Otomatik tarama başlatıldı - Chat ID: {chat_id}")

async def otomatik_tarama(context: ContextTypes.DEFAULT_TYPE):
    """
    Otomatik periyodik tarama fonksiyonu
    - Her SCAN_INTERVAL'da bir çalışır
    - Gece modunda çalışmaz
    - Güçlü sinyallerde bildirim gönderir
    """
    job = context.job
    user_data = job.data
    favorites = user_data.get('favorites', DEFAULT_FAVORITES)
    chat_id = job.chat_id
    
    # İstatistik güncelle
    scan_stats['total'] = scan_stats.get('total', 0) + 1
    scan_stats['last_scan'] = datetime.now(pytz.timezone('Europe/Istanbul')).strftime('%H:%M:%S')
    
    # Gece sessiz modu kontrolü
    now = datetime.now(pytz.timezone('Europe/Istanbul'))
    if NIGHT_MODE_START <= now.hour or now.hour < NIGHT_MODE_END: 
        logger.info(f"😴 Gece modu aktif ({now.hour}:00) - Tarama atlandı")
        return
    
    # Sembol limitini uygula
    symbols_to_scan = favorites[:MAX_SYMBOLS_PER_SCAN]
    
    logger.info(f"⏰ Tarama #{scan_stats['total']} başladı - {len(symbols_to_scan)} sembol")
    
    alerts = []
    errors = 0
    
    for idx, symbol in enumerate(symbols_to_scan):
        try:
            # CPU spike önleme (rate limiting)
            if idx > 0:
                await asyncio.sleep(2)
            
            # Analiz yap (async-safe wrapper)
            loop = asyncio.get_running_loop()
            score = await loop.run_in_executor(
                None, 
                brain.analyze_symbol_score_only, 
                symbol
            )
            
            if score is None:
                logger.warning(f"⚠️ {symbol}: Veri yok")
                errors += 1
                continue
            
            # Sadece güçlü sinyallerde alert
            if score >= 2.0: 
                alerts.append(f"🚀 <b>{symbol}</b>: GÜÇLÜ ALIM ({score:+.1f})")
                logger.info(f"🚀 SINYAL: {symbol} = {score:+.2f}")
            elif score <= -2.0: 
                alerts.append(f"📉 <b>{symbol}</b>: GÜÇLÜ SATIM ({score:+.1f})")
                logger.info(f"📉 SINYAL: {symbol} = {score:+.2f}")
            else:
                logger.debug(f"  {symbol}: {score:+.2f} (sinyal yok)")
            
        except Exception as e:
            logger.error(f"❌ Tarama hatası ({symbol}): {str(e)[:100]}")
            errors += 1
            scan_stats['errors'] = scan_stats.get('errors', 0) + 1
            continue
    
    # Cache temizliği (her 10 taramada bir)
    if scan_stats['total'] % 10 == 0:
        brain.clean_cache()
    
    # Bildirim gönder
    if alerts:
        msg = (
            f"🚨 <b>SİNYAL ALGILANDI</b>\n"
            f"🕐 {now.strftime('%d.%m.%Y %H:%M')}\n"
            f"━━━━━━━━━━━━━━━━\n" + 
            "\n".join(alerts) +
            f"\n\n<i>💡 /analiz [SEMBOL] ile detay alabilirsin</i>"
        )
        try:
            await context.bot.send_message(
                chat_id, 
                text=msg, 
                parse_mode='HTML'
            )
            scan_stats['signals_sent'] = scan_stats.get('signals_sent', 0) + 1
            logger.info(f"✅ {len(alerts)} sinyal gönderildi")
        except Exception as e:
            logger.error(f"❌ Telegram mesaj hatası: {e}")
    else:
        logger.info(f"ℹ️ Tarama tamamlandı - Sinyal yok (Hata: {errors})")

async def analiz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manuel analiz komutu"""
    if not context.args:
        await update.message.reply_text(
            "❌ <b>Kullanım:</b> /analiz [SEMBOL]\n\n"
            "📝 <b>Örnekler:</b>\n"
            "• /analiz THYAO.IS\n"
            "• /analiz BTC-USD\n"
            "• /analiz AAPL\n\n"
            "💡 <b>İpucu:</b> BIST hisseleri için .IS eki kullan",
            parse_mode='HTML'
        )
        return
    
    symbol = context.args[0].upper()
    user_name = update.effective_user.first_name
    
    logger.info(f"🔍 /analiz komutu - User: {user_name}, Symbol: {symbol}")
    
    status_msg = await update.message.reply_text(
        f"🔍 <b>{symbol}</b> analiz ediliyor...\n"
        f"⏳ Lütfen bekleyin...",
        parse_mode='HTML'
    )
    
    try:
        # Async wrapper
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, 
            brain.analyze_symbol_detailed, 
            symbol
        )
        
        await status_msg.edit_text(result, parse_mode='HTML')
        logger.info(f"✅ Analiz tamamlandı: {symbol}")
        
    except Exception as e:
        error_msg = (
            f"❌ <b>Hata Oluştu</b>\n\n"
            f"Sembol: {symbol}\n"
            f"Hata: {str(e)[:100]}\n\n"
            f"💡 Sembol formatını kontrol edin:\n"
            f"• BIST: THYAO.IS, ASELS.IS\n"
            f"• Kripto: BTC-USD, ETH-USD\n"
            f"• US: AAPL, TSLA, NVDA"
        )
        await status_msg.edit_text(error_msg, parse_mode='HTML')
        logger.error(f"❌ Analiz hatası ({symbol}): {e}")

async def favori_ekle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Favorilere ekleme komutu"""
    if not context.args:
        await update.message.reply_text(
            "❌ <b>Kullanım:</b> /favori [SEMBOL]\n\n"
            "📝 <b>Örnek:</b> /favori ASELS.IS",
            parse_mode='HTML'
        )
        return
    
    symbol = context.args[0].upper()
    
    if 'favorites' not in context.user_data:
        context.user_data['favorites'] = []
    
    # Limit kontrolü
    if len(context.user_data['favorites']) >= MAX_SYMBOLS_PER_SCAN:
        await update.message.reply_text(
            f"⚠️ <b>Limit Doldu!</b>\n\n"
            f"Maksimum {MAX_SYMBOLS_PER_SCAN} sembol eklenebilir.\n"
            f"Önce /liste ile mevcut sembolleri görün.",
            parse_mode='HTML'
        )
        return
    
    # Duplicate kontrolü
    if symbol in context.user_data['favorites']:
        await update.message.reply_text(
            f"ℹ️ <b>{symbol}</b> zaten listede!",
            parse_mode='HTML'
        )
    else:
        context.user_data['favorites'].append(symbol)
        await update.message.reply_text(
            f"✅ <b>{symbol}</b> listeye eklendi!\n\n"
            f"📊 Toplam: {len(context.user_data['favorites'])}/{MAX_SYMBOLS_PER_SCAN}",
            parse_mode='HTML'
        )
        logger.info(f"✅ Favori eklendi: {symbol}")

async def favori_liste(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Favori listesi gösterme komutu"""
    favorites = context.user_data.get('favorites', [])
    
    if not favorites:
        await update.message.reply_text(
            "📭 <b>Favori listeniz boş</b>\n\n"
            "➕ /favori [SEMBOL] ile ekleyebilirsin!",
            parse_mode='HTML'
        )
    else:
        liste = "\n".join([f"  • {s}" for s in favorites])
        await update.message.reply_text(
            f"📋 <b>Takip Edilen Semboller</b>\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"{liste}\n\n"
            f"Toplam: {len(favorites)}/{MAX_SYMBOLS_PER_SCAN}",
            parse_mode='HTML'
        )

async def durum(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bot durumu gösterme komutu"""
    uptime_seconds = time.time() - app.config['START_TIME']
    uptime_minutes = int(uptime_seconds / 60)
    uptime_hours = int(uptime_minutes / 60)
    
    await update.message.reply_text(
        f"🤖 <b>Bot Durumu</b>\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"✅ Durum: <b>AKTIF</b>\n"
        f"⏱ Uptime: <b>{uptime_hours}s {uptime_minutes % 60}d</b>\n"
        f"🔄 Tarama Sayısı: <b>{scan_stats.get('total', 0)}</b>\n"
        f"📊 Gönderilen Sinyal: <b>{scan_stats.get('signals_sent', 0)}</b>\n"
        f"❌ Hata Sayısı: <b>{scan_stats.get('errors', 0)}</b>\n"
        f"⏰ Son Tarama: <b>{scan_stats.get('last_scan', 'Henüz yok')}</b>\n"
        f"💾 Cache: <b>{len(brain.cache)} kayıt</b>\n"
        f"📋 Takip Edilen: <b>{len(context.user_data.get('favorites', []))}</b>",
        parse_mode='HTML'
    )

async def yardim(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Yardım menüsü"""
    await update.message.reply_text(
        "📖 <b>Komut Listesi</b>\n"
        "━━━━━━━━━━━━━━━━\n\n"
        "<b>/start</b>\n"
        "  Bot'u başlat ve otomatik taramayı aktifleştir\n\n"
        "<b>/analiz [SEMBOL]</b>\n"
        "  Belirtilen sembolü manuel olarak analiz et\n"
        "  Örnek: /analiz THYAO.IS\n\n"
        "<b>/favori [SEMBOL]</b>\n"
        "  Otomatik tarama listesine sembol ekle\n"
        "  Örnek: /favori BTC-USD\n\n"
        "<b>/liste</b>\n"
        "  Takip edilen sembolleri göster\n\n"
        "<b>/durum</b>\n"
        "  Bot istatistiklerini göster\n\n"
        "<b>/yardim</b>\n"
        "  Bu yardım menüsünü göster\n\n"
        "━━━━━━━━━━━━━━━━\n"
        "💡 <b>İpuçları:</b>\n"
        "• BIST hisseleri için .IS eki kullanın\n"
        "• Kripto paralar için -USD kullanın\n"
        "• Bot 7/24 otomatik tarama yapar\n"
        "• Güçlü sinyallerde bildirim alırsınız",
        parse_mode='HTML'
    )

# ═══════════════════════════════════════════════════════════════
# 6. MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════

def main():
    """Ana çalıştırma fonksiyonu"""
    
    logger.info("=" * 60)
    logger.info("🚀 TRADING BOT BAŞLATILIYOR")
    logger.info("=" * 60)
    
    # Keep-Alive başlat
    keep_alive()
    
    # Token kontrolü
    if not TOKEN:
        logger.error("❌ TELEGRAM_BOT_TOKEN bulunamadı!")
        logger.error("💡 Render.com Environment Variables bölümünden ekleyin")
        return
    
    logger.info(f"✅ Token yüklendi: {TOKEN[:10]}...{TOKEN[-5:]}")
    logger.info(f"⏰ Tarama aralığı: {SCAN_INTERVAL} saniye ({SCAN_INTERVAL//60} dakika)")
    logger.info(f"📊 Maksimum sembol: {MAX_SYMBOLS_PER_SCAN}")
    logger.info(f"💾 Cache TTL: {CACHE_TTL} saniye")
    logger.info(f"🌙 Gece modu: {NIGHT_MODE_START}:00 - {NIGHT_MODE_END}:00")
    
    # Bot oluştur
    logger.info("🤖 Telegram bot oluşturuluyor...")
    from telegram.ext import JobQueue
    application = (
        ApplicationBuilder()
        .token(TOKEN)
        .job_queue(JobQueue())
        .build()
    )
    
    # Komut işleyiciler
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("analiz", analiz))
    application.add_handler(CommandHandler("favori", favori_ekle))
    application.add_handler(CommandHandler("liste", favori_liste))
    application.add_handler(CommandHandler("durum", durum))
    application.add_handler(CommandHandler("yardim", yardim))
    
    logger.info("✅ Komut işleyiciler eklendi")
    logger.info("=" * 60)
    logger.info("🎉 BOT AKTIF - Telegram'dan /start ile başlatın!")
    logger.info("=" * 60)
    
    # Polling başlat
    try:
        application.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True  # Eski mesajları görmezden gel
        )
    except KeyboardInterrupt:
        logger.info("⚠️ Bot durduruldu (KeyboardInterrupt)")
    except Exception as e:
        logger.error(f"❌ Kritik hata: {e}")
        raise

if __name__ == '__main__':
    main()
