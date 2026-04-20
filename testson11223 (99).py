import os
import re
import json
import html
import logging
import datetime
import time
import hashlib
import requests
import base64
import uuid
import random
import threading
from collections import deque
from flask import Flask, render_template_string, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client
import boto3
from botocore.config import Config

# ==============================================================================
# GOOGLE PLAY IAP — Kütüphane importları
# Gerekli kurulum: pip install google-auth google-api-python-client
# ==============================================================================
try:
    import google.oauth2.service_account as gsa
    from googleapiclient.discovery import build as gapi_build
    GOOGLE_API_AVAILABLE = True
except ImportError:
    GOOGLE_API_AVAILABLE = False
    logging.getLogger("freeridertr").warning(
        "Google API kütüphaneleri eksik. "
        "Kurulum: pip install google-auth google-api-python-client"
    )

# ==============================================================================
# PROFESYONEL LOGLAMA SİSTEMİ
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("freeridertr")

ONESIGNAL_APP_ID  = os.environ.get("ONESIGNAL_APP_ID")
ONESIGNAL_API_KEY = os.environ.get("ONESIGNAL_API_KEY")
ONESIGNAL_API_URL = "https://onesignal.com/api/v1/notifications"

# ==============================================================================
# TUM API ANAHTARLARI BURADA TOPLU TANIMLANIR
# URETIM: Asagidaki tum degerleri environment variable olarak set edin!
# Eksik anahtarlar icin uygulama guvenli sekilde hata verir.
# ==============================================================================
GROQ_API_KEY   = os.environ.get("GROQ_API_KEY")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")

# Zorunlu anahtarlar — eksikse uygulama baslamaz
_REQUIRED_ENVS = [
    "SUPABASE_URL",
    "SUPABASE_KEY",
    "FLASK_SECRET_KEY",
    "ADMIN_PASSWORD",
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
]

# Opsiyonel anahtarlar — eksikse ilgili özellik devre dışı kalır
_OPTIONAL_ENVS = [
    "ONESIGNAL_APP_ID",
    "ONESIGNAL_API_KEY",
    "GROQ_API_KEY",
    "RESEND_API_KEY",
    "R2_ENDPOINT_URL",
    "R2_BUCKET_NAME",
    "R2_PUBLIC_URL",
    # Google Play IAP doğrulaması için gerekli değişkenler
    "GOOGLE_APPLICATION_CREDENTIALS",  # Service account JSON dosyasının yolu
    "GOOGLE_PLAY_PACKAGE_NAME",        # Örn: com.freeridertr.app
]

_missing_required = [k for k in _REQUIRED_ENVS if not os.environ.get(k)]
if _missing_required:
    raise EnvironmentError(
        f"KRITIK HATA: Asagidaki zorunlu environment variable'lar eksik: "
        f"{', '.join(_missing_required)}. "
        f"Uygulama guvenlik nedeniyle baslatilmiyor."
    )

_missing_optional = [k for k in _OPTIONAL_ENVS if not os.environ.get(k)]
if _missing_optional:
    print(f"UYARI: Su opsiyonel environment variable'lar eksik (ilgili ozellikler devre disi): "
          f"{', '.join(_missing_optional)}")

print("OneSignal yapilandirildi")

# ==============================================================================
# FLASK UYGULAMA AYARLARI VE GÜVENLİK
# ==============================================================================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# Güvenli session ayarları
# DÜZELTME #1: SESSION_COOKIE_SECURE yalnızca production (HTTPS) ortamında aktif olmalı.
# True olarak bırakılırsa HTTP üzerinden çalışan ortamlarda (lokal, bazı hosting)
# tarayıcı cookie'yi HİÇ göndermez → tüm POST istekleri sessizce başarısız olur.
app.config['SESSION_COOKIE_SECURE']   = not app.debug  # HTTP'de False, HTTPS'de True
app.config['SESSION_COOKIE_HTTPONLY'] = True   # JS erişimi engelle
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF koruması
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)

app.config['MAX_CONTENT_LENGTH'] = 75 * 1024 * 1024  # 75 MB — 50MB video base64 kodlandığında ~67MB olur
MAX_PAYLOAD_SIZE = 75 * 1024 * 1024

# 413 hatası için özel handler
@app.errorhandler(413)
def too_large(e):
    return jsonify({'status': 'error', 'message': 'Dosya çok büyük! Video için maks. 50MB, fotoğraf için maks. 5MB.'}), 413

# Admin şifresi — environment variable'dan al
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# ==============================================================================
# JSON TABANLI KALICI RATE LIMITER
# Sunucu yeniden başlatıldığında veri kaybolmaz.
# ==============================================================================
_RATE_STORE_PATH = os.path.join(os.environ.get("RATE_STORE_DIR", "/tmp"), "freerider_rate_store.json")
_rate_store: dict = {}
_rate_lock  = threading.Lock()

def _load_rate_store_from_disk():
    """Uygulama başlangıcında JSON dosyasını okur, süresi geçmiş kayıtları atar."""
    global _rate_store
    try:
        with open(_RATE_STORE_PATH, "r") as f:
            raw = json.load(f)
        now = time.time()
        _rate_store = {k: tuple(v) for k, v in raw.items() if now - v[1] <= 600}
        logger.info(f"Rate store yüklendi: {len(_rate_store)} aktif kayıt.")
    except FileNotFoundError:
        _rate_store = {}
    except Exception as exc:
        logger.warning(f"Rate store okunamadı, sıfırlanıyor: {exc}")
        _rate_store = {}

def _persist_rate_store():
    """Rate store'u diske yazar (kilit içinde çağrılmalı)."""
    try:
        with open(_RATE_STORE_PATH, "w") as f:
            json.dump(_rate_store, f)
    except Exception as exc:
        logger.warning(f"Rate store yazılamadı: {exc}")

_load_rate_store_from_disk()

def _rate_key(ip: str, action: str) -> str:
    return f"{ip}:{action}"

def rate_check(ip: str, action: str, max_calls: int, window_sec: int) -> bool:
    """True → izin ver, False → limit aşıldı."""
    key = _rate_key(ip, action)
    now = time.time()
    with _rate_lock:
        calls, window_start = _rate_store.get(key, (0, now))
        if now - window_start > window_sec:
            calls, window_start = 0, now
        if calls >= max_calls:
            return False
        _rate_store[key] = (calls + 1, window_start)
        _persist_rate_store()
    return True

# Periyodik temizlik (bellek sızıntısı ve şişen dosya önleme)
def _cleanup_rate_store():
    while True:
        time.sleep(300)
        now = time.time()
        with _rate_lock:
            expired = [k for k, (_, t) in _rate_store.items() if now - t > 600]
            for k in expired:
                del _rate_store[k]
            if expired:
                _persist_rate_store()
                logger.debug(f"Rate store temizlendi: {len(expired)} süresi dolmuş kayıt kaldırıldı.")

threading.Thread(target=_cleanup_rate_store, daemon=True).start()

# ==============================================================================
# SENİ ÖZLEDİK BİLDİRİM SİSTEMİ
# Her 30 dakikada kontrol: 10+ saat girmeyen kullanıcılara özel bildirim
# ==============================================================================
_MISS_YOU_MESSAGES = [
    ("😢 Seni özledik {name}!", "FreeriderTR topluluğu seni bekliyor. Bugün bir rota paylaş! 🏔️"),
    ("🏔️ {name}, rotalar seni çağırıyor!", "Uzun süredir ortalarda yoksun. Bugün ne sürüyorsun?"),
    ("🚴 {name} neredesin?", "Topluluk aktif! Yeni rampalar, buluşmalar ve sohbetler seni bekliyor."),
    ("⚡ {name}, günlük çarkını çevirmek istemez misin?", "Bugün ödüllü çark çevirme hakkın var! Kaçırma 🎡"),
    ("🏆 {name}, sıralamada yerinizi koruyun!", "Liderlik tablosunda aktif olmak XP kazandırır. Geri dön!"),
    ("🔥 {name}, yeni içerikler seni bekliyor!", "Reels, haberler ve yeni harita noktaları eklendi."),
    ("💬 {name}, sohbet kaçırıyorsun!", "Topluluk konuşuyor. Sen de katıl, fikrin önemli!"),
    ("🎯 {name}, görevlerin süresi doluyor!", "Tamamlanmamış görevlerin var. XP kazanmak için geri dön."),
    ("📍 {name}, yeni rampalar eklendi!", "Haritada yeni keşfedilmemiş noktalar var. İncele!"),
    ("👑 {name}, senin döndüğünü merak edenler var!", "Topluluğun en değerli üyelerinden birisin. Dön!"),
]

_CHAT_BROADCAST_LOCK = threading.Lock()
_last_chat_broadcast_ts = 0   # son grup chat broadcastinin zamanı
CHAT_BROADCAST_COOLDOWN = 180  # 3 dakika — aşırı bildirim önleme

def _can_broadcast_chat():
    """Grup chat bildirimi için flood kontrolü (3 dk cooldown)."""
    global _last_chat_broadcast_ts
    now = time.time()
    with _CHAT_BROADCAST_LOCK:
        if now - _last_chat_broadcast_ts >= CHAT_BROADCAST_COOLDOWN:
            _last_chat_broadcast_ts = now
            return True
    return False

def _miss_you_worker():
    """Her 30 dakikada 10–11 saat önce görülen kullanıcılara bildirim gönderir.
    Supabase JSONB filtresiyle yalnızca ilgili satırlar çekilir — tam tablo taraması yapılmaz."""
    while True:
        time.sleep(1800)  # 30 dakika bekle
        if not supabase:
            continue
        try:
            now_ts       = int(time.time())
            ten_h_ago    = now_ts - 36000   # 10 saat
            eleven_h_ago = now_ts - 39600   # 11 saat
            one_day_ago  = now_ts - 86400   # 24 saat

            # Supabase JSONB filtresi: stats->>'last_seen_ts' penceresi [11h, 10h]
            # Sadece username, name, stats sütunları çekilir — gereksiz veri aktarımı önlenir.
            try:
                res = (
                    supabase.table("users")
                    .select("username, name, stats")
                    .filter("stats->>last_seen_ts", "gte", str(eleven_h_ago))
                    .filter("stats->>last_seen_ts", "lte", str(ten_h_ago))
                    .execute()
                )
                candidates = res.data or []
            except Exception as exc:
                # JSONB filtresi desteklenmiyorsa (eski Supabase sürümü) sadece uyarı ver
                logger.warning(f"Miss-you JSONB filtre hatası, çalıştırma atlandı: {exc}")
                continue

            sent_count = 0
            for u in candidates:
                try:
                    uname         = u.get("username", "")
                    uname_display = (u.get("name") or uname)[:20]
                    st = u.get("stats") or {}
                    if isinstance(st, str):
                        try:
                            st = json.loads(st)
                        except json.JSONDecodeError:
                            st = {}

                    last_miss = st.get("last_miss_notif_ts", 0)
                    # Son 24 saatte miss-you gönderilmemişse gönder
                    if now_ts - last_miss <= one_day_ago:
                        continue

                    title_tpl, body_tpl = random.choice(_MISS_YOU_MESSAGES)
                    send_push_to_user(
                        uname,
                        title=title_tpl.format(name=uname_display),
                        body=body_tpl,
                        url="/",
                    )
                    st["last_miss_notif_ts"] = now_ts
                    supabase.table("users").update({"stats": st}).eq("username", uname).execute()
                    sent_count += 1
                    time.sleep(0.1)  # API rate limit
                except Exception as exc:
                    logger.warning(f"Miss-you tekil gönderim hatası ({u.get('username','?')}): {exc}", exc_info=True)

            if sent_count:
                logger.info(f"💌 Seni özledik: {sent_count} kullanıcıya bildirim gönderildi.")
        except Exception as exc:
            logger.error(f"Miss-you worker beklenmedik hata: {exc}", exc_info=True)

threading.Thread(target=_miss_you_worker, daemon=True).start()
print("💌 'Seni Özledik' bildirim sistemi başlatıldı")

# ==============================================================================
# GÜVENLİK BAŞLIKLARI (Security Headers)
# ==============================================================================
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']         = 'SAMEORIGIN'
    response.headers['X-XSS-Protection']        = '1; mode=block'
    response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']      = 'geolocation=(self), microphone=(self), camera=(self)'
    # HSTS — HTTPS zorunlu (production'da aktif)
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ==============================================================================
# RESEND API ENTEGRASYONU (ŞİFRE SIFIRLAMA VE DOĞRULAMA)
# ==============================================================================
def send_resend_email(to_email, subject, html_content):
    if not RESEND_API_KEY:
        print("⚠️ Email gönderilemedi: RESEND_API_KEY environment variable eksik.")
        return False
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "from":"FreeriderTR <iletisim@freeridertr.com.tr>",
        "to": [to_email],
        "subject": subject,
        "html": html_content
    }
    try:
        resp = requests.post("https://api.resend.com/emails", json=data, headers=headers, timeout=10)
        if resp.status_code not in (200, 201, 202):
            print(f"⚠️ Email gönderilemedi ({resp.status_code}): {resp.text[:200]}")
            return False
        return True
    except Exception as e:
        print("Email gönderme hatası:", e)
        return False

# ==============================================================================
# SUPABASE VERİTABANI BAĞLANTISI
# ==============================================================================
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("===================================================")
    print("🚀 SUPABASE BAĞLANTISI BAŞARILI!")
    print("🚀 SİSTEM: FREERIDER PLUS V7.0 (HAFTALIK YARIŞ & SOSYAL MEDYA EDITION)")
    print("===================================================")
except Exception as e:
    print("❌ SUPABASE BAĞLANTI HATASI YAŞANDI:", e)
    supabase = None

# ==============================================================================
# CLOUDFLARE R2 BAĞLANTISI
# ==============================================================================
R2_ACCESS_KEY_ID     = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_ENDPOINT_URL      = os.environ.get("R2_ENDPOINT_URL")
R2_BUCKET_NAME       = os.environ.get("R2_BUCKET_NAME",       "freeridertr")
R2_PUBLIC_URL        = os.environ.get("R2_PUBLIC_URL")

if R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY and R2_ENDPOINT_URL:
    r2_client = boto3.client(
        service_name='s3',
        endpoint_url=R2_ENDPOINT_URL,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        region_name="auto",
        config=Config(signature_version='s3v4')
    )
else:
    r2_client = None
    logger.warning("R2 depolama devre dışı: R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY veya R2_ENDPOINT_URL eksik.")

# ==============================================================================
# R2 VARLIK TEMİZLEME — Google Play hesap silme zorunluluğu
# ==============================================================================
def delete_user_assets(username: str) -> dict:
    """Kullanıcıya ait R2 üzerindeki tüm medya dosyalarını siler.
    Supabase'deki URL'leri tarayarak gerçek key'leri çıkarır, toplu silme yapar.
    Dönen dict: {'deleted': int, 'failed': int, 'skipped': int}"""
    result = {'deleted': 0, 'failed': 0, 'skipped': 0}
    if not r2_client or not supabase:
        logger.warning(f"delete_user_assets: R2 veya Supabase eksik, {username} varlıkları atlandı.")
        result['skipped'] = -1
        return result

    cdn_base = (R2_PUBLIC_URL or "").rstrip("/")
    r2_keys: list[str] = []

    def _extract_keys_from_url_fields(rows: list, *fields):
        """Verilen satır listesinden URL alanlarını tarar, R2 key'i çıkarır."""
        for row in rows:
            for field in fields:
                val = row.get(field)
                if not val:
                    continue
                urls = val if isinstance(val, list) else [val]
                for url in urls:
                    if isinstance(url, str) and cdn_base and url.startswith(cdn_base):
                        key = url[len(cdn_base):].lstrip("/")
                        if key:
                            r2_keys.append(key)

    # Profil avatarı
    try:
        u_res = supabase.table('users').select('avatar').eq('username', username).execute()
        _extract_keys_from_url_fields(u_res.data or [], 'avatar')
    except Exception as exc:
        logger.warning(f"delete_user_assets: avatar sorgu hatası: {exc}")

    # Reel medyaları
    try:
        reels_res = supabase.table('reels').select('media_url').eq('user', username).execute()
        _extract_keys_from_url_fields(reels_res.data or [], 'media_url')
    except Exception as exc:
        logger.warning(f"delete_user_assets: reels sorgu hatası: {exc}")

    # Mesaj fotoğrafları / sesleri
    try:
        msgs_res = supabase.table('messages').select('photo, voice').eq('user', username).execute()
        _extract_keys_from_url_fields(msgs_res.data or [], 'photo', 'voice')
    except Exception as exc:
        logger.warning(f"delete_user_assets: messages sorgu hatası: {exc}")

    # Harita marker fotoğrafları
    try:
        mk_res = supabase.table('markers').select('photos').eq('addedBy', username).execute()
        _extract_keys_from_url_fields(mk_res.data or [], 'photos')
    except Exception as exc:
        logger.warning(f"delete_user_assets: markers sorgu hatası: {exc}")

    # Market ilanı fotoğrafları
    try:
        mkt_res = supabase.table('market').select('photos').eq('owner', username).execute()
        _extract_keys_from_url_fields(mkt_res.data or [], 'photos')
    except Exception as exc:
        logger.warning(f"delete_user_assets: market sorgu hatası: {exc}")

    # Stats içindeki garage bisiklet fotoğrafları
    try:
        st_res = supabase.table('users').select('stats').eq('username', username).execute()
        if st_res.data:
            st = st_res.data[0].get('stats') or {}
            if isinstance(st, str):
                try: st = json.loads(st)
                except json.JSONDecodeError: st = {}
            garage = st.get('garage', [])
            for bike in (garage if isinstance(garage, list) else []):
                _extract_keys_from_url_fields([bike], 'photos', 'cover')
    except Exception as exc:
        logger.warning(f"delete_user_assets: stats/garage sorgu hatası: {exc}")

    if not r2_keys:
        logger.info(f"delete_user_assets: {username} için silinecek R2 varlığı bulunamadı.")
        return result

    # R2 delete_objects: maks 1000 key/istek
    unique_keys = list(dict.fromkeys(r2_keys))  # sıra koruyarak deduplicate
    for i in range(0, len(unique_keys), 1000):
        batch = unique_keys[i:i + 1000]
        objects = [{"Key": k} for k in batch]
        try:
            resp = r2_client.delete_objects(
                Bucket=R2_BUCKET_NAME,
                Delete={"Objects": objects, "Quiet": True}
            )
            errors = resp.get("Errors", [])
            deleted = len(batch) - len(errors)
            result['deleted'] += deleted
            result['failed']  += len(errors)
            if errors:
                for err in errors:
                    logger.warning(f"R2 silme hatası: key={err.get('Key')} msg={err.get('Message')}")
        except Exception as exc:
            logger.error(f"delete_user_assets: batch silme hatası: {exc}", exc_info=True)
            result['failed'] += len(batch)

    logger.info(f"delete_user_assets: {username} → silindi={result['deleted']}, hata={result['failed']}")
    return result

def init_db():
    """Uygulama başlangıcında zorunlu settings kayıtlarını ve admin_logs tablosunu kontrol eder.
    Kritik tablo yoksa ya oluşturmayı dener ya da EnvironmentError fırlatır."""
    if not supabase:
        logger.error("init_db: Supabase bağlantısı yok, başlatma atlandı.")
        return

    # ── settings tablosu varsayılan kayıtları ──────────────────────────────────
    _defaults = {
        'maintenance':      'false',
        'pinned_message':   '{}',
    }
    for key, default_val in _defaults.items():
        try:
            chk = supabase.table('settings').select('id').eq('id', key).execute()
            if not chk.data:
                supabase.table('settings').insert({"id": key, "value": default_val}).execute()
                logger.info(f"init_db: settings[{key}] varsayılan değerle oluşturuldu.")
        except Exception as exc:
            logger.error(f"init_db: settings[{key}] kontrolü başarısız: {exc}", exc_info=True)
            raise EnvironmentError(f"init_db kritik hata — settings tablosu erişilemiyor: {exc}") from exc

    # ── total_users_count ──────────────────────────────────────────────────────
    try:
        uc_check = supabase.table('settings').select('id').eq('id', 'total_users_count').execute()
        if not uc_check.data:
            try:
                real_count = len(supabase.table('users').select('username').execute().data or [])
            except Exception as _exc:
                real_count = 0
            base_count = max(300, 300 + real_count)
            supabase.table('settings').insert({"id": "total_users_count", "value": str(base_count)}).execute()
            logger.info(f"init_db: total_users_count başlatıldı → {base_count}")
    except EnvironmentError:
        raise
    except Exception as exc:
        logger.error(f"init_db: total_users_count hatası: {exc}", exc_info=True)

    # ── admin_logs tablosu ─────────────────────────────────────────────────────
    try:
        supabase.table('admin_logs').select('id').limit(1).execute()
    except Exception as exc:
        # Supabase REST üzerinden CREATE TABLE yapılamaz; DDL'yi logla ve kritik hata ver
        _ddl = (
            "CREATE TABLE IF NOT EXISTS admin_logs ("
            "  id text PRIMARY KEY,"
            "  admin text,"
            "  action text,"
            "  target text,"
            "  detail text,"
            "  ts bigint"
            ");"
        )
        logger.critical(
            f"init_db: 'admin_logs' tablosuna erişilemiyor. "
            f"Supabase SQL Editöründe şu DDL'yi çalıştırın:\n{_ddl}\nHata: {exc}"
        )
        raise EnvironmentError(
            "init_db kritik hata — 'admin_logs' tablosu eksik. "
            "Supabase SQL Editöründe tabloyu oluşturun ve uygulamayı yeniden başlatın."
        ) from exc

    logger.info("init_db: Veritabanı başlatma tamamlandı ✅")

init_db()

# ==============================================================================
# ONESIGNAL PUSH BİLDİRİM FONKSİYONLARI
# ==============================================================================
def _onesignal_send(payload: dict):
    """OneSignal REST API'ye bildirim gönderir (arka planda — request'i bloklamaz)."""
    if not ONESIGNAL_API_KEY or not ONESIGNAL_APP_ID:
        print("⚠️ OneSignal bildirimi gönderilemedi: ONESIGNAL_API_KEY veya ONESIGNAL_APP_ID environment variable eksik.")
        return
    def _do_send():
        try:
            resp = requests.post(
                ONESIGNAL_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Basic {ONESIGNAL_API_KEY}",
                    "Content-Type": "application/json",
                    "accept": "application/json"
                },
                timeout=8
            )
            result = resp.json() if resp.text else {}
            if resp.status_code not in (200, 202):
                print(f"⚠️ OneSignal hata {resp.status_code}: {resp.text}")
            else:
                recipients = result.get('recipients', 0)
                errors = result.get('errors', [])
                print(f"✅ OneSignal bildirim gönderildi | recipients={recipients} | id={result.get('id','?')}")
                if errors:
                    print(f"⚠️ OneSignal uyarıları: {errors}")
        except Exception as e:
            print(f"⚠️ OneSignal istek hatası: {e}")
    threading.Thread(target=_do_send, daemon=True).start()

def send_push_to_user(username, title, body, url="/"):
    """Belirli bir kullaniciya OneSignal uzerinden bildirim gonderir.
    Once kaydedilmis subscription_id (player_id) ile dener,
    bulamazsa include_aliases / external_id ile fallback yapar."""
    player_id = None
    if supabase:
        try:
            u = supabase.table('users').select('stats').eq('username', username).execute()
            if u.data:
                st = u.data[0].get('stats', {}) or {}
                if isinstance(st, str):
                    try: st = __import__('json').loads(st)
                    except: st = {}
                player_id = st.get('onesignal_player_id')
        except Exception as _exc:
            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~570]: {_exc}')

    if player_id:
        # En guvenilir yontem: dogrudan subscription ID ile gonder
        _onesignal_send({
            "app_id": ONESIGNAL_APP_ID,
            "include_subscription_ids": [player_id],
            "headings": {"en": title, "tr": title},
            "contents": {"en": body, "tr": body},
            "url": f"https://freeridertr.com.tr{url}",
            "web_push_topic": "freeridertr_dm"
        })
    else:
        # Fallback: external_id alias yontemi
        print(f"send_push_to_user: {username} icin player_id bulunamadi, include_aliases deneniyor")
        _onesignal_send({
            "app_id": ONESIGNAL_APP_ID,
            "include_aliases": {"external_id": [username]},
            "target_channel": "push",
            "headings": {"en": title, "tr": title},
            "contents": {"en": body, "tr": body},
            "url": f"https://freeridertr.com.tr{url}",
            "web_push_topic": "freeridertr_dm"
        })

def broadcast_push(title, body, exclude_user=None, url="/"):
    """Tüm kullanıcılara (veya belirli biri hariç) OneSignal üzerinden bildirim gönderir."""
    payload = {
        "app_id": ONESIGNAL_APP_ID,
        "included_segments": ["All"],
        "headings": {"en": title, "tr": title},
        "contents": {"en": body, "tr": body},
        "url": f"https://freeridertr.com.tr{url}",
        "web_push_topic": "freeridertr_broadcast"
    }
    # exclude_user varsa o kullanıcıyı dışla
    if exclude_user:
        payload["excluded_aliases"] = {"external_id": [exclude_user]}
    _onesignal_send(payload)


# Video MIME → uzantı eşlemesi
_VIDEO_EXT_MAP = {
    "mp4": "mp4", "mpeg": "mp4", "quicktime": "mov", "mov": "mov",
    "webm": "webm", "ogg": "ogv", "x-msvideo": "avi", "x-matroska": "mkv",
    "3gpp": "3gp", "3gpp2": "3g2", "x-ms-wmv": "wmv"
}

def upload_base64_to_storage(base64_string, folder="uploads"):
    if not isinstance(base64_string, str):
        return base64_string
    if not (base64_string.startswith("data:image/") or
            base64_string.startswith("data:audio/") or
            base64_string.startswith("data:video/")):
        return base64_string
    if not r2_client:
        print("⚠️ R2 depolama yapılandırılmamış, dosya yüklenemiyor.")
        return base64_string
    try:
        header, encoded = base64_string.split(",", 1)
        mime_type = header.split(";")[0].split(":")[1]          # e.g. video/mp4
        raw_sub   = mime_type.split("/")[1].split(";")[0]       # e.g. mp4

        # Uzantıyı belirle
        if mime_type.startswith("video/"):
            ext = _VIDEO_EXT_MAP.get(raw_sub, "mp4")
        elif mime_type.startswith("audio/"):
            ext = raw_sub if raw_sub in ("mp3","ogg","wav","webm","aac","m4a") else "mp3"
        else:
            ext = raw_sub
        if ext == "jpeg": ext = "jpg"

        file_data = base64.b64decode(encoded)
        file_name = f"{folder}/{uuid.uuid4().hex}.{ext}"

        r2_client.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=file_name,
            Body=file_data,
            ContentType=mime_type,
            CacheControl="public, max-age=31536000"
        )

        public_url = f"{R2_PUBLIC_URL}/{file_name}"
        print(f"✅ R2 yüklendi: {file_name} ({len(file_data)//1024} KB)")
        return public_url

    except Exception as e:
        print(f"❌ R2 Yükleme Hatası: {e}")

    return base64_string

def process_base64_in_dict(root):
    """Sözlük veya listede base64 veri URL'lerini R2'ye yükler.
    Özyinelemeli (recursive) değil, yığın (stack) tabanlı iteratif yaklaşım kullanır.
    Bu sayede derin iç içe yapılarda Python özyineleme limiti aşılmaz."""
    _B64_PREFIXES = ("data:image/", "data:audio/", "data:video/")
    stack: deque = deque()
    stack.append(root)
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k in list(node.keys()):
                v = node[k]
                if isinstance(v, str) and v.startswith(_B64_PREFIXES):
                    node[k] = upload_base64_to_storage(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                if isinstance(v, str) and v.startswith(_B64_PREFIXES):
                    node[i] = upload_base64_to_storage(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)

def _call_groq_ai(system_prompt: str, user_text: str) -> str:
    """Groq API'ye istek gönderir, hata durumunda varsayılan mesaj döner."""
    if not GROQ_API_KEY:
        print("⚠️ Groq AI devre dışı: GROQ_API_KEY environment variable eksik.")
        return "AI özelliği şu an yapılandırılmamış, daha sonra tekrar dener misin? 🏔️"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "llama-3.3-70b-versatile",
        "temperature": 0.4,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text[:2000]}  # max 2000 karakter
        ]
    }
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            json=payload, headers=headers, timeout=12
        )
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        print(f"⚠️ Groq API hatası: {e}")
        return "Sistemimde geçici bir arıza var dostum, daha sonra tekrar dener misin? 🏔️"

_GROQ_SYSTEM_CHAT = (
    "Sen FreeriderTR topluluğunun resmi yapay zeka asistanı Freerider AI'sın. "
    "Uzman bir downhill/freeride dağ bisikleti sürücüsü ve mekanikerisin. "
    "Sorulara net, teknik olarak doğru, mantıklı ve profesyonel cevaplar ver. "
    "Cevapların Türkçe, yardımsever, kısa ve öz (maksimum 3 cümle) olsun. "
    "Gerekirse ilgili emojiler kullan."
)
_GROQ_SYSTEM_DM = (
    "Sen FreeriderTR topluluğunun yapay zekasısın ve şu an bir kullanıcıyla özel mesajda (DM) konuşuyorsun. "
    "Bisiklet tamiri, parça uyumu, rotalar veya ekipmanlar hakkında sorulan sorulara uzman, "
    "mantıklı ve doğrudan cevaplar ver. Gereksiz muhabbete girme. Tamamen Türkçe ve anlaşılır ol."
)


def check_ai_limit(username, user_data):
    stats = user_data.get('stats', {})
    prem_tier = int(stats.get('premium_tier', 0))
    today_str = datetime.datetime.now().strftime("%Y-%m-%d")
    
    if prem_tier == 0:
        if stats.get('ai_usage_date') != today_str:
            stats['ai_usage_date'] = today_str
            stats['ai_usage_count'] = 0
            
        if stats.get('ai_usage_count', 0) >= 10:
            return False, "Günlük ücretsiz Freerider AI limitine (10 Soru) ulaştın! Sınırsız sohbet için Plus paketlerinden birini satın alabilirsin."
            
        stats['ai_usage_count'] = stats.get('ai_usage_count', 0) + 1
        try:
            supabase.table('users').update({"stats": stats}).eq('username', username).execute()
        except Exception as e:
            print(f"⚠️ AI stat güncelleme hatası: {e}")
    return True, ""

# ==============================================================================
# GOOGLE PLAY IN-APP PURCHASE (IAP) YAPILANDIRMASI
# Servis hesabı anahtarı ASLA koda gömülmez; GOOGLE_APPLICATION_CREDENTIALS
# environment variable üzerinden okunur (dosya yolu olarak tanımlanır).
# ==============================================================================
GOOGLE_PLAY_PACKAGE_NAME = os.environ.get("GOOGLE_PLAY_PACKAGE_NAME", "")

def _get_google_play_service():
    """Google Play Developer API servis nesnesini döndürür.
    Önce GOOGLE_CREDENTIALS_JSON (JSON string) sonra GOOGLE_APPLICATION_CREDENTIALS (dosya yolu) dener.
    Başarısızlık durumunda None döner ve hata loglanır."""
    if not GOOGLE_API_AVAILABLE:
        logger.error("Google API kütüphaneleri yüklü değil.")
        return None
    try:
        # Önce JSON string olarak dene (Render gibi platformlar için)
        creds_json = os.environ.get("GOOGLE_CREDENTIALS_JSON")
        if creds_json:
            info = json.loads(creds_json)
            credentials = gsa.Credentials.from_service_account_info(
                info,
                scopes=["https://www.googleapis.com/auth/androidpublisher"],
            )
        else:
            # Dosya yolu olarak dene
            creds_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            if not creds_path:
                logger.error("Ne GOOGLE_CREDENTIALS_JSON ne de GOOGLE_APPLICATION_CREDENTIALS tanımlı.")
                return None
            credentials = gsa.Credentials.from_service_account_file(
                creds_path,
                scopes=["https://www.googleapis.com/auth/androidpublisher"],
            )
        service = gapi_build("androidpublisher", "v3", credentials=credentials)
        return service
    except Exception as exc:
        logger.error(f"Google Play servis nesnesi oluşturulamadı: {exc}", exc_info=True)
        return None


# Ürün kimliği → premium tier eşleştirmesi
# Tüm paketler Google Play Console'da "Subscription" (Abonelik) tipinde
# tanımlanmış olmalıdır — tek seferlik (inapp) ürün olarak tanımlanmamalı!
_IAP_PRODUCT_TIER_MAP = {
    # ── AKTİF: Abonelik (Subscription) ürünleri — Play Console ID'leri ile BİREBİR AYNI ──
    # Bu ID'ler Android tarafındaki BillingManager.kt → PRODUCT_IDS listesiyle eşleşmeli.
    "freeridertr_ultra_pack_monthly":    3,  # 👑 Ultra+  (Tier 3) — aylık abonelik
    "freeridertr_deluxe_pack_monthly":   2,  # 🌟 Deluxe  (Tier 2) — aylık abonelik
    "freeridertr_standard_pack_monthly": 1,  # ⭐ Standart(Tier 1) — aylık abonelik

    # ── ESKİ / YEDEK: Geçiş dönemi ürünleri — aktif kullanıcı varsa tutulmalı ──
    "premium_standard_monthly": 1,
    "premium_deluxe_monthly":   2,
    "premium_ultra_monthly":    3,

    # ── GERİYE DÖNÜK UYUMLULUK: Eski tek seferlik (inapp) ürünler ────────
    # Eğer eski kullanıcıların yetkileri kaybolmasın istiyorsan bunları tut:
    "ultra_pack_1":    3,
    "deluxe_pack_1":   2,
    "standard_pack_1": 1,
}


@app.route("/api/verify_google_purchase", methods=["POST"])
def verify_google_purchase():
    """Google Play IAP satın alım token'ını backend'de doğrular ve
    kullanıcının premium seviyesini günceller.

    Beklenen JSON gövdesi:
        {
            "purchaseToken": "<Google'dan gelen token>",
            "productId":     "<Google Play ürün ID'si>",
            "purchaseType":  "subscription" | "inapp"   (opsiyonel)
        }

    Mobil WebView/JS Bridge, kullanıcı Google Play'den satın alım yaptıktan
    sonra bu endpoint'i çağırmalıdır.
    """
    # Oturum kontrolü — kimliği doğrulanmamış istek kabul edilmez
    if "username" not in session or not supabase:
        return jsonify({"status": "error", "message": "Oturum açılmamış."}), 401

    current_username = session["username"]

    # İstek gövdesini çözümle
    data = request.get_json(silent=True) or {}
    purchase_token = (data.get("purchaseToken") or "").strip()
    product_id     = (data.get("productId")     or "").strip()
    # purchaseType artık her zaman "subscription" — inapp desteklenmez.
    # Android tarafı bu alanı göndermese bile abonelik doğrulaması yapılır.
    purchase_type  = (data.get("purchaseType")  or "subscription").strip().lower()
    if purchase_type != "subscription":
        # Geriye dönük uyumluluk: eski istemci "inapp" gönderirse yine de
        # abonelik doğrulamasına yönlendir (paketler aboneliğe çevrildi)
        logger.warning(
            f"verify_google_purchase: purchaseType='{purchase_type}' alındı; "
            f"tüm paketler aboneliğe dönüştürüldüğünden 'subscription' olarak işleniyor."
        )
        purchase_type = "subscription"

    # Gerekli parametreler eksikse hata döndür
    if not purchase_token or not product_id:
        logger.warning(f"verify_google_purchase: Eksik parametre ({current_username})")
        return jsonify({"status": "error", "message": "purchaseToken ve productId zorunludur."}), 400

    # Ürün ID'sinden premium tier belirle
    tier = _IAP_PRODUCT_TIER_MAP.get(product_id)
    if tier is None:
        logger.warning(f"verify_google_purchase: Bilinmeyen ürün ID → {product_id}")
        return jsonify({"status": "error", "message": "Geçersiz ürün ID."}), 400

    # Paket adı yapılandırma kontrolü
    if not GOOGLE_PLAY_PACKAGE_NAME:
        logger.error("verify_google_purchase: GOOGLE_PLAY_PACKAGE_NAME tanımlı değil.")
        return jsonify({"status": "error", "message": "Sunucu yapılandırma hatası."}), 500

    # Google Play Developer API servis bağlantısını kur
    # Google Play API doğrulaması — hata olursa yine de üyelik ver
    expiry_ts = None
    service = _get_google_play_service()
    if service is None:
        logger.warning(
            f"verify_google_purchase: Google Play API kullanılamıyor, "
            f"üyelik yine de veriliyor ({current_username})"
        )
    else:
        try:
            result = (
                service.purchases()
                .subscriptions()
                .get(
                    packageName=GOOGLE_PLAY_PACKAGE_NAME,
                    subscriptionId=product_id,
                    token=purchase_token,
                )
                .execute()
            )
            payment_state = result.get("paymentState", 0)
            if payment_state not in (1, 2):
                logger.warning(
                    f"verify_google_purchase: Ödeme durumu geçersiz "
                    f"(paymentState={payment_state}, kullanıcı={current_username})"
                )
                return jsonify({"status": "error", "message": "Ödeme henüz tamamlanmamış."}), 402
            expiry_ms = int(result.get("expiryTimeMillis", 0))
            expiry_ts = expiry_ms // 1000 if expiry_ms else None
            logger.info(f"verify_google_purchase: API doğrulaması başarılı ({current_username})")
        except Exception as exc:
            logger.error(
                f"verify_google_purchase: Google Play API hatası ({current_username}): {exc}",
                exc_info=True,
            )
            logger.warning(f"verify_google_purchase: API hatası, üyelik yine de veriliyor ({current_username})")

    # ── Kullanıcı premium statüsünü Supabase'de güncelle ───────────────────
    try:
        u_res = supabase.table("users").select("stats").eq("username", current_username).execute()
        if not u_res.data:
            return jsonify({"status": "error", "message": "Kullanıcı bulunamadı."}), 404

        stats = u_res.data[0].get("stats", {}) or {}
        if isinstance(stats, str):
            try: stats = json.loads(stats)
            except json.JSONDecodeError: stats = {}

        # Premium tier ve bitiş tarihini güncelle
        stats["premium_tier"]   = tier
        stats.pop("pending_premium", None)

        # Varsayılan rengi ata (kullanıcı daha önce özel renk seçmediyse)
        if not stats.get("premium_color"):
            color_map = {1: "std-blue", 2: "dlx-blue", 3: "ult-gold"}
            stats["premium_color"] = color_map.get(tier, "std-blue")

        # Abonelik bitiş tarihlerini kaydet (heartbeat kontrolü için expiry_ts)
        if expiry_ts:
            stats["expiry_ts"]           = expiry_ts
            exp_dt                       = datetime.datetime.fromtimestamp(expiry_ts)
            stats["premium_expire_date"] = exp_dt.strftime("%Y-%m-%d")
        else:
            stats.pop("expiry_ts", None)
            stats.pop("premium_expire_date", None)

        # Google Play token'ı iade ve yenileme takibi için sakla
        stats["gp_purchase_token"] = purchase_token
        stats["gp_product_id"]     = product_id

        supabase.table("users").update({"stats": stats}).eq("username", current_username).execute()
        logger.info(
            f"✅ Google Play IAP doğrulandı: {current_username} → tier {tier} "
            f"(bitiş: {stats.get('premium_expire_date', 'belirsiz')})"
        )
    except Exception as exc:
        logger.error(
            f"verify_google_purchase: Supabase güncelleme hatası ({current_username}): {exc}",
            exc_info=True,
        )
        return jsonify({"status": "error", "message": "Kullanıcı güncellenemedi."}), 500

    return jsonify({
        "status":  "ok",
        "tier":    tier,
        "expiry":  stats.get("premium_expire_date"),
        "message": "Satın alım başarıyla doğrulandı.",
    })

@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    if 'username' not in session or not supabase:
        return jsonify({'status': 'error'}), 401
    username = session['username']
    revoked = False
    try:
        now_ts = int(time.time())
        u_res = supabase.table('users').select('stats').eq('username', username).execute()
        if u_res.data:
            stats = u_res.data[0].get('stats', {}) or {}
            if isinstance(stats, str):
                try: stats = json.loads(stats)
                except: stats = {}
            stats['last_seen_ts'] = now_ts

            # ── Üyelik bitiş tarihi (expiry_ts) kontrolü ──────────────────
            expiry_ts = stats.get('expiry_ts')
            if expiry_ts and int(stats.get('premium_tier', 0)) > 0:
                if now_ts >= int(expiry_ts):
                    was_trial = stats.get('is_trial', False)
                    stats['premium_tier'] = 0
                    stats['premium_color'] = ''
                    stats.pop('premium_expire_date', None)
                    stats.pop('expiry_ts', None)
                    stats.pop('weekly_reward_active', None)
                    stats.pop('monthly_reward_active', None)
                    if was_trial:
                        stats['trial_expired'] = True
                        stats['is_trial'] = False
                    revoked = True
            # ──────────────────────────────────────────────────────────────

            supabase.table('users').update({'stats': stats}).eq('username', username).execute()
    except Exception as _exc:
        import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~828]: {_exc}')
    return jsonify({'status': 'ok', 'premium_revoked': revoked})

@app.route("/api/save_push_id", methods=["POST"])
def save_push_id():
    """Kullanicinin OneSignal subscription ID sini Supabase e kaydeder."""
    if 'username' not in session or not supabase:
        return jsonify({'status': 'error'}), 401
    username = session['username']
    try:
        player_id = (request.json or {}).get('player_id', '').strip()
        if not player_id:
            return jsonify({'status': 'error', 'message': 'player_id eksik'}), 400
        u_res = supabase.table('users').select('stats').eq('username', username).execute()
        if u_res.data:
            stats = u_res.data[0].get('stats', {}) or {}
            if isinstance(stats, str):
                try: stats = json.loads(stats)
                except: stats = {}
            if stats.get('onesignal_player_id') != player_id:
                stats['onesignal_player_id'] = player_id
                supabase.table('users').update({'stats': stats}).eq('username', username).execute()
                print(f"OneSignal player_id kaydedildi: {username} -> {player_id[:20]}...")
        return jsonify({'status': 'ok'})
    except Exception as e:
        print(f"save_push_id hatasi: {e}")
        return jsonify({'status': 'error'}), 500

@app.route("/privacy-policy")
def privacy_policy():
    return """<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Gizlilik Politikası – FreeriderTR</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#09090b;color:#d4d4d8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:24px;max-width:720px;margin:0 auto}h1{color:#fff;font-size:1.8rem;font-weight:900;margin-bottom:4px}.logo{color:#dc2626}h2{color:#fff;font-size:1.1rem;font-weight:700;margin:24px 0 8px;border-left:3px solid #dc2626;padding-left:10px}p,li{font-size:0.9rem;line-height:1.7;color:#a1a1aa;margin-bottom:6px}ul{padding-left:20px;margin-bottom:10px}a{color:#dc2626}.back{margin-top:32px}hr{border-color:#27272a;margin:16px 0}</style>
</head>
<body>
<h1>FREERIDER<span class="logo">TR</span></h1>
<p style="color:#71717a;font-size:0.78rem;margin-bottom:24px">Son güncelleme: Nisan 2026</p>
<h2>1. Topladığımız Veriler</h2>
<ul><li>Kullanıcı adı, şehir ve isteğe bağlı e-posta adresi</li><li>Uygulama içi aktivite (paylaşımlar, mesajlar, harita noktaları)</li><li>Cihaz push bildirim token'ı (yalnızca bildirim göndermek için)</li><li>Galeri erişimi (yalnızca fotoğraf yüklendiğinde, yerel saklama yapılmaz)</li></ul>
<h2>2. Verilerin Kullanımı</h2>
<ul><li>Topluluk hizmetlerini sunmak ve kişiselleştirmek</li><li>Güvenlik ve spam koruması</li><li>Bildirim göndermek (yalnızca izin verilirse)</li><li>Yasal yükümlülüklerin yerine getirilmesi</li></ul>
<h2>3. Veri Paylaşımı</h2>
<p>Verileriniz üçüncü taraflara satılmaz. Yalnızca hizmet altyapısı (Supabase, Cloudflare R2) için teknik aktarım yapılır.</p>
<h2>4. Veri Saklama ve Silme</h2>
<p>Hesabınızı sildiğinizde tüm kişisel verileriniz kalıcı olarak silinir. Silme talebi için: <a href="/delete-account">freeridertr.com.tr/delete-account</a></p>
<h2>5. Güvenlik</h2>
<p>Şifreler bcrypt ile hashlenerek saklanır. Tüm iletişim HTTPS üzerinden gerçekleşir.</p>
<h2>6. İletişim</h2>
<p>Gizlilikle ilgili sorularınız için: <a href="mailto:destek.freerider@gmail.com">destek.freerider@gmail.com</a></p>
<div class="back"><a href="https://freeridertr.com.tr">← Uygulamaya Geri Dön</a></div>
</body></html>""", 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route("/terms")
def terms():
    return """<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Kullanım Şartları – FreeriderTR</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#09090b;color:#d4d4d8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:24px;max-width:720px;margin:0 auto}h1{color:#fff;font-size:1.8rem;font-weight:900;margin-bottom:4px}.logo{color:#dc2626}h2{color:#fff;font-size:1.1rem;font-weight:700;margin:24px 0 8px;border-left:3px solid #dc2626;padding-left:10px}p,li{font-size:0.9rem;line-height:1.7;color:#a1a1aa;margin-bottom:6px}ul{padding-left:20px;margin-bottom:10px}a{color:#dc2626}.back{margin-top:32px}</style>
</head>
<body>
<h1>FREERIDER<span class="logo">TR</span></h1>
<p style="color:#71717a;font-size:0.78rem;margin-bottom:24px">Kullanım Şartları – Son güncelleme: Nisan 2026</p>
<h2>1. Kabul</h2>
<p>FreeriderTR'yi kullanarak bu şartları kabul etmiş sayılırsınız. Kabul etmiyorsanız uygulamayı kullanmayınız.</p>
<h2>2. Kullanıcı Sorumlulukları</h2>
<ul><li>Gerçek bilgilerle kayıt olunmalıdır</li><li>Başka kullanıcılara taciz, hakaret veya zarar verici içerik paylaşılamaz</li><li>+18 içerik, uyuşturucu veya yasa dışı içerik kesinlikle yasaktır</li><li>Spam, bot veya sahte hesap oluşturulamaz</li></ul>
<h2>3. İçerik</h2>
<p>Paylaştığınız içeriklerden yasal olarak siz sorumlusunuz. Yönetim kuralları ihlal eden içerikleri kaldırma ve hesabı askıya alma hakkını saklı tutar.</p>
<h2>4. Hesap Feshi</h2>
<p>Kuralları ihlal eden hesaplar uyarısız kapatılabilir. Hesabınızı kendiniz silmek için: <a href="/delete-account">freeridertr.com.tr/delete-account</a></p>
<h2>5. Sorumluluk Sınırı</h2>
<p>FreeriderTR, kullanıcıların paylaştığı içeriklerden sorumlu tutulamaz. Platform "olduğu gibi" sunulmaktadır.</p>
<h2>6. İletişim</h2>
<p><a href="mailto:destek.freerider@gmail.com">destek.freerider@gmail.com</a></p>
<div class="back"><a href="https://freeridertr.com.tr">← Uygulamaya Geri Dön</a></div>
</body></html>""", 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route("/.well-known/assetlinks.json")
def assetlinks():
    PACKAGE_NAME = os.environ.get("TWA_PACKAGE_NAME", "com.freeridertr.app")
    SHA256_FINGERPRINT = os.environ.get("TWA_SHA256_FINGERPRINT", "BURAYA_PARMAK_IZI_GELECEK")
    
    data = [{
        "relation": ["delegate_permission/common.handle_all_urls"],
        "target": {
            "namespace": "android_app",
            "package_name": PACKAGE_NAME,
            "sha256_cert_fingerprints": [SHA256_FINGERPRINT]
        }
    }]
    from flask import Response
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Access-Control-Allow-Origin": "*"}
    )

@app.route("/manifest.json")
def manifest():
    manifest_data = {
        "name": "FreeriderTR - Downhill Toplulugu",
        "short_name": "FreeriderTR",
        "description": "Turkiye'nin en buyuk Downhill ve Freeride dag bisikleti toplulugu.",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#000000",
        "theme_color": "#b91c1c",
        "lang": "tr",
        "categories": ["sports", "social"],
        "icons": [
            {
                "src": "https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any maskable"
            },
            {
                "src": "https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg",
                "sizes": "512x512",
                "type": "image/png",
                "purpose": "any maskable"
            }
        ],
        "screenshots": [],
        "prefer_related_applications": True,
        "related_applications": [
            {
                "platform": "play",
                "url": "https://play.google.com/store/apps/details?id=com.freeridertr.app",
                "id": "com.freeridertr.app"
            }
        ]
    }
    return jsonify(manifest_data)

@app.route("/OneSignalSDKWorker.js")
@app.route("/sw.js")
def service_worker():
    sw_code = """
importScripts("https://cdn.onesignal.com/sdks/web/v16/OneSignalSDK.sw.js");

// ══════════════════════════════════════════════════════════
// FreeriderTR Offline Service Worker
// ══════════════════════════════════════════════════════════

const APP_CACHE    = 'freeridertr-app-v1';
const TILE_CACHE   = 'freeridertr-tiles-v1';
const APP_VERSION  = 'v8';

// İlk yüklemede önbelleğe alınacak CDN kaynakları
// ── CDN PRECACHE LİSTESİ ─────────────────────────────────────────────────
// NOT: cdn.tailwindcss.com / unpkg.com CORS başlığı dönmez.
// mode:'no-cors' → "opaque" response (status=0, ok=false) alınır — CORS hatası olmaz.
// Opaque response okunamaz ama cache'e konulabilir → offline için yeterli.
const PRECACHE_URLS = [
    'https://cdn.tailwindcss.com',
    'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css',
    'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',
    'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2',
    'https://unpkg.com/leaflet-control-geocoder/dist/Control.Geocoder.css',
    'https://unpkg.com/leaflet-control-geocoder/dist/Control.Geocoder.js',
];

const TILE_HOSTS = ['tile.openstreetmap.org', 'arcgisonline.com', 'basemaps.cartocdn.com'];

// ── INSTALL: CDN kaynaklarını önbelleğe al ──────────────────────────────
self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(APP_CACHE).then(cache =>
            Promise.allSettled(
                PRECACHE_URLS.map(url =>
                    fetch(url, { mode: 'no-cors' })      // 'cors' → 'no-cors' : CORS hatası önlenir
                        .then(res => {
                            // res.ok       → CORS destekli kaynak başarılı döndü
                            // res.type==='opaque' → no-cors CDN yanıtı (status=0 ama geçerli)
                            if (res.ok || res.type === 'opaque') {
                                return cache.put(url, res);
                            }
                            console.warn('[SW install] Önbelleğe alınamadı:', url, 'status:', res.status);
                        })
                        .catch(err =>
                            // Ağ hatası → yalnızca logla, install'ı durdurma
                            console.warn('[SW install] Fetch başarısız:', url, err.message)
                        )
                )
            )
        )
    );
});

// ── FETCH: Tüm istekleri yönet ──
self.addEventListener('fetch', event => {
    const req = event.request;
    const url = req.url;

    // 1) Harita tile'ları: stale-while-revalidate
    if (TILE_HOSTS.some(h => url.includes(h))) {
        event.respondWith(
            caches.open(TILE_CACHE).then(cache =>
                cache.match(req).then(cached => {
                    const network = fetch(req).then(res => {
                        // clone() ÖNCE yapılır, orijinal response döndürülür
                        if (res && res.status === 200) {
                            cache.put(req, res.clone());
                        }
                        return res;
                    }).catch(() => null);
                    return cached || network;
                })
            )
        );
        return;
    }

    // 2) CDN kaynakları: cache-first → yoksa no-cors ile çek ve cache'e at
    if (PRECACHE_URLS.some(u => url === u || url.startsWith(u))) {
        event.respondWith(
            caches.match(req).then(cached => {
                if (cached) return cached;
                return fetch(req, { mode: 'no-cors' }).then(res => {
                    if (res && (res.ok || res.type === 'opaque')) {
                        // res.clone() ile cache'e yaz, orijinali tarayıcıya ver
                        const toCache = res.clone();
                        caches.open(APP_CACHE).then(c => c.put(req, toCache));
                    }
                    return res;
                }).catch(() => null);
            })
        );
        return;
    }

    // 3) Ana sayfa (/): network-first, offline'da cache'den dön
    if (req.mode === 'navigate' || url.endsWith('/') || url.match(/\/$/)) {
        event.respondWith(
            fetch(req)
                .then(res => {
                    if (res && res.status === 200) {
                        // clone() → cache, orijinal → tarayıcı
                        const toCache = res.clone();
                        caches.open(APP_CACHE).then(cache => cache.put(req, toCache));
                    }
                    return res;
                })
                .catch(() =>
                    caches.match(req).then(cached =>
                        cached || caches.match('/')
                    )
                )
        );
        return;
    }

    // 4) API çağrıları: sadece online, offline'da boş JSON dön
    if (url.includes('/api/')) {
        event.respondWith(
            fetch(req).catch(() =>
                new Response(
                    JSON.stringify({ status: 'offline', message: 'İnternet bağlantısı yok. Uygulama çevrimdışı modda çalışıyor.' }),
                    { headers: { 'Content-Type': 'application/json' } }
                )
            )
        );
        return;
    }
});
"""
    return sw_code, 200, {
        'Content-Type': 'application/javascript',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Service-Worker-Allowed': '/'
    }

@app.route("/api/upload", methods=["POST"])
def api_upload():
    """Multipart binary dosya yükleme — base64 JSON'dan çok daha hızlı."""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Giriş yapmalısınız!'}), 401

    if not r2_client:
        return jsonify({'status': 'error', 'message': 'Depolama servisi yapılandırılmamış, yükleme şu an kullanılamıyor.'})

    file  = request.files.get('file')
    folder = request.form.get('folder', 'uploads')

    if not file or not file.filename:
        return jsonify({'status': 'error', 'message': 'Dosya bulunamadı!'})

    mime_type = file.content_type or 'application/octet-stream'
    allowed_image = mime_type.startswith('image/')
    allowed_video = mime_type.startswith('video/')
    allowed_audio = mime_type.startswith('audio/')

    if not (allowed_image or allowed_video or allowed_audio):
        return jsonify({'status': 'error', 'message': f'Desteklenmeyen dosya türü: {mime_type}'})

    raw_sub = mime_type.split('/')[1].split(';')[0]
    if allowed_video:
        ext = _VIDEO_EXT_MAP.get(raw_sub, 'mp4')
    elif allowed_audio:
        ext = raw_sub if raw_sub in ('mp3','ogg','wav','webm','aac','m4a') else 'mp3'
    else:
        ext = 'jpg' if raw_sub == 'jpeg' else raw_sub

    try:
        file_data = file.read()
        file_size = len(file_data)
        # Video max 50MB, diğer max 10MB
        max_size = 50 * 1024 * 1024 if allowed_video else 10 * 1024 * 1024
        if file_size > max_size:
            mb = max_size // (1024*1024)
            return jsonify({'status': 'error', 'message': f'Dosya çok büyük! Maksimum {mb}MB olabilir.'})

        file_name = f"{folder}/{uuid.uuid4().hex}.{ext}"
        r2_client.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=file_name,
            Body=file_data,
            ContentType=mime_type,
            CacheControl="public, max-age=31536000"
        )
        public_url = f"{R2_PUBLIC_URL}/{file_name}"
        print(f"✅ /api/upload: {file_name} ({file_size//1024} KB)")
        return jsonify({'status': 'ok', 'url': public_url})
    except Exception as e:
        print(f"❌ /api/upload hatası: {e}")
        return jsonify({'status': 'error', 'message': 'Yükleme başarısız oldu, lütfen tekrar deneyin.'})

@app.route("/api/data", methods=["GET", "POST"])
def api_data():
    if not supabase: 
        return jsonify({'status': 'error', 'message': 'Veritabanı bağlantısı kurulamadı.'})
        
    try:
        maint_res = supabase.table('settings').select('*').eq('id', 'maintenance').execute()
        maintenance_mode = (maint_res.data[0].get("value") == 'true') if maint_res.data else False
    except Exception as _exc:
        maintenance_mode = False

    if request.method == "GET":
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        
        try:
            events_res = supabase.table('events').select('*').execute()
            pending_events = [
                ev for ev in (events_res.data or [])
                if ev.get('datetime', '').split(' ')[0] <= today and not ev.get('xp_awarded')
            ]
            if pending_events:
                # Etkilenecek tüm kullanıcıları bir seferde çek (N+1 sorgu önleme)
                all_involved = set()
                for ev_data in pending_events:
                    if ev_data.get('creator'):
                        all_involved.add(ev_data['creator'])
                    all_involved.update(ev_data.get('attendees', []))
                
                user_cache = {}
                if all_involved:
                    for uname in all_involved:
                        try:
                            u_r = supabase.table('users').select('username, xp, stats').eq('username', uname).execute()
                            if u_r.data:
                                user_cache[uname] = u_r.data[0]
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~1182]: {_exc}')
                
                for ev_data in pending_events:
                    ev_id = str(ev_data.get('id'))
                    creator = ev_data.get('creator')
                    attendees = ev_data.get('attendees', [])
                    
                    if creator and creator in user_cache:
                        ud = user_cache[creator]
                        try:
                            supabase.table('users').update({"xp": ud.get('xp', 0) + 200}).eq('username', creator).execute()
                            user_cache[creator]['xp'] = ud.get('xp', 0) + 200
                        except Exception as e:
                            print(f"⚠️ Etkinlik XP (creator) hatası: {e}")
                            
                    for att in attendees:
                        if att != creator and att in user_cache:
                            ud = user_cache[att]
                            try:
                                supabase.table('users').update({"xp": ud.get('xp', 0) + 100}).eq('username', att).execute()
                                user_cache[att]['xp'] = ud.get('xp', 0) + 100
                            except Exception as e:
                                print(f"⚠️ Etkinlik XP (attendee) hatası: {e}")
                    try:
                        supabase.table('events').update({"xp_awarded": True}).eq('id', ev_id).execute()
                    except Exception as e:
                        print(f"⚠️ Etkinlik xp_awarded güncelleme hatası: {e}")
        except Exception as e: 
            print(f"⚠️ Etkinlik XP dağıtım hatası: {e}")

        # Toplam kullanıcı sayısı
        try:
            uc_res = supabase.table('settings').select('value').eq('id', 'total_users_count').execute()
            total_users_count = int(uc_res.data[0]['value']) if uc_res.data else 300
        except Exception as _exc:
            total_users_count = 300

        # Aktif kullanıcılar: son 5 dakikada görülenler — JSONB filtresiyle sayım
        try:
            now_ts2    = int(time.time())
            five_min_ago = now_ts2 - 300
            # Supabase count=exact: sadece sayı döner, tüm satırları aktarmaz
            count_res  = (
                supabase.table("users")
                .select("username", count="exact")
                .filter("stats->>last_seen_ts", "gte", str(five_min_ago))
                .execute()
            )
            real_active = count_res.count or 0
        except Exception as exc:
            logger.warning(f"Aktif kullanıcı sayımı hatası: {exc}")
            real_active = 0
        random_active = random.randint(1, 100)
        active_users_count = real_active + random_active

        db_data = {
            'users': [], 
            'banned': [], 
            'maintenance': maintenance_mode,
            'pinned_message': {},
            'total_users': total_users_count,
            'active_users': active_users_count
        }

        # ── Liderlik tablosu önbelleği (TTL: 5 dakika) ─────────────────────────
        # Her GET isteğinde DB'yi dökmek yerine önbellekten servis edilir.
        _lb_cache = getattr(app, '_leaderboard_cache', None)
        _now_lb   = time.time()
        if _lb_cache and _now_lb - _lb_cache['ts'] < 300:
            db_data['users']  = _lb_cache['users']
            db_data['banned'] = _lb_cache['banned']
        else:
            try:
                # Listedekiler için hafif veri (garage/missions gibi ağır alanlar hariç)
                users_res = (
                    supabase.table('users')
                    .select('username, name, bio, city, avatar, role, xp, stats, accepted_chat_rules')
                    .order('xp', desc=True)
                    .limit(50)
                    .execute()
                )
                current_user_lb = session.get('username')
                stripped = []
                for u in (users_res.data or []):
                    # Admin sıralamada gösterilmez
                    if u.get('username') == 'Admin' or u.get('role') == 'Admin':
                        continue
                    st = u.get('stats') or {}
                    if isinstance(st, str):
                        try:
                            st = json.loads(st)
                        except json.JSONDecodeError:
                            st = {}
                    light_stats = {k: v for k, v in st.items()
                                   if k not in ('garage', 'missions', 'daily_missions', 'weekly_missions')}
                    u2 = dict(u); u2['stats'] = light_stats
                    stripped.append(u2)
                db_data['users'] = stripped

                if current_user_lb:
                    # Mevcut kullanıcı ilk 50'de değilse tam verisini ayrıca çek
                    if not any(u['username'] == current_user_lb for u in db_data['users']):
                        curr_res = (
                            supabase.table('users')
                            .select('username, name, bio, city, avatar, role, xp, stats, accepted_chat_rules')
                            .eq('username', current_user_lb)
                            .execute()
                        )
                        if curr_res.data:
                            db_data['users'].append(curr_res.data[0])

                banned_res = supabase.table('banned').select('username').execute()
                db_data['banned'] = [r['username'] for r in (banned_res.data or [])]

                # Önbelleği güncelle
                app._leaderboard_cache = {
                    'ts':     time.time(),
                    'users':  db_data['users'],
                    'banned': db_data['banned'],
                }
            except Exception as exc:
                logger.error(f"Liderlik tablosu yükleme hatası: {exc}", exc_info=True)

        try:
            pin_res = supabase.table('settings').select('value').eq('id', 'pinned_message').execute()
            if pin_res.data:
                val = pin_res.data[0].get('value', '{}')
                if val:
                    db_data['pinned_message'] = json.loads(val)
        except Exception as exc:
            logger.warning(f"Sabitlenmiş mesaj yükleme hatası: {exc}")
        
        # ── Tablo verileri — select('*') ile tüm sütunlar çekilir ──────────────
        # NOT: Önceden _TABLE_COLUMNS ile spesifik sütun isimleri belirtiliyordu.
        # Veritabanındaki sütun isimleri ile kodun beklediği isimler uyuşmadığında
        # try-except bloğu boş veri döndürüyordu. Artık select('*') kullanılıyor.
        tables_to_fetch = {
            'markers': 5000,   # Tüm marker'ların gelmesi için yüksek limit
            'reports': 50,
            'news':    50,
            'events':  50,
        }

        for table, limit in tables_to_fetch.items():
            try:
                res = supabase.table(table).select('*').order('id', desc=True).limit(limit).execute()
                db_data[table] = res.data or []
            except Exception as exc:
                logger.warning(f"Tablo yükleme hatası [{table}]: {exc}")
                db_data[table] = []

        # Market tablosu — bumped_at sütunu yoksa created_at'e fallback
        try:
            try:
                market_res = supabase.table('market').select('*').order('bumped_at', desc=True).limit(50).execute()
            except Exception:
                # bumped_at sütunu yoksa created_at ile sırala
                logger.info("Market: bumped_at sütunu bulunamadı, created_at ile sıralanıyor.")
                market_res = supabase.table('market').select('*').order('created_at', desc=True).limit(50).execute()
            db_data['market'] = market_res.data or []
        except Exception as exc:
            logger.warning(f"Market yükleme hatası: {exc}")
            db_data['market'] = []

        # Stories
        try:
            now_ts = int(time.time())
            stories_res = supabase.table('stories').select('*').gt('expires_at', now_ts).order('created_at', desc=True).limit(50).execute()
            db_data['stories'] = stories_res.data or []
        except Exception as exc:
            logger.warning(f"Stories yükleme hatası: {exc}")
            db_data['stories'] = []

        # DM'ler
        try:
            current_user = session.get('username')
            if current_user:
                dm_res = (
                    supabase.table('dms')
                    .select('*')
                    .contains('participants', [current_user])
                    .order('id', desc=True)
                    .limit(50)
                    .execute()
                )
                db_data['dms'] = dm_res.data or []
            else:
                db_data['dms'] = []
        except Exception as exc:
            logger.warning(f"DM yükleme hatası: {exc}")
            db_data['dms'] = []

        # Mesajlar (son 50 mesaj, eski→yeni sıralı)
        try:
            msg_res = (
                supabase.table('messages')
                .select('*')
                .order('id', desc=True)
                .limit(50)
                .execute()
            )
            db_data['messages'] = list(reversed(msg_res.data)) if msg_res.data else []
        except Exception as exc:
            logger.warning(f"Mesajlar yükleme hatası: {exc}")
            db_data['messages'] = []

        return jsonify(db_data)
        
    elif request.method == "POST":
        req = request.json
        action = req.get('action')
        data = req.get('data', {})
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()

        # Rate limiting — brute force koruması
        _rate_limits = {
            'login':                (10, 300),   # 5 dak içinde maks 10 deneme
            'register':             (5,  600),   # 10 dak içinde maks 5 kayıt
            'ask_ai':               (30, 60),    # 1 dak içinde maks 30 istek
            'request_reset':        (5,  600),   # 10 dak içinde maks 5 istek
            'reset_password_code':  (5,  600),
            'send_profile_verification': (5, 600),
            'add_message':          (30, 60),    # 1 dak içinde maks 30 mesaj (spam önleme)
            'send_dm':              (20, 60),    # 1 dak içinde maks 20 DM
            'add_marker':           (10, 300),   # 5 dak içinde maks 10 marker
            'daily_spin':           (5,  60),    # 1 dak içinde maks 5 istek (çift çevirme önleme)
            'verify_email':         (10, 600),   # brute-force kod tahmini önleme
        }
        if action in _rate_limits:
            max_c, win = _rate_limits[action]
            if not rate_check(client_ip, action, max_c, win):
                return jsonify({'status': 'error', 'message': 'Çok fazla istek gönderdiniz. Lütfen biraz bekleyin.'}), 429

        if action not in ['login', 'register', 'ask_ai', 'daily_spin', 'request_reset', 'reset_password_code', 'verify_email', 'send_profile_verification', 'claim_ref_reward', 'get_stories', 'upload_media']:
            process_base64_in_dict(data)
        
        try:
            # 1) Herkese Açık İşlemler
            if action == 'login':
                username_input = data.get('username', '').strip()
                password_input = data.get('password', '').strip()
                
                if username_input.lower() == 'admin' and password_input == ADMIN_PASSWORD:
                    admin_payload = {
                        "username": "Admin", 
                        "name": "Sistem Yöneticisi", 
                        "role": "Admin", 
                        "xp": 99999,
                        "avatar": "https://cdn.freeridertr.com.tr/video%20ana/istockphoto-2221026101-640_adpp_is.mp4",
                        "bio": "FreeriderTR Grubu Kurucusu", 
                        "accepted_chat_rules": True,
                        "stats": {
                            "markers": 99, "events": 99, "market": 99, "premium_tier": 3, 
                            "premium_color": "rainbow", "avatar_effect": "fire", "login_streak": 999,
                            "last_login": datetime.datetime.now().strftime("%Y-%m-%d"),
                            "monthly_xp": 9999, "weekly_xp": 9999, "garage": [], "profile_views": 999,
                            "onboarding": True
                        },
                        "password": generate_password_hash(ADMIN_PASSWORD)
                    }
                    # Sadece admin yoksa oluştur, her girişte DB'ye yazma
                    admin_check = supabase.table('users').select('username').eq('username', 'Admin').execute()
                    if not admin_check.data:
                        supabase.table('users').upsert(admin_payload).execute()
                    session['username'] = 'Admin'
                    session['role'] = 'Admin'
                    admin_payload.pop('password')
                    return jsonify({'status': 'ok', 'user': admin_payload})

                if maintenance_mode: 
                    return jsonify({'status': 'error', 'message': 'Sistem bakım modunda.'})
                
                # ilike zaten büyük/küçük harf duyarsız, tek sorgu yeterli
                user_res = supabase.table('users').select('*').ilike('username', username_input.strip()).execute()

                if user_res.data:
                    user_data = user_res.data[0]
                    
                    ban_check = supabase.table('banned').select('*').eq('username', user_data['username']).execute()
                    if ban_check.data: 
                        return jsonify({'status': 'error', 'message': 'Hesabınız banlanmıştır!'})
                        
                    if check_password_hash(user_data.get('password', ''), password_input):
                        session['username'] = user_data['username']
                        session['role'] = user_data.get('role', 'user')
                        user_data.pop('password', None)
                        
                        today = datetime.datetime.now().strftime("%Y-%m-%d")
                        current_month = datetime.datetime.now().strftime("%Y-%m")
                        current_week = datetime.datetime.now().strftime("%Y-%V")
                        yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
                        
                        stats = user_data.get('stats', {})
                        
                        if 'premium_expire_date' in stats:
                            try:
                                exp_dt = datetime.datetime.strptime(stats['premium_expire_date'], "%Y-%m-%d")
                                if datetime.datetime.now() > exp_dt:
                                    was_trial = stats.get('is_trial', False)
                                    stats['premium_tier'] = 0
                                    stats['premium_color'] = ''
                                    stats.pop('premium_expire_date', None)
                                    if was_trial:
                                        stats['trial_expired'] = True
                                        stats['is_trial'] = False
                                    supabase.table('users').update({"stats": stats}).eq('username', user_data['username']).execute()
                            except Exception as e:
                                print(f"⚠️ Premium sona erme hatası: {e}")
                        
                        # ── Haftalık / Aylık Liderlik Ödülü: TÜM ilk-3 kullanıcıya dağıt ──
                        try:
                            now_dt = datetime.datetime.now()
                            week_key = now_dt.strftime("%Y-%V")
                            month_key = now_dt.strftime("%Y-%m")

                            # Bu kontrol yalnızca dönem sınırlarında tetiklenir; bir kez
                            # çalıştığında tüm top-3 kullanıcılara yazar (giriş yapan kim
                            # olursa olsun) ve tekrarını önlemek için 'reward_distributed_*'
                            # anahtarını global bir "sentinel" kullanıcıya değil, her
                            # kullanıcının kendi stats'ına yazar.

                            def _safe_stats(u):
                                s = u.get('stats') or {}
                                if isinstance(s, str):
                                    try: s = json.loads(s)
                                    except: s = {}
                                return s

                            # ── Haftalık: Pazartesi günü, yeni hafta ──
                            if now_dt.weekday() == 0 and stats.get('last_reward_week', '') != week_key:
                                all_users_w = supabase.table('users').select('username, stats, role').execute()
                                if all_users_w.data:
                                    sorted_w = sorted(
                                        [u for u in all_users_w.data
                                         if _safe_stats(u).get('weekly_xp', 0) > 0
                                         and u.get('username') != 'Admin'
                                         and u.get('role') not in ('Admin', 'SubAdmin')],
                                        key=lambda u: _safe_stats(u).get('weekly_xp', 0), reverse=True
                                    )
                                    for rank_i, ranked_u in enumerate(sorted_w[:3]):
                                        r_stats = _safe_stats(ranked_u)
                                        # Önceki dönem ödülünü geri çek (reward flag'i varsa)
                                        if r_stats.get('weekly_reward_active'):
                                            # Sadece ödül kaynaklı premium'u sil; manuel/satın
                                            # alınmış (expiry_ts > şimdi) premium'a dokunma
                                            exp_ts = r_stats.get('expiry_ts', 0)
                                            if not exp_ts or int(time.time()) >= int(exp_ts):
                                                r_stats['premium_tier'] = 0
                                                r_stats['premium_color'] = ''
                                                r_stats.pop('premium_expire_date', None)
                                            r_stats.pop('weekly_reward_active', None)
                                        # Yeni ödülü ver
                                        if rank_i == 0:
                                            r_stats['premium_tier'] = 3
                                            r_stats['premium_color'] = 'ult-gold'
                                            reward_label = "1 Hafta Ultra+"
                                        elif rank_i == 1:
                                            r_stats['premium_tier'] = 2
                                            r_stats['premium_color'] = 'dlx-blue'
                                            reward_label = "1 Hafta Deluxe"
                                        else:
                                            r_stats['premium_tier'] = 1
                                            r_stats['premium_color'] = 'std-blue'
                                            reward_label = "1 Hafta Standart"
                                        exp_date = (now_dt + datetime.timedelta(days=7)).strftime("%Y-%m-%d")
                                        r_stats['premium_expire_date'] = exp_date
                                        r_stats['expiry_ts'] = int((now_dt + datetime.timedelta(days=7)).timestamp())
                                        r_stats['last_reward_week'] = week_key
                                        r_stats['weekly_reward_active'] = True
                                        r_stats['weekly_reward_label'] = reward_label
                                        supabase.table('users').update({'stats': r_stats}).eq('username', ranked_u['username']).execute()
                                        if ranked_u['username'] == user_data['username']:
                                            stats.update(r_stats)
                                            user_data['weekly_reward'] = reward_label

                            # ── Aylık: Ayın 1'i, yeni ay ──
                            if now_dt.day == 1 and stats.get('last_reward_month', '') != month_key:
                                all_users_m = supabase.table('users').select('username, stats, role').execute()
                                if all_users_m.data:
                                    sorted_m = sorted(
                                        [u for u in all_users_m.data
                                         if _safe_stats(u).get('monthly_xp', 0) > 0
                                         and u.get('username') != 'Admin'
                                         and u.get('role') not in ('Admin', 'SubAdmin')],
                                        key=lambda u: _safe_stats(u).get('monthly_xp', 0), reverse=True
                                    )
                                    for rank_i, ranked_u in enumerate(sorted_m[:3]):
                                        r_stats = _safe_stats(ranked_u)
                                        # Önceki dönem aylık ödülünü geri çek
                                        if r_stats.get('monthly_reward_active'):
                                            exp_ts = r_stats.get('expiry_ts', 0)
                                            if not exp_ts or int(time.time()) >= int(exp_ts):
                                                r_stats['premium_tier'] = 0
                                                r_stats['premium_color'] = ''
                                                r_stats.pop('premium_expire_date', None)
                                            r_stats.pop('monthly_reward_active', None)
                                        if rank_i == 0:
                                            r_stats['premium_tier'] = 3
                                            r_stats['premium_color'] = 'ult-gold'
                                            reward_label = "1 Ay Ultra+"
                                        elif rank_i == 1:
                                            r_stats['premium_tier'] = 2
                                            r_stats['premium_color'] = 'dlx-blue'
                                            reward_label = "1 Ay Deluxe"
                                        else:
                                            r_stats['premium_tier'] = 1
                                            r_stats['premium_color'] = 'std-blue'
                                            reward_label = "1 Ay Standart"
                                        exp_date = (now_dt + datetime.timedelta(days=30)).strftime("%Y-%m-%d")
                                        r_stats['premium_expire_date'] = exp_date
                                        r_stats['expiry_ts'] = int((now_dt + datetime.timedelta(days=30)).timestamp())
                                        r_stats['last_reward_month'] = month_key
                                        r_stats['monthly_reward_active'] = True
                                        r_stats['monthly_reward_label'] = reward_label
                                        supabase.table('users').update({'stats': r_stats}).eq('username', ranked_u['username']).execute()
                                        if ranked_u['username'] == user_data['username']:
                                            stats.update(r_stats)
                                            user_data['monthly_reward'] = reward_label
                        except Exception as reward_e:
                            print("Liderlik odulu hatasi:", reward_e)

                        last_login = stats.get('last_login', '')
                        streak = stats.get('login_streak', 0)
                        
                        if stats.get('current_month') != current_month:
                            stats['monthly_xp'] = 0
                            stats['current_month'] = current_month
                            
                        if stats.get('current_week') != current_week:
                            stats['weekly_xp'] = 0
                            stats['current_week'] = current_week
                        
                        stats['last_seen_ts'] = int(time.time())

                        if last_login != today:
                            if last_login == yesterday:
                                streak += 1
                            else:
                                streak = 1
                                
                            stats['last_login'] = today
                            stats['login_streak'] = streak
                            
                            daily_xp = 20
                            if streak % 7 == 0: daily_xp += 200
                            if streak % 30 == 0: daily_xp += 2000
                            
                            user_data['xp'] = user_data.get('xp', 0) + daily_xp
                            stats['monthly_xp'] = stats.get('monthly_xp', 0) + daily_xp
                            stats['weekly_xp'] = stats.get('weekly_xp', 0) + daily_xp
                            
                            supabase.table('users').update({
                                "xp": user_data['xp'], 
                                "stats": stats
                            }).eq('username', user_data['username']).execute()
                            
                            user_data['stats'] = stats
                            user_data['just_got_daily'] = daily_xp 
                        
                        # Her girişte last_seen_ts güncelle
                        stats['last_seen_ts'] = int(time.time())
                        try:
                            supabase.table('users').update({"stats": stats}).eq('username', user_data['username']).execute()
                        except Exception as e:
                            print(f"⚠️ Login stat güncelleme hatası: {e}")
                        user_data['stats'] = stats
                        return jsonify({'status': 'ok', 'user': user_data})
                        
                return jsonify({'status': 'error', 'message': 'Hatalı kullanıcı adı veya şifre!'})

            elif action == 'register':
                if maintenance_mode: 
                    return jsonify({'status': 'error', 'message': 'Bakım modundayken kayıt olunamaz.'})
                    
                username = html.escape(data.get('username', '').strip())
                password_raw = data.get('password', '').strip()
                
                # Temel doğrulama
                if not username or len(username) < 3:
                    return jsonify({'status': 'error', 'message': 'Kullanıcı adı en az 3 karakter olmalıdır.'})
                if len(username) > 30:
                    return jsonify({'status': 'error', 'message': 'Kullanıcı adı en fazla 30 karakter olabilir.'})
                if not re.match(r'^[A-Za-z0-9_.\-]+$', username):
                    return jsonify({'status': 'error', 'message': 'Kullanıcı adı yalnızca harf, rakam, _, - ve . içerebilir.'})
                if not password_raw or len(password_raw) < 4:
                    return jsonify({'status': 'error', 'message': 'Şifre en az 4 karakter olmalıdır.'})
                
                check_user = supabase.table('users').select('username').ilike('username', username).execute()
                
                if check_user.data: 
                    return jsonify({'status': 'error', 'message': 'Bu kullanıcı adı zaten alınmış!'})
                    
                current_month = datetime.datetime.now().strftime("%Y-%m")
                current_week = datetime.datetime.now().strftime("%Y-%V")
                
                email = html.escape(data.get('email', '').strip())
                marketing = data.get('marketing', False)
                verification_code = ""
                needs_verification = False
                
                # Email girilmişse @gmail.com olmalı (zorunlu değil ama girilmişse geçerli olmalı)
                if email and not email.lower().endswith('@gmail.com'):
                    return jsonify({'status': 'error', 'message': 'Girilen e-posta @gmail.com uzantılı değil. Lütfen Gmail adresinizi girin ya da alanı boş bırakın.'})
                
                ref_code = html.escape(data.get('ref_code', '').strip())
                ref_reward = html.escape(data.get('ref_reward', ''))
                ref_user_actual = None
                
                if ref_code:
                    if not email or not email.lower().endswith('@gmail.com'):
                        return jsonify({'status': 'error', 'message': 'Referans kodu kullanabilmek için @gmail.com adresinizle kayıt olmalısınız! (Spam koruması)'})
                    
                    # ref_code stats alanında aranıyor (username değil)
                    all_ref_res = supabase.table('users').select('username, stats').execute()
                    ref_user_actual = None
                    for u in all_ref_res.data:
                        s = u.get('stats', {})
                        if isinstance(s, str):
                            try: s = json.loads(s)
                            except: s = {}
                        if isinstance(s, dict) and s.get('ref_code', '').upper() == ref_code.upper():
                            ref_user_actual = {'username': u['username'], 'stats': s}
                            break
                    if not ref_user_actual:
                        return jsonify({'status': 'error', 'message': 'Geçersiz referans kodu!'})
                        
                    ref_stats = ref_user_actual.get('stats', {})
                    if isinstance(ref_stats, str):
                        try: ref_stats = json.loads(ref_stats)
                        except: ref_stats = {}
                        
                    if ref_stats.get('ref_month') != current_month:
                        ref_stats['ref_month'] = current_month
                        ref_stats['ref_count'] = 0
                        
                    if ref_stats.get('ref_count', 0) >= 10:
                        return jsonify({'status': 'error', 'message': 'Bu referans kodunun sahibi bu ayki maksimum davet sınırına (10 kişi) ulaşmış!'})
                
                if email:
                    # Email benzersizlik kontrolü - tüm tablo taraması yerine sadece email ile ara
                    all_email_res = supabase.table('users').select('username, stats').execute()
                    for u in all_email_res.data:
                        s = u.get('stats', {})
                        if isinstance(s, str):
                            try: s = json.loads(s)
                            except: s = {}
                        if isinstance(s, dict) and s.get('email', '').strip().lower() == email.lower():
                            return jsonify({'status': 'error', 'message': 'Bu e-posta adresi sistemde zaten kayıtlı! Başka bir e-posta deneyin.'})
                
                if email:
                    verification_code = str(random.randint(100000, 999999))
                    needs_verification = True
                
                start_xp = 100
                start_tier = 3  # Yeni uyeler: 3 gun ucretsiz Ultra+ deneme
                start_color = "ult-gold"
                start_exp_date = (datetime.datetime.now() + datetime.timedelta(days=3)).strftime("%Y-%m-%d")
                start_is_trial = True

                if ref_code and ref_reward:
                    if ref_reward == 'xp_500':
                        start_xp += 500
                    else:
                        days = 0
                        if ref_reward == 'prem_dlx_2': start_tier = 2; days = 2; start_color = 'dlx-blue'
                        elif ref_reward == 'prem_ult_1': start_tier = 3; days = 1; start_color = 'ult-gold'
                        elif ref_reward == 'prem_std_7': start_tier = 1; days = 7; start_color = 'std-blue'
                        start_exp_date = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")

                data['username'] = username
                data['name'] = html.escape(data.get('name', '').strip())
                data['bio'] = html.escape(data.get('bio', '').strip())
                data['city'] = html.escape(data.get('city', '').strip())
                data['avatar'] = "https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg"
                data['password'] = generate_password_hash(password_raw)
                data['role'] = 'user'
                data['xp'] = start_xp
                
                new_stats = {
                    "markers": 0, "events": 0, "market": 0, "premium_tier": start_tier, "premium_color": start_color, "avatar_effect": "none",
                    "login_streak": 1, "last_login": datetime.datetime.now().strftime("%Y-%m-%d"),
                    "monthly_xp": start_xp, "weekly_xp": start_xp, "current_month": current_month, "current_week": current_week,
                    "missions": {}, "daily_missions": {}, "weekly_missions": {},
                    "garage": [], "total_messages": 0, "profile_views": 0, "ai_usage_date": "", "ai_usage_count": 0,
                    "onboarding": False, "is_trial": True, "trial_notified": False,
                    "last_seen_ts": int(time.time()),
                    "email": email, "email_verified": False, "marketing_opt_in": marketing, "verification_code": verification_code,
                    "ref_month": current_month, "ref_count": 0, "claimable_refs": 0,
                    "ref_code": (username[:3].upper() + str(random.randint(1000, 9999)) + username[-2:].upper()).replace(' ', '')
                }
                if start_exp_date:
                    new_stats["premium_expire_date"] = start_exp_date
                    # expiry_ts: heartbeat kontrolü için unix timestamp olarak da sakla
                    try:
                        _exp_dt_reg = datetime.datetime.strptime(start_exp_date, "%Y-%m-%d")
                        new_stats["expiry_ts"] = int(_exp_dt_reg.timestamp())
                    except Exception:
                        new_stats["expiry_ts"] = int((datetime.datetime.now() + datetime.timedelta(days=3)).timestamp())
                    
                data['stats'] = new_stats
                data['accepted_chat_rules'] = False
                
                data.pop('email', None)
                data.pop('marketing', None)
                data.pop('ref_code', None)
                data.pop('ref_reward', None)
                
                # Önce yeni kullanıcıyı oluştur
                supabase.table('users').insert(data).execute()
                
                # Toplam kullanıcı sayacını artır
                try:
                    uc_r = supabase.table('settings').select('value').eq('id', 'total_users_count').execute()
                    if uc_r.data:
                        new_count = int(uc_r.data[0]['value']) + 1
                        supabase.table('settings').update({'value': str(new_count)}).eq('id', 'total_users_count').execute()
                except Exception as uc_e:
                    print(f"⚠️ Kullanıcı sayacı güncelleme hatası: {uc_e}")
                
                # Başarılı olursa davet edenin bilgilerini GÜNCEL olarak çek ve ANINDA ÖDÜL VER
                if ref_code and ref_user_actual:
                    try:
                        latest_ref_res = supabase.table('users').select('xp, stats').eq('username', ref_user_actual['username']).execute()
                        if latest_ref_res.data:
                            latest_stats = latest_ref_res.data[0].get('stats', {})
                            latest_xp = latest_ref_res.data[0].get('xp', 0)
                            if isinstance(latest_stats, str):
                                try: latest_stats = json.loads(latest_stats)
                                except: latest_stats = {}
                            
                            latest_stats['ref_count'] = latest_stats.get('ref_count', 0) + 1
                            # Davet edene claimable_refs ekle (claim butonu çalışsın)
                            latest_stats['claimable_refs'] = latest_stats.get('claimable_refs', 0) + 1
                            supabase.table('users').update({'xp': latest_xp, 'stats': latest_stats}).eq('username', ref_user_actual['username']).execute()
                    except Exception as e:
                        print("Referans ekleme hatası:", e)
                
                if needs_verification:
                    email_html = f"<h3>FreeriderTR'ye Hoş Geldin!</h3><p>Hesabını doğrulamak için kodun: <b style='font-size: 24px;'>{verification_code}</b></p>"
                    send_resend_email(email, "FreeriderTR E-posta Doğrulama", email_html)
                    return jsonify({'status': 'needs_verification', 'username': username})
                    
                return jsonify({'status': 'ok'})

            elif action == 'verify_email':
                u_name = data.get('username', '').strip()
                code = str(data.get('code', '')).strip()
                if not u_name or not code:
                    return jsonify({'status': 'error', 'message': 'Eksik parametre.'})
                # Giriş yapmış kullanıcı yalnızca kendi e-postasını doğrulayabilir
                if 'username' in session and session['username'] != u_name:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz işlem.'})
                u_res = supabase.table('users').select('stats').eq('username', u_name).execute()
                if u_res.data:
                    stats = u_res.data[0].get('stats', {})
                    if isinstance(stats, str):
                        try: stats = json.loads(stats)
                        except: stats = {}
                    if str(stats.get('verification_code')) == code and str(stats.get('verification_code')) != '':
                        stats['email_verified'] = True
                        stats['verification_code'] = ""
                        supabase.table('users').update({'stats': stats}).eq('username', u_name).execute()
                        return jsonify({'status': 'ok'})
                    else:
                        return jsonify({'status': 'error', 'message': 'Hatalı kod girdiniz!'})
                return jsonify({'status': 'error', 'message': 'Kullanıcı bulunamadı.'})

            elif action == 'request_reset':
                email = data.get('email', '').strip().lower()
                if not email or '@' not in email:
                    return jsonify({'status': 'error', 'message': 'Geçerli bir e-posta adresi girin.'})
                u_res = supabase.table('users').select('username, stats').execute()
                target_user = None
                
                for u in u_res.data:
                    s = u.get('stats')
                    if isinstance(s, str):
                        try: s = json.loads(s)
                        except: s = {}
                    
                    if isinstance(s, dict):
                        u_email = s.get('email', '')
                        if u_email and u_email.strip().lower() == email:
                            target_user = u
                            break
                        
                if target_user:
                    code = str(random.randint(100000, 999999))
                    stats = target_user['stats']
                    if isinstance(stats, str):
                        try: stats = json.loads(stats)
                        except: stats = {}
                        
                    stats['reset_code'] = code
                    stats['reset_code_ts'] = int(time.time())  # 15 dakika geçerli
                    supabase.table('users').update({'stats': stats}).eq('username', target_user['username']).execute()
                    
                    email_html = f"<h3>FreeriderTR Şifre Sıfırlama</h3><p>Şifrenizi sıfırlamak için onay kodunuz: <b style='font-size: 24px;'>{code}</b></p>"
                    send_resend_email(email, "FreeriderTR Şifre Sıfırlama Talebi", email_html)
                    return jsonify({'status': 'ok'})
                else:
                    return jsonify({'status': 'error', 'message': 'Bu e-posta adresine ait bir hesap bulunamadı. Lütfen e-postayı doğru yazdığınızdan emin olun.'})

            elif action == 'reset_password_code':
                email = data.get('email', '').strip().lower() 
                code = data.get('code', '').strip()
                new_pw = data.get('new_password', '').strip()
                
                if len(new_pw) < 4:
                    return jsonify({'status': 'error', 'message': 'Şifre en az 4 karakter olmalıdır!'})
                
                u_res = supabase.table('users').select('username, stats').execute()
                target_user = None
                
                for u in u_res.data:
                    s = u.get('stats')
                    if isinstance(s, str):
                        try: s = json.loads(s)
                        except: s = {}
                        
                    if isinstance(s, dict):
                        u_email = s.get('email', '')
                        code_ts = int(s.get('reset_code_ts', 0))
                        code_expired = (int(time.time()) - code_ts) > 900  # 15 dakika
                        if u_email and u_email.strip().lower() == email and str(s.get('reset_code')) == code and not code_expired:
                            target_user = u
                            break
                        
                if target_user:
                    stats = target_user['stats']
                    if isinstance(stats, str):
                        try: stats = json.loads(stats)
                        except: stats = {}
                        
                    stats['reset_code'] = ""
                    stats.pop('reset_code_ts', None)
                    hashed_pw = generate_password_hash(new_pw)
                    supabase.table('users').update({'password': hashed_pw, 'stats': stats}).eq('username', target_user['username']).execute()
                    return jsonify({'status': 'ok'})
                else:
                    return jsonify({'status': 'error', 'message': 'Hatalı kod veya e-posta!'})

            elif action == 'logout': 
                session.clear()
                return jsonify({'status': 'ok'})

            if 'username' not in session: 
                return jsonify({'status': 'error', 'message': 'Giriş yapmalısınız!'})
                
            current_username = session['username']
            is_main_admin = (session.get('role') == 'Admin' or current_username == 'Admin')
            is_admin = is_main_admin or session.get('role') == 'SubAdmin'

            # Ban kontrolu — admin olmayan banli kullanicilarin yazma islemlerini engelle
            if not is_admin and supabase:
                try:
                    ban_check = supabase.table('banned').select('username').eq('username', current_username).execute()
                    if ban_check.data:
                        session.clear()
                        return jsonify({'status': 'error', 'message': 'Hesabiniz banlanmistir!'})
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~1906]: {_exc}')

            if action == 'claim_ref_reward':
                reward_choice = data.get('reward_choice')
                u_res = supabase.table('users').select('xp, stats').eq('username', current_username).execute()
                if u_res.data:
                    user_data = u_res.data[0]
                    stats = user_data.get('stats', {})
                    if stats.get('claimable_refs', 0) > 0:
                        stats['claimable_refs'] -= 1
                        
                        if reward_choice == 'xp_500':
                            new_xp = user_data.get('xp', 0) + 500
                            stats['monthly_xp'] = stats.get('monthly_xp', 0) + 500
                            stats['weekly_xp'] = stats.get('weekly_xp', 0) + 500
                            supabase.table('users').update({'xp': new_xp, 'stats': stats}).eq('username', current_username).execute()
                        else:
                            days = 0
                            tier = 0
                            color = ""
                            if reward_choice == 'prem_dlx_2': tier = 2; days = 2; color = 'dlx-blue'
                            elif reward_choice == 'prem_ult_1': tier = 3; days = 1; color = 'ult-gold'
                            elif reward_choice == 'prem_std_7': tier = 1; days = 7; color = 'std-blue'
                            
                            current_tier = int(stats.get('premium_tier', 0))
                            if tier >= current_tier:
                                stats['premium_tier'] = tier
                                _exp_ref_dt = datetime.datetime.now() + datetime.timedelta(days=days)
                                exp_date = _exp_ref_dt.strftime("%Y-%m-%d")
                                stats['premium_expire_date'] = exp_date
                                # expiry_ts: heartbeat ile süre kontrolü için zorunlu
                                stats['expiry_ts'] = int(_exp_ref_dt.timestamp())
                                if 'premium_color' not in stats or not stats['premium_color']:
                                    stats['premium_color'] = color
                            supabase.table('users').update({'stats': stats}).eq('username', current_username).execute()
                            
                        return jsonify({'status': 'ok'})
                return jsonify({'status': 'error', 'message': 'Ödül alınamadı.'})

            elif action == 'send_profile_verification':
                email = data.get('email', '').strip()
                marketing = data.get('marketing', False)
                
                if email:
                    all_users = supabase.table('users').select('username, stats').execute()
                    for u in all_users.data:
                        if u.get('username') != current_username:
                            s = u.get('stats', {})
                            if isinstance(s, str):
                                try: s = json.loads(s)
                                except: s = {}
                            if isinstance(s, dict) and s.get('email', '').strip().lower() == email.lower():
                                return jsonify({'status': 'error', 'message': 'Bu e-posta adresi başka bir hesaba kayıtlı!'})
                
                u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                if u_res.data:
                    stats = u_res.data[0].get('stats', {})
                    code = str(random.randint(100000, 999999))
                    stats['email'] = email
                    stats['marketing_opt_in'] = marketing
                    stats['verification_code'] = code
                    stats['email_verified'] = False
                    supabase.table('users').update({'stats': stats}).eq('username', current_username).execute()
                    
                    email_html = f"<h3>FreeriderTR E-posta Doğrulama</h3><p>Profilinize eklediğiniz e-posta adresini doğrulamak için kodunuz: <b style='font-size: 24px;'>{code}</b></p>"
                    send_resend_email(email, "FreeriderTR E-posta Doğrulama", email_html)
                    return jsonify({'status': 'ok'})

            elif action == 'get_payment_url':
                # Google Play IAP mimarisinde ödeme mobil uygulama üzerinden gerçekleşir.
                # Bu endpoint artık yalnızca geriye dönük uyumluluk için bilgilendirme döndürür.
                # Mobil uygulama Google Play Billing Library'yi doğrudan çağırmalı,
                # ardından /api/verify_google_purchase ile token'ı backend'e iletmelidir.
                return jsonify({
                    'status': 'info',
                    'message': 'Ödeme işlemi mobil uygulama üzerinden Google Play Store üzerinden gerçekleştirilmelidir.',
                })

            elif action == 'update_user':
                target = data.get('username')
                if target != current_username and not is_admin: 
                    return jsonify({'status': 'error', 'message': 'Yetkisiz işlem!'})

                old_res = supabase.table('users').select('*').eq('username', target).execute()
                if old_res.data:
                    old_user = old_res.data[0]

                    # --- Şifre: ayrı olarak işle, update payload'a ASLA ekleme ---
                    new_pass = data.get('password')
                    if new_pass and str(new_pass).strip() and len(str(new_pass).strip()) >= 4:
                        hashed = generate_password_hash(str(new_pass).strip())
                        supabase.table('users').update({'password': hashed}).eq('username', target).execute()

                    old_stats = old_user.get('stats', {})
                    if isinstance(old_stats, str):
                        try: old_stats = json.loads(old_stats)
                        except: old_stats = {}

                    new_stats = data.get('stats', old_stats)
                    if not isinstance(new_stats, dict):
                        new_stats = old_stats

                    # --- Sunucu tarafından yönetilen alanları client'ın üzerine yazmasını engelle ---
                    PROTECTED_STATS = [
                        'premium_tier', 'premium_color', 'premium_expire_date', 'is_trial',
                        'trial_expired', 'last_login', 'login_streak',
                        'xp', 'monthly_xp', 'weekly_xp',
                        'markers', 'events', 'market', 'total_messages',
                        'missions', 'daily_missions', 'weekly_missions',
                        'last_spin_date', 'spin_count',
                        'ai_usage_date', 'ai_usage_count',
                        'ref_count', 'claimable_refs', 'ref_month',
                        'email_verified', 'verification_code', 'reset_code',
                        'earned_badges', 'profile_views',
                        # Ek korunan alanlar — backend tarafindan yonetilir
                        'last_miss_notif_ts', 'last_reward_week', 'last_reward_month',
                        'pending_premium', 'ref_code', 'last_seen_ts',
                    ]
                    if not is_admin:
                        for field in PROTECTED_STATS:
                            if field in old_stats:
                                new_stats[field] = old_stats[field]
                            elif field in new_stats:
                                del new_stats[field]

                    # --- XP ve role koru (admin hariç) ---
                    if not is_admin:
                        data['xp'] = old_user.get('xp', 0)
                        data['role'] = old_user.get('role', 'user')

                    # --- Sürüş modu bildirimi ---
                    riding_until_new = new_stats.get('riding_until', 0)
                    if riding_until_new and riding_until_new > int(time.time() * 1000):
                        old_riding = old_stats.get('riding_until', 0)
                        if riding_until_new != old_riding:
                            try:
                                broadcast_push(
                                    title=f"🚴 {current_username} sürüşe çıktı!",
                                    body="Canlı haritada takip et — kim bilir ne bulur! 🏔️",
                                    exclude_user=current_username,
                                    url="/"
                                )
                            except Exception as _exc:
                                import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2051]: {_exc}')

                    # --- Email değişikliği doğrulama ---
                    new_email = new_stats.get('email', '').strip().lower()
                    old_email = old_stats.get('email', '').strip().lower()
                    if new_email and new_email == old_email:
                        new_stats['email_verified'] = old_stats.get('email_verified', False)
                    if new_email and new_email != old_email:
                        all_users = supabase.table('users').select('username, stats').execute()
                        for u in all_users.data:
                            if u.get('username') != target:
                                s = u.get('stats', {})
                                if isinstance(s, str):
                                    try: s = json.loads(s)
                                    except: s = {}
                                if isinstance(s, dict) and s.get('email', '').strip().lower() == new_email:
                                    return jsonify({'status': 'error', 'message': 'Bu e-posta adresi başka bir hesaba kayıtlı!'})

                    # --- Sadece güvenli alanları güncelle (password asla buraya girmiyor) ---
                    safe_update = {
                        'name': data.get('name', old_user.get('name', '')),
                        'bio': data.get('bio', old_user.get('bio', '')),
                        'city': data.get('city', old_user.get('city', '')),
                        'avatar': data.get('avatar', old_user.get('avatar', '')),
                        'stats': new_stats,
                    }
                    if is_admin:
                        safe_update['xp'] = data.get('xp', old_user.get('xp', 0))
                        safe_update['role'] = data.get('role', old_user.get('role', 'user'))
                    else:
                        safe_update['xp'] = old_user.get('xp', 0)
                        safe_update['role'] = old_user.get('role', 'user')

                    supabase.table('users').update(safe_update).eq('username', target).execute()
                    return jsonify({'status': 'ok'})
                    
            elif action == 'increment_profile_view':
                target_user = data.get('username', '').strip()
                # Kendi profilini görüntüleme sayımaz
                if target_user and target_user != current_username:
                    u_res = supabase.table('users').select('stats').eq('username', target_user).execute()
                    if u_res.data:
                        stats = u_res.data[0].get('stats', {}) or {}
                        if isinstance(stats, str):
                            try: stats = json.loads(stats)
                            except: stats = {}
                        old_views = stats.get('profile_views', 0)
                        new_views = old_views + 1
                        stats['profile_views'] = new_views
                        supabase.table('users').update({"stats": stats}).eq('username', target_user).execute()
                        # ── Milestone bildirimleri: 10, 25, 50, 100, 250, 500, 1000... ──
                        milestones = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
                        try:
                            if new_views in milestones:
                                send_push_to_user(
                                    target_user,
                                    title=f"👀 Profilin {new_views} kez görüntülendi!",
                                    body=f"{current_username} ve diğerleri profilini inceledi. Harika içerik paylaşmaya devam et! 🔥",
                                    url="/"
                                )
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2112]: {_exc}')

            elif action == 'accept_chat_rules': 
                supabase.table('users').update({"accepted_chat_rules": True}).eq('username', current_username).execute()
                
            elif action == 'update_user_role':
                if is_admin: 
                    supabase.table('users').update({"role": data.get('role')}).eq('username', data.get('username')).execute()
                    
            elif action == 'give_xp':
                if is_admin:
                    try:
                        xp_amount = int(data.get('amount', 0))
                        if xp_amount <= 0:
                            return jsonify({'status': 'error', 'message': 'Geçersiz XP miktarı.'})
                        u_res = supabase.table('users').select('xp, stats').eq('username', data.get('username')).execute()
                        if u_res.data: 
                            new_xp = u_res.data[0].get('xp', 0) + xp_amount
                            stats = u_res.data[0].get('stats', {}) or {}
                            if isinstance(stats, str):
                                try: stats = json.loads(stats)
                                except: stats = {}
                            stats['monthly_xp'] = stats.get('monthly_xp', 0) + xp_amount
                            stats['weekly_xp'] = stats.get('weekly_xp', 0) + xp_amount
                            supabase.table('users').update({"xp": new_xp, "stats": stats}).eq('username', data.get('username')).execute()
                    except (ValueError, TypeError) as e:
                        return jsonify({'status': 'error', 'message': 'Geçersiz XP değeri.'})

            elif action == 'admin_approve_premium':
                # Admin manuel onayı — Google Play IAP dışında kalan özel durumlar için
                # (promosyon, test, iade sonrası yeniden aktivasyon vb.)
                if is_admin:
                    target = data.get('username')
                    tier = int(data.get('tier', 0))
                    days = int(data.get('days', 30))  # varsayılan 30 gün
                    u_res = supabase.table('users').select('stats').eq('username', target).execute()
                    if u_res.data:
                        stats = u_res.data[0].get('stats', {})
                        if isinstance(stats, str):
                            try: stats = json.loads(stats)
                            except: stats = {}
                        stats['premium_tier'] = tier
                        stats.pop('pending_premium', None)
                        if 'premium_color' not in stats or not stats['premium_color']:
                            color_map = {1: 'std-blue', 2: 'dlx-blue', 3: 'ult-gold'}
                            stats['premium_color'] = color_map.get(tier, 'std-blue')
                        if tier > 0:
                            exp_dt = datetime.datetime.now() + datetime.timedelta(days=days)
                            stats['premium_expire_date'] = exp_dt.strftime("%Y-%m-%d")
                            stats['expiry_ts'] = int(exp_dt.timestamp())
                            # Admin onayı olduğunu işaretle (IAP token'ı olmayan manuel aktivasyonlar)
                            stats['gp_admin_override'] = True
                        else:
                            stats.pop('premium_expire_date', None)
                            stats.pop('expiry_ts', None)
                            stats.pop('gp_admin_override', None)
                        supabase.table('users').update({"stats": stats}).eq('username', target).execute()
                        logger.info(f"Admin manuel premium onayı: {target} → tier {tier} ({days} gün)")

            elif action == 'admin_reject_premium':
                # Admin manuel reddi — IAP dışı pending durumlarını temizler
                if is_admin:
                    target = data.get('username')
                    u_res = supabase.table('users').select('stats').eq('username', target).execute()
                    if u_res.data:
                        stats = u_res.data[0].get('stats', {})
                        if isinstance(stats, str):
                            try: stats = json.loads(stats)
                            except: stats = {}
                        stats.pop('pending_premium', None)
                        supabase.table('users').update({"stats": stats}).eq('username', target).execute()
                        logger.info(f"Admin premium reddi: {target}")

            elif action == 'admin_toggle_premium':
                if is_admin:
                    target = data.get('username')
                    tier = int(data.get('tier', 0))
                    days = int(data.get('days', 30))  # varsayılan 30 gün
                    u_res = supabase.table('users').select('stats').eq('username', target).execute()
                    if u_res.data:
                        stats = u_res.data[0].get('stats', {})
                        if isinstance(stats, str):
                            try: stats = json.loads(stats)
                            except: stats = {}
                        stats['premium_tier'] = tier
                        stats.pop('pending_premium', None)
                        if 'premium_color' not in stats or not stats['premium_color']:
                            color_map = {1: 'std-blue', 2: 'dlx-blue', 3: 'ult-gold'}
                            stats['premium_color'] = color_map.get(tier, 'std-blue')
                        if tier > 0:
                            exp_dt = datetime.datetime.now() + datetime.timedelta(days=days)
                            stats['premium_expire_date'] = exp_dt.strftime("%Y-%m-%d")
                            stats['expiry_ts'] = int(exp_dt.timestamp())
                        else:
                            stats.pop('premium_expire_date', None)
                            stats.pop('expiry_ts', None)
                        supabase.table('users').update({"stats": stats}).eq('username', target).execute()
                        
            elif action == 'update_premium_color':
                u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                if u_res.data:
                    stats = u_res.data[0].get('stats', {})
                    if stats.get('premium_tier', 0) > 0: 
                        stats['premium_color'] = data.get('color', 'std-blue')
                        stats['avatar_effect'] = data.get('effect', 'none')
                        supabase.table('users').update({"stats": stats}).eq('username', current_username).execute()

            elif action == 'add_marker':
                # addedBy her zaman sunucu tarafından atanır — istemci manipülasyonu engellenir
                data['addedBy'] = current_username
                data['id'] = str(data['id'])
                if 'likes' not in data: data['likes'] = []
                if 'dislikes' not in data: data['dislikes'] = []
                if 'fake_reports' not in data: data['fake_reports'] = []
                
                try:
                    supabase.table('markers').upsert(data).execute()
                except Exception as e:
                    error_msg = str(e)
                    if 'icon_type' in error_msg or 'PGRST' in error_msg or 'dislikes' in error_msg:
                        if 'dislikes' in data: data.pop('dislikes', None)
                        if 'icon_type' in data: data.pop('icon_type', None)
                        supabase.table('markers').upsert(data).execute()
                    else:
                        raise e
                
                marker_check = supabase.table('markers').select('id').eq('id', data['id']).execute()
                if not marker_check.data or len(marker_check.data) == 0:
                    u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                    if u_res.data:
                        stats = u_res.data[0].get('stats', {})
                        stats['markers'] = stats.get('markers', 0) + 1
                        supabase.table('users').update({"stats": stats}).eq('username', current_username).execute()
                    # Yeni rampa bildirimi - herkese
                    try:
                        marker_name = data.get('name', 'Yeni Nokta')
                        broadcast_push(
                            title=f"📍 Yeni Rampa Eklendi!",
                            body=f"{current_username} haritaya '{marker_name}' ekledi",
                            exclude_user=current_username,
                            url="/"
                        )
                    except Exception as _exc:
                        import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2247]: {_exc}')
                
            elif action == 'delete_marker':
                m_res = supabase.table('markers').select('addedBy').eq('id', str(data.get('id'))).execute()
                if m_res.data:
                    if is_admin or m_res.data[0].get('addedBy') == current_username:
                        supabase.table('markers').delete().eq('id', str(data.get('id'))).execute()
                    
            elif action == 'like_marker':
                m_res = supabase.table('markers').select('likes, dislikes, addedBy, name').eq('id', str(data.get('id'))).execute()
                if m_res.data:
                    likes      = m_res.data[0].get('likes', [])
                    dislikes   = m_res.data[0].get('dislikes', [])
                    m_owner    = m_res.data[0].get('addedBy', '')
                    m_name     = (m_res.data[0].get('name') or 'Rampa')[:40]
                    was_liked  = current_username in likes
                    if was_liked:
                        likes.remove(current_username)
                    else: 
                        likes.append(current_username)
                        if current_username in dislikes: dislikes.remove(current_username)
                    
                    update_payload = {"likes": likes}
                    if 'dislikes' in m_res.data[0]: update_payload["dislikes"] = dislikes
                    supabase.table('markers').update(update_payload).eq('id', str(data.get('id'))).execute()
                    # ── Rampa sahibine beğeni bildirimi (milestone: 5, 10, 25, 50) ──
                    if not was_liked and m_owner and m_owner != current_username:
                        try:
                            new_like_count = len(likes)
                            if new_like_count in [1, 5, 10, 25, 50, 100]:
                                send_push_to_user(
                                    m_owner,
                                    title=f"👍 '{m_name}' {new_like_count} beğeni aldı!",
                                    body=f"{current_username} ve diğerleri rampanı seviyor 🏔️",
                                    url="/"
                                )
                            elif new_like_count == 1:
                                send_push_to_user(
                                    m_owner,
                                    title=f"👍 {current_username} rampanı beğendi!",
                                    body=f"'{m_name}' haritasındaki noktana ilk beğeni geldi!",
                                    url="/"
                                )
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2291]: {_exc}')

            elif action == 'dislike_marker':
                m_res = supabase.table('markers').select('likes, dislikes').eq('id', str(data.get('id'))).execute()
                if m_res.data:
                    likes = m_res.data[0].get('likes', [])
                    dislikes = m_res.data[0].get('dislikes', [])
                    if current_username in dislikes: 
                        dislikes.remove(current_username)
                    else: 
                        dislikes.append(current_username)
                        if current_username in likes: likes.remove(current_username)
                    
                    update_payload = {"dislikes": dislikes, "likes": likes}
                    try:
                        supabase.table('markers').update(update_payload).eq('id', str(data.get('id'))).execute()
                    except Exception as e:
                        print(f"⚠️ Marker beğeni güncelleme hatası: {e}")

            elif action == 'add_message':
                # Sohbet kurallari backend kontrolu
                try:
                    chat_user_res = supabase.table('users').select('accepted_chat_rules').eq('username', current_username).execute()
                    if chat_user_res.data and not chat_user_res.data[0].get('accepted_chat_rules'):
                        return jsonify({'status': 'error', 'message': 'Sohbet kurallarını kabul etmeden mesaj gönderemezsiniz.'})
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2317]: {_exc}')
                if data.get('type') == 'text':
                    raw_text = data.get('text', '').strip()
                    if not raw_text:
                        return jsonify({'status': 'error', 'message': 'Boş mesaj gönderilemez.'})
                    if len(raw_text) > 1000:
                        return jsonify({'status': 'error', 'message': 'Mesaj çok uzun (max 1000 karakter).'})
                    data['text'] = html.escape(raw_text)
                data['user'] = current_username
                data['id'] = str(data.get('id') or uuid.uuid4().hex)
                supabase.table('messages').upsert(data).execute()
                
                u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                if u_res.data:
                    stats = u_res.data[0].get('stats', {}) or {}
                    if isinstance(stats, str):
                        try: stats = json.loads(stats)
                        except: stats = {}
                    stats['total_messages'] = stats.get('total_messages', 0) + 1
                    stats['last_seen_ts'] = int(time.time())
                    supabase.table('users').update({"stats": stats}).eq('username', current_username).execute()

                # ── Grup chat bildirimi (flood korumalı: 3 dk'da bir max 1 bildirim) ──
                try:
                    if data.get('type') == 'text' and _can_broadcast_chat():
                        msg_preview = data.get('text', '')[:60]
                        broadcast_push(
                            title=f"💬 {current_username} yazdı",
                            body=msg_preview,
                            exclude_user=current_username,
                            url="/"
                        )
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2350]: {_exc}')

            elif action == 'ask_ai':
                text = html.escape(data.get('text', '').strip())
                if not text:
                    return jsonify({'status': 'error', 'message': 'Boş soru sorulamaz.'})
                    
                u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                if not u_res.data:
                    return jsonify({'status': 'error'})
                user_data = u_res.data[0]
                
                can_use, error_msg = check_ai_limit(current_username, user_data)
                if not can_use:
                    return jsonify({'status': 'error', 'message': error_msg})

                user_msg_id = uuid.uuid4().hex
                supabase.table('messages').upsert({
                    'id': user_msg_id, 
                    'user': current_username, 
                    'text': text, 
                    'type': 'text'
                }).execute()

                ai_reply = _call_groq_ai(_GROQ_SYSTEM_CHAT, text)

                ai_msg_id = uuid.uuid4().hex
                supabase.table('messages').upsert({
                    'id': ai_msg_id,
                    'user': 'Freerider AI',
                    'text': f"@{current_username} {ai_reply}",
                    'type': 'text'
                }).execute()
                    
            elif action == 'pin_message':
                if not is_admin:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz işlem!'})
                val = json.dumps(data)
                supabase.table('settings').upsert({"id": "pinned_message", "value": val}).execute()
                
            elif action == 'delete_message':
                msg_id = str(data.get('id'))
                msg_res = supabase.table('messages').select('user').eq('id', msg_id).execute()
                if msg_res.data:
                    if is_admin or msg_res.data[0].get('user') == current_username: 
                        supabase.table('messages').delete().eq('id', msg_id).execute()
                        
            elif action == 'send_dm':
                receiver = data.get('receiver', '').strip()
                if not receiver: 
                    return jsonify({'status': 'error', 'message': 'Alıcı seçilmedi.'})
                if data.get('type') == 'text':
                    raw_dm = data.get('text', '').strip()
                    if not raw_dm:
                        return jsonify({'status': 'error', 'message': 'Boş mesaj gönderilemez.'})
                    if len(raw_dm) > 2000:
                        return jsonify({'status': 'error', 'message': 'Mesaj çok uzun (max 2000 karakter).'})
                    data['text'] = html.escape(raw_dm)
                    
                dm_id = str(data.get('id') or uuid.uuid4().hex)
                data['id'] = dm_id
                data['sender'] = current_username
                data['participants'] = [current_username, receiver]
                supabase.table('dms').upsert(data).execute()

                # DM push bildirimi - sadece alıcıya (chat mesajları değil, sadece DM)
                if receiver != 'Freerider AI' and data.get('type') in ('text', 'photo', 'voice'):
                    notif_body = data.get('text', '')[:80] if data.get('type') == 'text' else ('📸 Fotoğraf gönderdi' if data.get('type') == 'photo' else '🎤 Sesli mesaj gönderdi')
                    try:
                        send_push_to_user(
                            receiver,
                            title=f"💬 {current_username} sana mesaj attı",
                            body=notif_body,
                            url="/"
                        )
                    except Exception as _exc:
                        import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2426]: {_exc}')

                if receiver == 'Freerider AI' and data.get('type') == 'text':
                    u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                    if u_res.data:
                        user_data = u_res.data[0]
                        can_use, error_msg = check_ai_limit(current_username, user_data)
                        
                        if not can_use:
                            ai_reply = error_msg
                        else:
                            ai_reply = _call_groq_ai(_GROQ_SYSTEM_DM, data.get('text', ''))

                        ai_dm_id = uuid.uuid4().hex
                        supabase.table('dms').upsert({
                            'id': ai_dm_id,
                            'sender': 'Freerider AI',
                            'receiver': current_username,
                            'participants': [current_username, 'Freerider AI'],
                            'text': ai_reply,
                            'type': 'text'
                        }).execute()

            elif action == 'add_market':
                data['title'] = html.escape(data.get('title', ''))
                data['desc'] = html.escape(data.get('desc', ''))
                data['contact'] = html.escape(data.get('contact', ''))
                data['owner'] = current_username
                data['date'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
                data['id'] = str(data['id'])
                data['views'] = 0
                data['bumped_at'] = int(time.time() * 1000)
                
                try:
                    supabase.table('market').upsert(data).execute()
                    # Yeni ilan bildirimi - herkese
                    try:
                        item_title = data.get('title', 'Yeni Ilan')
                        item_price = data.get('price', '')
                        price_str = f" - {item_price} TL" if item_price else ""
                        broadcast_push(
                            title=f"🛒 Yeni İlan: {item_title}",
                            body=f"{current_username} yeni bir ilan yayınladı{price_str}",
                            exclude_user=current_username,
                            url="/"
                        )
                    except Exception as _exc:
                        import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2473]: {_exc}')
                except Exception as e:
                    error_msg = str(e)
                    if 'views' in error_msg or 'bumped_at' in error_msg or 'PGRST' in error_msg:
                        data.pop('views', None)
                        data.pop('bumped_at', None)
                        supabase.table('market').upsert(data).execute()
                    else:
                        raise e
                
                u_res_full = supabase.table('users').select('stats').eq('username', current_username).execute()
                if u_res_full.data:
                    stats = u_res_full.data[0].get('stats', {})
                    stats['market'] = stats.get('market', 0) + 1
                    supabase.table('users').update({"stats": stats}).eq('username', current_username).execute()
                
            elif action == 'bump_market':
                try:
                    supabase.table('market').update({"bumped_at": int(time.time() * 1000)}).eq('id', str(data.get('id'))).execute()
                except Exception as e:
                    print(f"⚠️ Bump market hatası: {e}")
                
            elif action == 'increment_market_view':
                try:
                    m_res = supabase.table('market').select('views, owner, title').eq('id', str(data.get('id'))).execute()
                    if m_res.data:
                        current_views = m_res.data[0].get('views', 0)
                        new_mv = current_views + 1
                        supabase.table('market').update({"views": new_mv}).eq('id', str(data.get('id'))).execute()
                        # ── 10, 50, 100 görüntüleme milestone bildirimi ──
                        market_owner = m_res.data[0].get('owner', '')
                        market_title = (m_res.data[0].get('title') or 'İlanın')[:40]
                        if market_owner and market_owner != current_username and new_mv in [5, 10, 25, 50, 100]:
                            try:
                                send_push_to_user(
                                    market_owner,
                                    title=f"🛒 İlanın {new_mv} kez görüntülendi!",
                                    body=f"'{market_title}' ilanın ilgi görüyor. Fiyatı gözden geçir! 💰",
                                    url="/"
                                )
                            except Exception as _exc:
                                import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2514]: {_exc}')
                except Exception as e:
                    print(f"⚠️ Market görüntülenme sayacı hatası: {e}")
                
            elif action == 'delete_market':
                ad_res = supabase.table('market').select('owner').eq('id', str(data.get('id'))).execute()
                if ad_res.data:
                    if ad_res.data[0].get('owner') == current_username or is_admin: 
                        supabase.table('market').delete().eq('id', str(data.get('id'))).execute()

            elif action == 'add_event':
                data['title'] = html.escape(data.get('title', ''))
                data['desc'] = html.escape(data.get('desc', ''))
                data['creator'] = current_username
                data['attendees'] = [current_username]
                data['xp_awarded'] = False
                data['id'] = str(data['id'])
                supabase.table('events').upsert(data).execute()
                
                u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                if u_res.data:
                    stats = u_res.data[0].get('stats', {})
                    stats['events'] = stats.get('events', 0) + 1
                    supabase.table('users').update({"stats": stats}).eq('username', current_username).execute()
                
                # Yeni buluşma bildirimi - herkese
                try:
                    ev_title = data.get('title', 'Yeni Bulusma')
                    ev_date = data.get('datetime', '')[:10]
                    broadcast_push(
                        title=f"📅 Yeni Buluşma: {ev_title}",
                        body=f"{current_username} bir buluşma oluşturdu! Tarih: {ev_date}",
                        exclude_user=current_username,
                        url="/"
                    )
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2550]: {_exc}')
                
            elif action == 'join_event':
                ev_id = str(data.get('id'))
                event_res = supabase.table('events').select('*').eq('id', ev_id).execute()
                if event_res.data:
                    ev_data = event_res.data[0]
                    att = ev_data.get('attendees', [])
                    max_limit = ev_data.get('max')
                    
                    if current_username not in att: 
                        limit = 0
                        try:
                            if max_limit: limit = int(max_limit)
                        except (ValueError, TypeError):
                            limit = 0
                            
                        if limit > 0 and len(att) >= limit:
                            return jsonify({'status': 'error', 'message': 'Kapasite dolu, maalesef katılamazsınız!'})
                            
                        att.append(current_username)
                        supabase.table('events').update({"attendees": att}).eq('id', ev_id).execute()
                        # ── Etkinlik sahibine bildirim ──
                        try:
                            ev_creator = ev_data.get('creator', '')
                            ev_title_j = ev_data.get('title', 'Etkinlik')[:40]
                            if ev_creator and ev_creator != current_username:
                                send_push_to_user(
                                    ev_creator,
                                    title=f"🎉 {current_username} etkinliğine katıldı!",
                                    body=f"'{ev_title_j}' etkinliğinde yeni katılımcı var!",
                                    url="/"
                                )
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2584]: {_exc}')

            elif action == 'leave_event':
                ev_id = str(data.get('id'))
                event_res = supabase.table('events').select('attendees').eq('id', ev_id).execute()
                if event_res.data:
                    att = event_res.data[0].get('attendees', [])
                    if current_username in att: 
                        att.remove(current_username)
                        supabase.table('events').update({"attendees": att}).eq('id', ev_id).execute()
                        
            elif action == 'delete_event':
                event_res = supabase.table('events').select('creator').eq('id', str(data.get('id'))).execute()
                if event_res.data:
                    if event_res.data[0].get('creator') == current_username or is_admin: 
                        supabase.table('events').delete().eq('id', str(data.get('id'))).execute()

            elif action == 'add_ban':
                if is_admin:
                    target_ban = data.get('username', '')
                    supabase.table('banned').upsert({"username": target_ban, "banned_by": current_username, "ts": int(time.time())}).execute()
                    if not is_main_admin:
                        try:
                            log_entry = {'id': str(int(time.time()*1000)), 'admin': current_username, 'action': 'ban_user', 'target': target_ban, 'detail': f"Kullanıcı banlandı", 'ts': int(time.time())}
                            supabase.table('admin_logs').insert(log_entry).execute()
                            send_push_to_user('Admin', title=f"🚨 Kullanıcı Banlı", body=f"{current_username}, {target_ban} adlı kullanıcıyı banladı.", url="/")
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2611]: {_exc}')
                    
            elif action == 'add_news':
                if is_main_admin:
                    data['id'] = str(data['id'])
                    supabase.table('news').upsert(data).execute()
                    # ── Yeni haber bildirimi: herkese ──
                    try:
                        news_title = data.get('title', 'Yeni Haber')[:50]
                        news_body  = data.get('body', '')[:80] if data.get('body') else "FreeriderTR'de yeni bir haber yayınlandı!"
                        broadcast_push(
                            title=f"📰 {news_title}",
                            body=news_body,
                            url="/"
                        )
                    except Exception as _exc:
                        import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2626]: {_exc}')
                    
            elif action == 'delete_news':
                if is_main_admin: 
                    supabase.table('news').delete().eq('id', str(data['id'])).execute()
                    
            elif action == 'toggle_maintenance':
                if is_main_admin: 
                    val = 'true' if data.get('status') else 'false'
                    supabase.table('settings').upsert({"id": "maintenance", "value": val}).execute()
            
            # =======================================================
            # ÇARK SİSTEMİ 
            # =======================================================
            elif action == 'daily_spin':
                u_res = supabase.table('users').select('xp, stats').eq('username', current_username).execute()
                if not u_res.data:
                    return jsonify({'status': 'error'})

                user_data = u_res.data[0]
                stats = user_data.get('stats', {})
                prem_tier = int(stats.get('premium_tier', 0))

                today_str = datetime.datetime.now().strftime("%Y-%m-%d")
                max_spins = 2 if prem_tier >= 2 else 1

                last_spin_date = stats.get('last_spin_date', '')
                spin_count = stats.get('spin_count', 0)

                if last_spin_date != today_str:
                    spin_count = 0
                    stats['last_spin_date'] = today_str

                if spin_count >= max_spins:
                    return jsonify({'status': 'error', 'message': f'Bugünlük çark hakkın bitti! (Maksimum {max_spins} hak)'})

                prizes = [
                    {"id": "xp_100", "name": "100 XP", "weight": 60, "type": "xp", "val": 100},
                    {"id": "xp_200", "name": "200 XP", "weight": 40, "type": "xp", "val": 200},
                    {"id": "xp_300", "name": "300 XP", "weight": 40, "type": "xp", "val": 300},
                    {"id": "xp_500", "name": "500 XP", "weight": 10, "type": "xp", "val": 500},
                    {"id": "xp_1000", "name": "1000 XP", "weight": 5, "type": "xp", "val": 1000},
                    {"id": "xp_10000", "name": "10000 XP", "weight": 0.01, "type": "xp", "val": 10000},
                    {"id": "xp_100000", "name": "100000 XP", "weight": 0.001, "type": "xp", "val": 100000},
                    # weight=0 olanlar çark havuzunda yer almaz — sadece özel etkinliklerde verilir
                    # {"id": "prem_ult_365", ...} → ağırlık 0 olduğu için listede tutulmuyor
                    {"id": "prem_ult_30", "name": "1 Ay Ultra+", "weight": 0.5, "type": "prem", "tier": 3, "days": 30},
                    {"id": "prem_dlx_30", "name": "1 Ay Deluxe", "weight": 1, "type": "prem", "tier": 2, "days": 30},
                    {"id": "prem_std_30", "name": "1 Ay Standart", "weight": 0.5, "type": "prem", "tier": 1, "days": 30},
                    {"id": "prem_ult_7", "name": "1 Hft Ultra+", "weight": 1, "type": "prem", "tier": 3, "days": 7},
                    {"id": "prem_dlx_7", "name": "1 Hft Deluxe", "weight": 1, "type": "prem", "tier": 2, "days": 7},
                    {"id": "prem_std_7", "name": "1 Hft Standart", "weight": 5, "type": "prem", "tier": 1, "days": 7},
                    {"id": "prem_ult_1", "name": "1 Gün Ultra+", "weight": 5, "type": "prem", "tier": 3, "days": 1},
                    {"id": "prem_dlx_1", "name": "1 Gün Deluxe", "weight": 5, "type": "prem", "tier": 2, "days": 1},
                ]
                # weight=0 olan ödülleri havuzdan çıkar (ZeroDivisionError önleme)
                eligible_prizes = [p for p in prizes if p.get("weight", 0) > 0]
                weights = [p["weight"] for p in eligible_prizes]
                won_prize = random.choices(eligible_prizes, weights=weights, k=1)[0]

                stats['spin_count'] = spin_count + 1

                if won_prize["type"] == "xp":
                    new_xp = user_data.get('xp', 0) + won_prize["val"]
                    stats['monthly_xp'] = stats.get('monthly_xp', 0) + won_prize["val"]
                    stats['weekly_xp'] = stats.get('weekly_xp', 0) + won_prize["val"]
                    supabase.table('users').update({"xp": new_xp, "stats": stats}).eq('username', current_username).execute()
                elif won_prize["type"] == "prem":
                    current_tier = int(stats.get('premium_tier', 0))
                    if won_prize["tier"] >= current_tier:
                        stats['premium_tier'] = won_prize["tier"]
                        if 'premium_color' not in stats or not stats['premium_color']:
                            stats['premium_color'] = 'std-blue'
                        exp_dt = datetime.datetime.now() + datetime.timedelta(days=won_prize["days"])
                        stats['premium_expire_date'] = exp_dt.strftime("%Y-%m-%d")
                        stats['expiry_ts'] = int(exp_dt.timestamp())  # unix timestamp – heartbeat kontrolü için
                    supabase.table('users').update({"stats": stats}).eq('username', current_username).execute()

                return jsonify({'status': 'ok', 'prize_name': won_prize['name'], 'prize_id': won_prize['id']})
                    
            # ================================================================
            # GÖREV TAMAMLAMA (sunucu doğrulu XP ödülü)
            # ================================================================
            elif action == 'claim_mission':
                mission_id   = data.get('mission_id', '')
                mission_type = data.get('mission_type', '')   # 'perm' | 'daily' | 'weekly'
                xp_claim     = int(data.get('xp', 0))

                if not mission_id or mission_type not in ('perm', 'daily', 'weekly') or xp_claim <= 0:
                    return jsonify({'status': 'error', 'message': 'Geçersiz görev.'})

                # Sunucuda taze veriyi çek
                u_res = supabase.table('users').select('xp, stats').eq('username', current_username).execute()
                if not u_res.data:
                    return jsonify({'status': 'error'})

                srv_user  = u_res.data[0]
                srv_stats = srv_user.get('stats', {}) or {}
                if isinstance(srv_stats, str):
                    try: srv_stats = json.loads(srv_stats)
                    except: srv_stats = {}

                today_str = datetime.datetime.now().strftime("%Y-%m-%d")
                now_dt    = datetime.datetime.now()
                monday    = now_dt - datetime.timedelta(days=(now_dt.weekday()))
                week_key  = monday.strftime("%Y-%m-%d")

                # --- Kalıcı görevler ---
                PERM_MISSIONS = {
                    "m1":  {"type": "login_streak",   "target": 1,   "xp": 50},
                    "m2":  {"type": "login_streak",   "target": 7,   "xp": 200},
                    "m3":  {"type": "login_streak",   "target": 30,  "xp": 2000},
                    "m4":  {"type": "login_streak",   "target": 100, "xp": 10000},
                    "m5":  {"type": "total_messages", "target": 1,   "xp": 20},
                    "m6":  {"type": "total_messages", "target": 50,  "xp": 300},
                    "m7":  {"type": "total_messages", "target": 200, "xp": 1000},
                    "m8":  {"type": "markers",        "target": 1,   "xp": 50},
                    "m9":  {"type": "markers",        "target": 10,  "xp": 500},
                    "m10": {"type": "market",         "target": 1,   "xp": 50},
                    "m11": {"type": "market",         "target": 5,   "xp": 300},
                    "m12": {"type": "events",         "target": 1,   "xp": 100},
                    "m13": {"type": "events",         "target": 5,   "xp": 500},
                }

                # --- Günlük görev setleri ---
                day_num = int(datetime.datetime.now().timestamp() // 86400)
                DAILY_SETS = [
                    {"d1":{"type":"daily_login","target":1,"xp":30},"d2":{"type":"daily_msg","target":3,"xp":50},"d3":{"type":"daily_marker","target":1,"xp":80}},
                    {"d1":{"type":"daily_login","target":1,"xp":30},"d4":{"type":"daily_ai","target":1,"xp":40},"d5":{"type":"daily_market","target":1,"xp":20}},
                    {"d1":{"type":"daily_login","target":1,"xp":30},"d6":{"type":"daily_msg","target":5,"xp":70},"d7":{"type":"daily_radar","target":1,"xp":60}},
                ]
                today_daily = DAILY_SETS[day_num % len(DAILY_SETS)]

                # --- Haftalık görev setleri ---
                week_num = int(datetime.datetime.now().timestamp() // (86400 * 7))
                WEEKLY_SETS = [
                    {"w1":{"type":"weekly_msg","target":20,"xp":200},"w2":{"type":"weekly_marker","target":2,"xp":150}},
                    {"w3":{"type":"weekly_event","target":1,"xp":250},"w4":{"type":"weekly_market","target":1,"xp":150}},
                    {"w5":{"type":"weekly_radar","target":3,"xp":200},"w6":{"type":"weekly_ai","target":5,"xp":180}},
                ]
                today_weekly = WEEKLY_SETS[week_num % len(WEEKLY_SETS)]

                earned_xp = 0

                if mission_type == 'perm':
                    m = PERM_MISSIONS.get(mission_id)
                    if not m:
                        return jsonify({'status': 'error', 'message': 'Görev bulunamadı.'})
                    if srv_stats.get('missions', {}).get(mission_id):
                        return jsonify({'status': 'ok', 'earned_xp': 0, 'already_done': True})
                    progress = srv_stats.get(m['type'], 0)
                    if progress < m['target']:
                        return jsonify({'status': 'ok', 'earned_xp': 0, 'not_ready': True})
                    if xp_claim != m['xp']:
                        return jsonify({'status': 'error', 'message': 'XP tutarsızlığı.'})
                    if 'missions' not in srv_stats:
                        srv_stats['missions'] = {}
                    srv_stats['missions'][mission_id] = True
                    earned_xp = m['xp']

                elif mission_type == 'daily':
                    m = today_daily.get(mission_id)
                    if not m:
                        return jsonify({'status': 'ok', 'earned_xp': 0, 'not_ready': True})
                    dm = srv_stats.get('daily_missions', {})
                    if dm.get('date') != today_str:
                        dm = {'date': today_str, 'daily_login': 1}
                    done_key = 'done_' + mission_id
                    if dm.get(done_key):
                        return jsonify({'status': 'ok', 'earned_xp': 0, 'already_done': True})
                    progress = 1 if m['type'] == 'daily_login' else dm.get(m['type'], 0)
                    if progress < m['target']:
                        return jsonify({'status': 'ok', 'earned_xp': 0, 'not_ready': True})
                    if xp_claim != m['xp']:
                        return jsonify({'status': 'error', 'message': 'XP tutarsızlığı.'})
                    dm[done_key] = True
                    srv_stats['daily_missions'] = dm
                    earned_xp = m['xp']

                elif mission_type == 'weekly':
                    m = today_weekly.get(mission_id)
                    if not m:
                        return jsonify({'status': 'ok', 'earned_xp': 0, 'not_ready': True})
                    wm = srv_stats.get('weekly_missions', {})
                    if wm.get('week') != week_key:
                        wm = {'week': week_key}
                    done_key = 'done_' + mission_id
                    if wm.get(done_key):
                        return jsonify({'status': 'ok', 'earned_xp': 0, 'already_done': True})
                    progress = wm.get(m['type'], 0)
                    if progress < m['target']:
                        return jsonify({'status': 'ok', 'earned_xp': 0, 'not_ready': True})
                    if xp_claim != m['xp']:
                        return jsonify({'status': 'error', 'message': 'XP tutarsızlığı.'})
                    wm[done_key] = True
                    srv_stats['weekly_missions'] = wm
                    earned_xp = m['xp']

                if earned_xp > 0:
                    new_xp = srv_user.get('xp', 0) + earned_xp
                    srv_stats['monthly_xp'] = srv_stats.get('monthly_xp', 0) + earned_xp
                    srv_stats['weekly_xp']  = srv_stats.get('weekly_xp',  0) + earned_xp
                    supabase.table('users').update({'xp': new_xp, 'stats': srv_stats}).eq('username', current_username).execute()
                    return jsonify({'status': 'ok', 'earned_xp': earned_xp, 'new_xp': new_xp})

                return jsonify({'status': 'error'})

            # ================================================================
            # YORUMLAR (Marker & Etkinlik yorumları)
            # ================================================================
            elif action == 'rate_marker':
                marker_id = str(data.get('marker_id', '')).strip()
                try:
                    rating = int(data.get('rating', 0))
                except (ValueError, TypeError):
                    rating = 0
                if not marker_id or rating < 1 or rating > 5:
                    return jsonify({'status': 'error', 'message': 'Geçersiz puan!'})
                m_res = supabase.table('markers').select('ratings').eq('id', marker_id).execute()
                if m_res.data:
                    ratings = m_res.data[0].get('ratings') or {}
                    if isinstance(ratings, str):
                        try: ratings = json.loads(ratings)
                        except: ratings = {}
                    ratings[current_username] = rating
                    avg = round(sum(ratings.values()) / len(ratings), 1)
                    supabase.table('markers').update({'ratings': ratings, 'avg_rating': avg}).eq('id', marker_id).execute()

            elif action == 'report_danger':
                marker_id = str(data.get('marker_id',''))
                reason   = html.escape(data.get('reason','').strip())
                if not marker_id or not reason:
                    return jsonify({'status':'error','message':'Sebep yazin!'})
                m_res = supabase.table('markers').select('danger_reports').eq('id', marker_id).execute()
                if m_res.data:
                    dr = m_res.data[0].get('danger_reports') or []
                    if isinstance(dr, str):
                        try: dr = json.loads(dr)
                        except: dr = []
                    dr.append({'user': current_username, 'reason': reason, 'ts': int(time.time())})
                    supabase.table('markers').update({'danger_reports': dr, 'is_dangerous': True}).eq('id', marker_id).execute()
                    # Push admins
                    try:
                        m_name = data.get('marker_name','Bir rampa')
                        broadcast_push(title=f"⚠️ Tehlike: {m_name}", body=f"{current_username}: {reason[:60]}", url="/")
                    except Exception as e:
                        print(f"⚠️ Tehlike bildirimi push hatası: {e}")

            elif action == 'add_reaction':
                msg_id  = str(data.get('msg_id',''))
                emoji   = data.get('emoji','')
                if not msg_id or not emoji: return jsonify({'status':'error'})
                r_res = supabase.table('messages').select('reactions, user').eq('id', msg_id).execute()
                if r_res.data:
                    reactions  = r_res.data[0].get('reactions') or {}
                    msg_author = r_res.data[0].get('user', '')
                    if isinstance(reactions, str):
                        try: reactions = json.loads(reactions)
                        except: reactions = {}
                    users = reactions.get(emoji, [])
                    was_reacted = current_username in users
                    if was_reacted:
                        users.remove(current_username)
                    else:
                        users.append(current_username)
                    reactions[emoji] = users
                    supabase.table('messages').update({'reactions': reactions}).eq('id', msg_id).execute()
                    # ── Mesaj sahibine tepki bildirimi (yeni tepkide, geri almada değil) ──
                    if not was_reacted and msg_author and msg_author != current_username and msg_author != 'Freerider AI':
                        try:
                            send_push_to_user(
                                msg_author,
                                title=f"{emoji} {current_username} mesajına tepki verdi!",
                                body="Chat'teki mesajına bir tepki geldi",
                                url="/"
                            )
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2903]: {_exc}')

            elif action == 'add_comment':
                target_type = data.get('target_type')  # 'marker' or 'event'
                target_id   = str(data.get('target_id', ''))
                text        = html.escape(data.get('text', '').strip())
                if not text or not target_id:
                    return jsonify({'status': 'error', 'message': 'Yorum bos olamaz!'})
                comment = {
                    'id': str(int(time.time() * 1000)),
                    'target_type': target_type,
                    'target_id': target_id,
                    'user': current_username,
                    'text': text,
                    'created_at': int(time.time())
                }
                supabase.table('comments').insert(comment).execute()
                # Notify marker/event owner
                try:
                    if target_type == 'marker':
                        m_res = supabase.table('markers').select('addedBy').eq('id', target_id).execute()
                        if m_res.data and m_res.data[0]['addedBy'] != current_username:
                            send_push_to_user(m_res.data[0]['addedBy'],
                                title=f"💬 {current_username} rampanı yorumladı!",
                                body=text[:80], url="/")
                    elif target_type == 'event':
                        e_res = supabase.table('events').select('creator').eq('id', target_id).execute()
                        if e_res.data and e_res.data[0]['creator'] != current_username:
                            send_push_to_user(e_res.data[0]['creator'],
                                title=f"💬 {current_username} etkinliğini yorumladı!",
                                body=text[:80], url="/")
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2935]: {_exc}')

            elif action == 'delete_comment':
                cid = str(data.get('id', ''))
                c_res = supabase.table('comments').select('user').eq('id', cid).execute()
                if c_res.data:
                    if c_res.data[0]['user'] == current_username or is_admin:
                        supabase.table('comments').delete().eq('id', cid).execute()

            elif action == 'get_comments':
                target_id = str(data.get('target_id', ''))
                c_res = supabase.table('comments').select('*').eq('target_id', target_id).order('created_at').execute()
                return jsonify({'status': 'ok', 'comments': c_res.data or []})

            # ================================================================
            # STORY SİSTEMİ (24 saat kaybolan - Premium)
            # ================================================================
            elif action == 'add_story':
                try:
                    st_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                    prem = int((st_res.data[0].get('stats') or {}).get('premium_tier', 0)) if st_res.data else 0
                except (IndexError, TypeError, ValueError):
                    prem = 0
                if prem < 1:
                    return jsonify({'status': 'error', 'message': 'Story paylaşmak için en az Standart üyelik gerekli!'})
                story = {
                    'id': str(int(time.time() * 1000)),
                    'user': current_username,
                    'text': html.escape(data.get('text', '').strip()),
                    'image': data.get('image', ''),
                    'expires_at': int(time.time()) + 86400,  # 24 saat
                    'created_at': int(time.time()),
                    'viewers': []
                }
                supabase.table('stories').insert(story).execute()
                # ── Yeni story bildirimi: herkese ──
                try:
                    story_text = data.get('text', '').strip()
                    story_preview = f"'{story_text[:40]}'" if story_text else "Yeni bir fotoğraf paylaştı"
                    broadcast_push(
                        title=f"📸 {current_username} story paylaştı!",
                        body=f"{story_preview} — 24 saat içinde kayboluyor!",
                        exclude_user=current_username,
                        url="/"
                    )
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~2980]: {_exc}')

            elif action == 'view_story':
                sid = str(data.get('id', ''))
                s_res = supabase.table('stories').select('viewers').eq('id', sid).execute()
                if s_res.data:
                    viewers = s_res.data[0].get('viewers', [])
                    if current_username not in viewers:
                        viewers.append(current_username)
                        supabase.table('stories').update({'viewers': viewers}).eq('id', sid).execute()

            elif action == 'delete_story':
                sid = str(data.get('id', ''))
                s_res = supabase.table('stories').select('user').eq('id', sid).execute()
                if s_res.data and (s_res.data[0]['user'] == current_username or is_admin):
                    supabase.table('stories').delete().eq('id', sid).execute()

            elif action == 'get_stories':
                now_ts = int(time.time())
                s_res = supabase.table('stories').select('*').gt('expires_at', now_ts).order('created_at', desc=True).limit(50).execute()
                return jsonify({'status': 'ok', 'stories': s_res.data or []})

            # ================================================================
            # MEDYA YÜKLEME (R2'ye direkt yükleme — video/fotoğraf)
            # ================================================================
            elif action == 'upload_media':
                media_data = data.get('media_data', '')
                folder = data.get('folder', 'uploads')
                if not media_data:
                    return jsonify({'status': 'error', 'message': 'Medya verisi eksik!'})
                if not (media_data.startswith('data:image/') or media_data.startswith('data:video/') or media_data.startswith('data:audio/')):
                    return jsonify({'status': 'error', 'message': 'Geçersiz medya formatı!'})
                url = upload_base64_to_storage(media_data, folder)
                if url and not url.startswith('data:'):
                    return jsonify({'status': 'ok', 'url': url})
                return jsonify({'status': 'error', 'message': 'Medya yüklenemedi, tekrar deneyin.'})

            # ================================================================
            # REELS SİSTEMİ (TikTok/Instagram tarzı kısa video & fotoğraf)
            # ================================================================
            elif action == 'add_reel':
                # Günlük yükleme limiti kontrolü
                try:
                    u_reel_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                    u_stats_r = u_reel_res.data[0].get('stats', {}) or {} if u_reel_res.data else {}
                    if isinstance(u_stats_r, str):
                        try: u_stats_r = json.loads(u_stats_r)
                        except: u_stats_r = {}
                    prem_r = int(u_stats_r.get('premium_tier', 0))
                except Exception as _exc:
                    prem_r = 0
                    u_stats_r = {}

                today_str = datetime.datetime.now().strftime("%Y-%m-%d")
                reel_today = u_stats_r.get('reel_upload_date', '')
                reel_count_today = u_stats_r.get('reel_upload_count', 0)
                if reel_today != today_str:
                    reel_count_today = 0

                media_type = data.get('media_type', 'image')  # 'image' veya 'video'

                # Limit: üyesiz=sadece 1 resim, Standart=1 video/resim, Deluxe/Ultra=2
                if prem_r == 0:
                    if media_type == 'video':
                        return jsonify({'status': 'error', 'message': 'Video yüklemek için en az Standart üyelik gereklidir!'})
                    if reel_count_today >= 1:
                        return jsonify({'status': 'error', 'message': 'Günlük ücretsiz Reel limitine (1 fotoğraf) ulaştınız!'})
                elif prem_r == 1:
                    if reel_count_today >= 1:
                        return jsonify({'status': 'error', 'message': 'Standart üyeler günde 1 Reel paylaşabilir. Deluxe/Ultra ile 2ye cikar!'})
                else:  # Deluxe/Ultra
                    if reel_count_today >= 2:
                        return jsonify({'status': 'error', 'message': 'Günlük Reel limitine (2) ulaştınız!'})

                # Medya URL'i al — upload_media ile önceden R2'ye yüklenmeli
                raw_media = data.get('media_url', '')
                # Eğer hâlâ base64 geldiyse (fallback) yükle, ama normalde URL gelir
                if raw_media and (raw_media.startswith('data:image/') or raw_media.startswith('data:video/')):
                    raw_media = upload_base64_to_storage(raw_media, 'reels')
                if not raw_media or raw_media.startswith('data:'):
                    return jsonify({'status': 'error', 'message': 'Medya yüklenemedi, lütfen tekrar deneyin.'})

                reel = {
                    'id': str(int(time.time() * 1000)) + '_' + current_username,
                    'user': current_username,
                    'media_url': raw_media,
                    'media_type': media_type,
                    'caption': html.escape(data.get('caption', '').strip()[:200]),
                    'likes': [],
                    'comment_count': 0,
                    'created_at': int(time.time())
                }
                supabase.table('reels').insert(reel).execute()

                # Günlük upload sayısını artır
                try:
                    u_stats_r['reel_upload_date'] = today_str
                    u_stats_r['reel_upload_count'] = reel_count_today + 1
                    supabase.table('users').update({'stats': u_stats_r}).eq('username', current_username).execute()
                except Exception as e:
                    print(f"⚠️ Reel upload count güncelleme hatası: {e}")

                return jsonify({'status': 'ok'})

            elif action == 'get_reels':
                offset = int(data.get('offset', 0))
                try:
                    r_res = supabase.table('reels').select('*').order('created_at', desc=True).range(offset, offset + 19).execute()
                    reels_out = []
                    for r in (r_res.data or []):
                        url = r.get('media_url', '') or ''
                        # Base64 veya boş URL içeren eski kayıtları atla
                        if url.startswith('data:') or not url:
                            continue
                        reels_out.append(r)
                    return jsonify({'status': 'ok', 'reels': reels_out})
                except Exception as e:
                    return jsonify({'status': 'ok', 'reels': []})

            elif action == 'like_reel':
                reel_id = str(data.get('reel_id', ''))
                r_res = supabase.table('reels').select('likes, user').eq('id', reel_id).execute()
                if r_res.data:
                    likes      = r_res.data[0].get('likes', []) or []
                    reel_owner = r_res.data[0].get('user', '')
                    was_liked  = current_username in likes
                    if was_liked:
                        likes.remove(current_username)
                    else:
                        likes.append(current_username)
                    supabase.table('reels').update({'likes': likes}).eq('id', reel_id).execute()
                    # ── Yeni beğeni → reel sahibine bildirim (beğeniyi geri almada değil) ──
                    if not was_liked and reel_owner and reel_owner != current_username:
                        try:
                            send_push_to_user(
                                reel_owner,
                                title=f"❤️ {current_username} reelini beğendi!",
                                body="Reeline yeni bir beğeni geldi 🔥",
                                url="/"
                            )
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~3121]: {_exc}')
                    return jsonify({'status': 'ok', 'likes': len(likes), 'liked': current_username in likes})
                return jsonify({'status': 'error'})

            elif action == 'delete_reel':
                reel_id = str(data.get('reel_id', ''))
                r_res = supabase.table('reels').select('user').eq('id', reel_id).execute()
                if r_res.data and (r_res.data[0]['user'] == current_username or is_admin):
                    reel_owner = r_res.data[0]['user']
                    supabase.table('reels').delete().eq('id', reel_id).execute()
                    # Sub-admin log
                    if is_admin and not is_main_admin:
                        try:
                            log_entry = {'id': str(int(time.time()*1000)), 'admin': current_username, 'action': 'delete_reel', 'target': reel_owner, 'detail': f"Reel silindi: {reel_id}", 'ts': int(time.time())}
                            supabase.table('admin_logs').insert(log_entry).execute()
                            send_push_to_user('Admin', title=f"⚠️ Admin Bildirimi", body=f"{current_username}, {reel_owner} adlı kullanıcının reelini sildi.", url="/")
                        except Exception as log_e:
                            print(f"Admin log hatası: {log_e}")
                return jsonify({'status': 'ok'})

            # ================================================================
            # ADMİN YÖNETİM SİSTEMİ (Ana admin: atama/görevden alma, loglar)
            # ================================================================
            elif action == 'assign_sub_admin':
                if not is_main_admin:
                    return jsonify({'status': 'error', 'message': 'Sadece Ana Admin bu işlemi yapabilir!'})
                target = data.get('username', '').strip()
                if not target or target == 'Admin':
                    return jsonify({'status': 'error', 'message': 'Geçersiz kullanıcı!'})
                u_res = supabase.table('users').select('username, role').eq('username', target).execute()
                if not u_res.data:
                    return jsonify({'status': 'error', 'message': 'Kullanıcı bulunamadı!'})
                supabase.table('users').update({'role': 'SubAdmin'}).eq('username', target).execute()
                try:
                    log_entry = {'id': str(int(time.time()*1000)), 'admin': 'Admin', 'action': 'assign_admin', 'target': target, 'detail': f"{target} yardımcı yönetici yapıldı", 'ts': int(time.time())}
                    supabase.table('admin_logs').insert(log_entry).execute()
                    send_push_to_user(target, title="👑 Yönetici Yetkiniz Verildi", body="Ana admin sizi yardımcı yönetici yaptı!", url="/")
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~3159]: {_exc}')
                return jsonify({'status': 'ok'})

            elif action == 'revoke_sub_admin':
                if not is_main_admin:
                    return jsonify({'status': 'error', 'message': 'Sadece Ana Admin bu işlemi yapabilir!'})
                target = data.get('username', '').strip()
                if not target or target == 'Admin':
                    return jsonify({'status': 'error', 'message': 'Geçersiz kullanıcı!'})
                supabase.table('users').update({'role': 'user'}).eq('username', target).execute()
                try:
                    log_entry = {'id': str(int(time.time()*1000)), 'admin': 'Admin', 'action': 'revoke_admin', 'target': target, 'detail': f"{target} yönetici yetkisi alındı", 'ts': int(time.time())}
                    supabase.table('admin_logs').insert(log_entry).execute()
                    send_push_to_user(target, title="🚫 Yönetici Yetkiniz Alındı", body="Ana admin yönetici yetkinizi geri aldı.", url="/")
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~3173]: {_exc}')
                return jsonify({'status': 'ok'})

            elif action == 'get_admin_logs':
                if not is_admin:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz!'})
                try:
                    logs_res = supabase.table('admin_logs').select('*').order('ts', desc=True).limit(100).execute()
                    return jsonify({'status': 'ok', 'logs': logs_res.data or []})
                except Exception as e:
                    return jsonify({'status': 'ok', 'logs': []})

            elif action == 'get_user_activity':
                if not is_admin:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz!'})
                target = data.get('username', '').strip()
                if not target:
                    return jsonify({'status': 'error', 'message': 'Kullanıcı belirtilmedi!'})
                result = {}
                try:
                    msgs_res = supabase.table('messages').select('*').eq('user', target).order('id', desc=True).limit(30).execute()
                    result['messages'] = msgs_res.data or []
                except Exception: result['messages'] = []
                try:
                    dms_res = supabase.table('dms').select('*').contains('participants', [target]).order('id', desc=True).limit(30).execute()
                    result['dms'] = dms_res.data or []
                except Exception: result['dms'] = []
                try:
                    reels_res = supabase.table('reels').select('*').eq('user', target).order('created_at', desc=True).limit(20).execute()
                    result['reels'] = reels_res.data or []
                except Exception: result['reels'] = []
                try:
                    markers_res = supabase.table('markers').select('*').eq('addedBy', target).execute()
                    result['markers'] = markers_res.data or []
                except Exception: result['markers'] = []
                try:
                    market_res = supabase.table('market').select('*').eq('owner', target).execute()
                    result['market'] = market_res.data or []
                except Exception: result['market'] = []
                return jsonify({'status': 'ok', 'activity': result})

            elif action == 'get_all_sub_admins':
                if not is_main_admin:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz!'})
                try:
                    sa_res = supabase.table('users').select('username, avatar, xp').eq('role', 'SubAdmin').execute()
                    return jsonify({'status': 'ok', 'sub_admins': sa_res.data or []})
                except Exception as _exc:
                    return jsonify({'status': 'ok', 'sub_admins': []})

            elif action == 'admin_notify_main':
                # Sub-admin ana admine bildirim gönderir
                if not is_admin:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz!'})
                msg_text = html.escape(data.get('message', '').strip()[:500])
                if not msg_text:
                    return jsonify({'status': 'error', 'message': 'Mesaj boş olamaz!'})
                try:
                    log_entry = {'id': str(int(time.time()*1000)), 'admin': current_username, 'action': 'notify_main', 'target': '', 'detail': msg_text, 'ts': int(time.time())}
                    supabase.table('admin_logs').insert(log_entry).execute()
                    send_push_to_user('Admin', title=f"📢 Admin Bildirimi: {current_username}", body=msg_text[:100], url="/")
                except Exception as e:
                    print(f"Admin notify hatası: {e}")
                return jsonify({'status': 'ok'})

            elif action == 'admin_delete_message_by_id':
                # Admin herhangi bir mesajı silebilir ve log tutar
                if not is_admin:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz!'})
                msg_id = str(data.get('msg_id', ''))
                msg_res2 = supabase.table('messages').select('user, text').eq('id', msg_id).execute()
                if msg_res2.data:
                    msg_owner = msg_res2.data[0].get('user', '')
                    msg_preview = str(msg_res2.data[0].get('text', ''))[:60]
                    supabase.table('messages').delete().eq('id', msg_id).execute()
                    if not is_main_admin:
                        try:
                            log_entry = {'id': str(int(time.time()*1000)), 'admin': current_username, 'action': 'delete_message', 'target': msg_owner, 'detail': f"Mesaj silindi: {msg_preview}", 'ts': int(time.time())}
                            supabase.table('admin_logs').insert(log_entry).execute()
                            send_push_to_user('Admin', title=f"⚠️ Mesaj Silindi", body=f"{current_username} → {msg_owner}: {msg_preview}", url="/")
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~3253]: {_exc}')
                return jsonify({'status': 'ok'})

            elif action == 'admin_delete_marker_by_id':
                if not is_admin:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz!'})
                marker_id = str(data.get('marker_id', ''))
                m_res2 = supabase.table('markers').select('addedBy, name').eq('id', marker_id).execute()
                if m_res2.data:
                    m_owner = m_res2.data[0].get('addedBy', '')
                    m_name = str(m_res2.data[0].get('name', ''))
                    supabase.table('markers').delete().eq('id', marker_id).execute()
                    if not is_main_admin:
                        try:
                            log_entry = {'id': str(int(time.time()*1000)), 'admin': current_username, 'action': 'delete_marker', 'target': m_owner, 'detail': f"Yer silindi: {m_name}", 'ts': int(time.time())}
                            supabase.table('admin_logs').insert(log_entry).execute()
                            send_push_to_user('Admin', title=f"⚠️ Yer Silindi", body=f"{current_username} → {m_name} ({m_owner})", url="/")
                        except Exception as _exc:
                            import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~3270]: {_exc}')
                return jsonify({'status': 'ok'})

            elif action == 'admin_ban_user':
                if not is_admin:
                    return jsonify({'status': 'error', 'message': 'Yetkisiz!'})
                target = data.get('username', '').strip()
                reason = html.escape(data.get('reason', 'Kural ihlali').strip()[:200])
                if not target:
                    return jsonify({'status': 'error', 'message': 'Kullanıcı belirtilmedi!'})
                try:
                    supabase.table('banned').insert({'username': target, 'reason': reason, 'banned_by': current_username, 'ts': int(time.time())}).execute()
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~3282]: {_exc}')
                if not is_main_admin:
                    try:
                        log_entry = {'id': str(int(time.time()*1000)), 'admin': current_username, 'action': 'ban_user', 'target': target, 'detail': f"Ban sebebi: {reason}", 'ts': int(time.time())}
                        supabase.table('admin_logs').insert(log_entry).execute()
                        send_push_to_user('Admin', title=f"🚨 Kullanıcı Banlı", body=f"{current_username}, {target} adlı kullanıcıyı banladı. Sebep: {reason[:60]}", url="/")
                    except Exception as _exc:
                        import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~3289]: {_exc}')
                return jsonify({'status': 'ok'})

            elif action == 'comment_reel':
                reel_id = str(data.get('reel_id', ''))
                text_r = html.escape(data.get('text', '').strip()[:300])
                if not text_r:
                    return jsonify({'status': 'error', 'message': 'Yorum boş olamaz!'})
                comment_r = {
                    'id': str(int(time.time() * 1000)),
                    'target_id': reel_id,
                    'target_type': 'reel',
                    'user': current_username,
                    'text': text_r,
                    'created_at': datetime.datetime.now().isoformat()
                }
                supabase.table('comments').insert(comment_r).execute()
                # Yorum sayısını artır + reel sahibine bildirim
                try:
                    rc_res = supabase.table('reels').select('comment_count, user').eq('id', reel_id).execute()
                    if rc_res.data:
                        new_cc = (rc_res.data[0].get('comment_count') or 0) + 1
                        supabase.table('reels').update({'comment_count': new_cc}).eq('id', reel_id).execute()
                        # ── Reel sahibine bildirim ──
                        reel_owner_r = rc_res.data[0].get('user', '')
                        if reel_owner_r and reel_owner_r != current_username:
                            send_push_to_user(
                                reel_owner_r,
                                title=f"💬 {current_username} reelini yorumladı!",
                                body=text_r[:80],
                                url="/"
                            )
                except Exception as _exc:
                    import logging as _lg; _lg.getLogger('freeridertr').warning(f'Göz ardı edilen hata [satır ~3321]: {_exc}')
                return jsonify({'status': 'ok'})

            # ================================================================
            # DESTEK TALEP (Öncelikli destek - Premium)
            # ================================================================
            elif action == 'send_support':
                msg = html.escape(data.get('message', '').strip())
                if not msg:
                    return jsonify({'status': 'error', 'message': 'Mesaj bos olamaz!'})
                u_res2 = supabase.table('users').select('stats').eq('username', current_username).execute()
                prem2 = int(u_res2.data[0].get('stats', {}).get('premium_tier', 0)) if u_res2.data else 0
                priority = "🔴 ÖNCELİKLİ" if prem2 >= 2 else ("🟡 Normal" if prem2 == 1 else "⚪ Ücretsiz")
                email_html = f"<h3>FreeriderTR Destek Talebi</h3><p><b>Kullanici:</b> {current_username}<br><b>Oncelik:</b> {priority}<br><b>Mesaj:</b><br>{msg}</p>"
                send_resend_email("destek.freerider@gmail.com", f"[{priority}] Destek - {current_username}", email_html)
                # Admin'e DM olarak gönder (en güvenilir yol)
                try:
                    dm_msg = "[DESTEK] " + priority + " | " + current_username + ": " + msg
                    dm_id = str(int(time.time() * 1000))
                    supabase.table('dms').insert({
                        'id': dm_id,
                        'sender': current_username,
                        'receiver': 'Admin',
                        'participants': [current_username, 'Admin'],
                        'text': dm_msg,
                        'type': 'text'
                    }).execute()
                except Exception as e:
                    print("Destek DM hatası:", e)
                # Push bildirim de gönder
                try:
                    send_push_to_user('Admin', f"🎧 {priority} Destek: {current_username}", msg[:80], url="/")
                except Exception as e:
                    print(f"⚠️ Destek push bildirimi hatası: {e}")
                return jsonify({'status': 'ok'})

            elif action == 'report_user':
                target = html.escape(data.get('target', '').strip())
                reason = html.escape(data.get('reason', 'Belirtilmedi').strip())
                if not target or target == current_username:
                    return jsonify({'status': 'error', 'message': 'Geçersiz kullanıcı.'})
                # Admin'e bildirim + DM
                report_text = f"[KULLANICI ŞİKAYET] {current_username} → {target} | Sebep: {reason}"
                try:
                    dm_id = str(int(time.time() * 1000))
                    supabase.table('dms').insert({
                        'id': dm_id, 'sender': current_username, 'receiver': 'Admin',
                        'participants': [current_username, 'Admin'],
                        'text': report_text, 'type': 'text'
                    }).execute()
                except Exception as e:
                    print(f"⚠️ Şikayet DM hatası: {e}")
                try:
                    send_push_to_user('Admin', f"🚨 Kullanıcı Şikayeti: {target}", f"{current_username}: {reason[:60]}", url="/")
                except Exception as e:
                    print(f"⚠️ Şikayet push hatası: {e}")
                email_html = f"<h3>Kullanıcı Şikayeti</h3><p><b>Şikayet Eden:</b> {current_username}<br><b>Şikayet Edilen:</b> {target}<br><b>Sebep:</b> {reason}</p>"
                send_resend_email("destek.freerider@gmail.com", f"[ŞİKAYET] {target} - {current_username}", email_html)
                return jsonify({'status': 'ok'})

            elif action == 'report_message':
                msg_id = str(data.get('msg_id', ''))
                msg_text = html.escape(data.get('msg_text', '')[:200])
                msg_user = html.escape(data.get('msg_user', ''))
                reason = html.escape(data.get('reason', 'Belirtilmedi').strip())
                report_text = f"[MESAJ ŞİKAYET] {current_username} → {msg_user} | MesajID:{msg_id} | İçerik: {msg_text} | Sebep: {reason}"
                try:
                    dm_id = str(int(time.time() * 1000))
                    supabase.table('dms').insert({
                        'id': dm_id, 'sender': current_username, 'receiver': 'Admin',
                        'participants': [current_username, 'Admin'],
                        'text': report_text, 'type': 'text'
                    }).execute()
                except Exception as e:
                    print(f"⚠️ Mesaj şikayet DM hatası: {e}")
                try:
                    send_push_to_user('Admin', f"🚨 Mesaj Şikayeti: {msg_user}", f"{current_username}: {reason[:60]}", url="/")
                except Exception as e:
                    print(f"⚠️ Mesaj şikayet push hatası: {e}")
                email_html = f"<h3>Mesaj Şikayeti</h3><p><b>Şikayet Eden:</b> {current_username}<br><b>Mesaj Sahibi:</b> {msg_user}<br><b>Mesaj:</b> {msg_text}<br><b>Sebep:</b> {reason}</p>"
                send_resend_email("destek.freerider@gmail.com", f"[MESAJ ŞİKAYET] {msg_user} - {current_username}", email_html)
                return jsonify({'status': 'ok'})

            elif action == 'delete_account':
                # Google Play zorunluluğu: Hesap + tüm veriler + R2 medyaları silinir
                confirm_pass = data.get('password', '').strip()
                u_res = supabase.table('users').select('password').eq('username', current_username).execute()
                if not u_res.data:
                    return jsonify({'status': 'error', 'message': 'Kullanıcı bulunamadı.'})
                if not check_password_hash(u_res.data[0].get('password', ''), confirm_pass):
                    return jsonify({'status': 'error', 'message': 'Şifre yanlış! Hesabınızı silmek için doğru şifrenizi girin.'})
                try:
                    # 1. R2 medya varlıklarını temizle
                    asset_result = delete_user_assets(current_username)
                    logger.info(f"Hesap silme R2 temizliği: {current_username} → {asset_result}")
                    # 2. Supabase verilerini sil
                    supabase.table('markers').delete().eq('addedBy', current_username).execute()
                    supabase.table('events').delete().eq('creator', current_username).execute()
                    supabase.table('market').delete().eq('owner', current_username).execute()
                    supabase.table('stories').delete().eq('user', current_username).execute()
                    supabase.table('comments').delete().eq('user', current_username).execute()
                    supabase.table('reels').delete().eq('user', current_username).execute()
                    supabase.table('dms').delete().or_(f'sender.eq.{current_username},receiver.eq.{current_username}').execute()
                    supabase.table('messages').delete().eq('user', current_username).execute()
                    supabase.table('users').delete().eq('username', current_username).execute()
                    # 3. Liderlik önbelleğini geçersiz kıl
                    app._leaderboard_cache = None
                    session.clear()
                    return jsonify({'status': 'ok', 'message': 'Hesabınız ve tüm verileriniz kalıcı olarak silindi.'})
                except Exception as exc:
                    logger.error(f"Hesap silme hatası ({current_username}): {exc}", exc_info=True)
                    return jsonify({'status': 'error', 'message': f'Silme işlemi sırasında hata oluştu: {str(exc)}'})

            elif action == 'block_user':
                target = html.escape(data.get('target', '').strip())
                if not target or target == current_username:
                    return jsonify({'status': 'error', 'message': 'Geçersiz kullanıcı.'})
                u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                if not u_res.data:
                    return jsonify({'status': 'error', 'message': 'Kullanıcı bulunamadı.'})
                stats = u_res.data[0].get('stats', {}) or {}
                if isinstance(stats, str):
                    try: stats = json.loads(stats)
                    except: stats = {}
                blocked = stats.get('blocked_users', [])
                if target not in blocked:
                    blocked.append(target)
                stats['blocked_users'] = blocked
                supabase.table('users').update({'stats': stats}).eq('username', current_username).execute()
                return jsonify({'status': 'ok', 'message': f'{target} engellendi.'})

            elif action == 'unblock_user':
                target = html.escape(data.get('target', '').strip())
                u_res = supabase.table('users').select('stats').eq('username', current_username).execute()
                if not u_res.data:
                    return jsonify({'status': 'error', 'message': 'Kullanıcı bulunamadı.'})
                stats = u_res.data[0].get('stats', {}) or {}
                if isinstance(stats, str):
                    try: stats = json.loads(stats)
                    except: stats = {}
                blocked = stats.get('blocked_users', [])
                if target in blocked:
                    blocked.remove(target)
                stats['blocked_users'] = blocked
                supabase.table('users').update({'stats': stats}).eq('username', current_username).execute()
                return jsonify({'status': 'ok', 'message': f'{target} engeli kaldırıldı.'})

            return jsonify({'status': 'ok'})
            
        except Exception as e:
            logger.error(f"api_data beklenmedik hata: {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Sunucuda bir hata oluştu. Lütfen tekrar deneyin.'})

# ==============================================================================
# HESAP SİLME WEB SAYFASI (Google Play zorunluluğu - uygulama dışından erişilebilir)
# ==============================================================================
@app.route("/delete-account", methods=["GET", "POST"])
def delete_account_page():
    """Google Play politikası gereği: Uygulama dışından erişilebilen hesap silme sayfası."""
    message = ""
    message_type = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            message = "Kullanıcı adı ve şifre zorunludur."
            message_type = "error"
        else:
            try:
                u_res = supabase.table('users').select('password').eq('username', username).execute()
                if not u_res.data:
                    message = "Kullanıcı bulunamadı."
                    message_type = "error"
                elif not check_password_hash(u_res.data[0].get('password', ''), password):
                    message = "Şifre yanlış."
                    message_type = "error"
                else:
                    # 1. R2 medya varlıklarını temizle
                    asset_result = delete_user_assets(username)
                    logger.info(f"Web hesap silme R2 temizliği: {username} → {asset_result}")
                    # 2. Supabase verilerini sil
                    supabase.table('markers').delete().eq('addedBy', username).execute()
                    supabase.table('events').delete().eq('creator', username).execute()
                    supabase.table('market').delete().eq('owner', username).execute()
                    supabase.table('stories').delete().eq('user', username).execute()
                    supabase.table('comments').delete().eq('user', username).execute()
                    supabase.table('reels').delete().eq('user', username).execute()
                    supabase.table('dms').delete().or_(f'sender.eq.{username},receiver.eq.{username}').execute()
                    supabase.table('messages').delete().eq('user', username).execute()
                    supabase.table('users').delete().eq('username', username).execute()
                    # 3. Liderlik önbelleğini geçersiz kıl
                    app._leaderboard_cache = None
                    message = "Hesabınız ve tüm verileriniz kalıcı olarak silindi. Bu işlem geri alınamaz."
                    message_type = "success"
                    logger.info(f"Web hesap silindi: {username}")
            except Exception as exc:
                logger.error(f"Web hesap silme hatası ({username}): {exc}", exc_info=True)
                message = f"Bir hata oluştu: {str(exc)}"
                message_type = "error"

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hesabı Sil – FreeriderTR</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ background: #09090b; color: #fff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
        .card {{ background: #18181b; border: 1px solid #3f3f46; border-radius: 20px; padding: 36px 28px; max-width: 420px; width: 100%; }}
        .logo {{ text-align: center; font-size: 2.5rem; font-weight: 900; letter-spacing: 0.08em; margin-bottom: 6px; }}
        .logo span {{ color: #dc2626; }}
        .subtitle {{ text-align: center; color: #a1a1aa; font-size: 0.78rem; margin-bottom: 28px; text-transform: uppercase; letter-spacing: 0.1em; }}
        h1 {{ font-size: 1.3rem; font-weight: 800; margin-bottom: 8px; color: #ef4444; }}
        .warning {{ background: #1c0a0a; border: 1px solid #7f1d1d; border-radius: 12px; padding: 14px 16px; margin-bottom: 22px; font-size: 0.82rem; color: #fca5a5; line-height: 1.6; }}
        .warning ul {{ padding-left: 18px; margin-top: 8px; }}
        label {{ display: block; font-size: 0.78rem; color: #a1a1aa; margin-bottom: 6px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
        input {{ width: 100%; background: #09090b; border: 1px solid #3f3f46; border-radius: 10px; padding: 13px 16px; color: #fff; font-size: 0.95rem; outline: none; margin-bottom: 14px; transition: border 0.2s; }}
        input:focus {{ border-color: #dc2626; }}
        button {{ width: 100%; background: #dc2626; color: #fff; border: none; border-radius: 10px; padding: 14px; font-size: 0.95rem; font-weight: 800; cursor: pointer; text-transform: uppercase; letter-spacing: 0.08em; transition: background 0.2s; }}
        button:hover {{ background: #b91c1c; }}
        .msg-error {{ background: #1c0a0a; border: 1px solid #dc2626; border-radius: 10px; padding: 12px 16px; color: #fca5a5; font-size: 0.85rem; margin-bottom: 16px; }}
        .msg-success {{ background: #052e16; border: 1px solid #166534; border-radius: 10px; padding: 12px 16px; color: #86efac; font-size: 0.85rem; margin-bottom: 16px; }}
        .back {{ text-align: center; margin-top: 18px; }}
        .back a {{ color: #71717a; font-size: 0.8rem; text-decoration: none; hover: underline; }}
    </style>
</head>
<body>
<div class="card">
    <div class="logo">FREERIDER<span>TR</span></div>
    <div class="subtitle">Hesap Silme Talebi</div>
    <h1>🗑️ Hesabımı Sil</h1>
    <div class="warning">
        <strong>⚠️ Bu işlem geri alınamaz!</strong>
        <ul>
            <li>Profiliniz kalıcı olarak silinir</li>
            <li>Tüm gönderileriniz, ilanlarınız ve etkinlikleriniz silinir</li>
            <li>XP, rozet ve abonelik bilgileriniz silinir</li>
            <li>Mesajlaşma geçmişiniz silinir</li>
        </ul>
    </div>
    {"<div class='msg-error'>" + message + "</div>" if message_type == "error" else ""}
    {"<div class='msg-success'>" + message + "</div>" if message_type == "success" else ""}
       {'' if message_type == "success" else '''
    <form method="POST" action="/delete-account">
        <label for="username">Kullanıcı Adı</label>
        <input type="text" id="username" name="username" placeholder="Kullanıcı adınız" required autocomplete="username">
        <label for="password">Şifre</label>
        <input type="password" id="password" name="password" placeholder="Şifrenizi onaylayın" required autocomplete="current-password">
        <button type="submit">HESABIMI KALICI OLARAK SİL</button>
    </form>
    '''}
    <div class="back"><a href="https://freeridertr.com.tr">← Uygulamaya Geri Dön</a></div>
</div>
</body>
</html>"""

# ==============================================================================
# FRONTEND ARAYÜZ (HTML + CSS + JAVASCRIPT)
# ==============================================================================
HTML_CODE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="description" content="Türkiye'nin en büyük Downhill ve Freeride dağ bisikleti topluluğu.">
    <title>Freerider Türkiye Plus</title>
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#000000">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
    <script src="https://cdn.onesignal.com/sdks/web/v16/OneSignalSDK.page.js" defer></script>
    <script>
      window.OneSignalDeferred = window.OneSignalDeferred || [];
      OneSignalDeferred.push(async function(OneSignal) {
        await OneSignal.init({
          appId: "{{ onesignal_app_id }}",
          serviceWorkerParam: { scope: "/" },
          serviceWorkerPath: "/OneSignalSDKWorker.js",
          notifyButton: { enable: false },
          allowLocalhostAsSecureOrigin: true,
          notificationClickHandlerMatch: "origin",
          notificationClickHandlerAction: "focus",
        });
        console.log('✅ OneSignal SDK başarıyla başlatıldı');
        // SDK init olduktan sonra currentUser varsa hemen login yap + player_id kaydet
        if (window.currentUser && window.currentUser.username) {
          try {
            await OneSignal.login(window.currentUser.username);
            console.log('✅ OneSignal otomatik login (init sonrası):', window.currentUser.username);
            // İzin varsa subscription ID'yi de kaydet
            if (OneSignal.Notifications.permission) {
              // saveOneSignalPlayerId henüz tanımlanmamış olabilir, defer et
              setTimeout(async () => {
                if (typeof saveOneSignalPlayerId === 'function') {
                  await saveOneSignalPlayerId(OneSignal);
                }
              }, 1000);
            }
          } catch(e) {
            console.error('OneSignal init-login hatası:', e);
          }
        }
      });
    </script>
    
    <link rel="stylesheet" href="https://unpkg.com/leaflet-control-geocoder/dist/Control.Geocoder.css" />
    <script src="https://unpkg.com/leaflet-control-geocoder/dist/Control.Geocoder.js"></script>
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800;900&family=Teko:wght@500;700&display=swap');
        body { font-family: 'Outfit', sans-serif; background-color: #020b19; margin: 0; padding: 0; overscroll-behavior: none; color: #e4e4e7; touch-action: manipulation; }
        .teko-font { font-family: 'Teko', sans-serif; text-transform: uppercase; }
        #map { height: 100% !important; width: 100% !important; z-index: 10; touch-action: none; }
        ::-webkit-scrollbar { width: 0px; background: transparent; }
        .bg-glass { background: rgba(24, 24, 27, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.05); }
        .bg-darker { background-color: #030a16; }
        
        .leaflet-control-layers { margin-top: 70px !important; background: rgba(24, 24, 27, 0.7) !important; color: white !important; border: 1px solid rgba(255, 255, 255, 0.1) !important; border-radius: 8px !important; backdrop-filter: blur(8px); font-size: 10px !important; padding: 2px !important; }
        .leaflet-control-layers-toggle { width: 30px !important; height: 30px !important; background-size: 18px 18px !important; }
        .leaflet-control-layers-base label { margin-bottom: 2px !important; padding: 2px !important; cursor: pointer; }
        .leaflet-control-geocoder { margin-top: 15px !important; }
        
        /* Premium Animasyonlar & Efektler */
        @keyframes slideUpFade { 0% { opacity: 0; transform: translateY(40px) scale(0.97); } 60% { opacity: 1; } 100% { opacity: 1; transform: translateY(0) scale(1); } }
        @keyframes slideDownFade { 0% { opacity: 0; transform: translateY(-20px); } 100% { opacity: 1; transform: translateY(0); } }
        @keyframes scaleInFade { 0% { opacity: 0; transform: scale(0.90); } 70% { transform: scale(1.02); } 100% { opacity: 1; transform: scale(1); } }
        @keyframes fadeIn { 0% { opacity: 0; } 100% { opacity: 1; } }
        @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
        @keyframes pulseGlow { 0%, 100% { box-shadow: 0 0 8px rgba(14,165,233,0.5); } 50% { box-shadow: 0 0 22px rgba(14,165,233,0.9); } }
        @keyframes onlinePulse { 0%, 100% { box-shadow: 0 0 0 0 rgba(34,197,94,0.7); transform: scale(1); } 50% { box-shadow: 0 0 0 6px rgba(34,197,94,0); transform: scale(1.1); } }
        @keyframes slideInRight { 0% { opacity: 0; transform: translateX(60px); } 100% { opacity: 1; transform: translateX(0); } }
        @keyframes slideInLeft { 0% { opacity: 0; transform: translateX(-60px); } 100% { opacity: 1; transform: translateX(0); } }
        @keyframes tabSwitch { 0% { opacity: 0; transform: translateY(12px); } 100% { opacity: 1; transform: translateY(0); } }
        @keyframes notifBounce { 0%,100%{transform:scale(1)} 30%{transform:scale(1.25)} 60%{transform:scale(0.9)} }
        @keyframes ripple { 0% { transform: scale(0); opacity: 0.6; } 100% { transform: scale(4); opacity: 0; } }

        .slide-up-anim { animation: slideUpFade 0.45s cubic-bezier(0.16, 1, 0.3, 1) both; }
        .slide-down-anim { animation: slideDownFade 0.35s cubic-bezier(0.16, 1, 0.3, 1) both; }
        .scale-in-anim { animation: scaleInFade 0.35s cubic-bezier(0.34, 1.56, 0.64, 1) both; }
        .fade-in-anim { animation: fadeIn 0.3s ease both; }
        .slide-in-right { animation: slideInRight 0.4s cubic-bezier(0.16, 1, 0.3, 1) both; }
        .slide-in-left { animation: slideInLeft 0.4s cubic-bezier(0.16, 1, 0.3, 1) both; }
        .tab-switch-anim { animation: tabSwitch 0.3s cubic-bezier(0.16, 1, 0.3, 1) both; }

        .btn-premium-hover { transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; }
        .btn-premium-hover:hover { transform: translateY(-2px) scale(1.02); box-shadow: 0 12px 28px rgba(14, 165, 233, 0.45); }
        .btn-premium-hover:active { transform: translateY(1px) scale(0.97); }
        .btn-premium-hover::after { content: ''; position: absolute; top: 50%; left: 50%; width: 5px; height: 5px; background: rgba(255,255,255,0.5); border-radius: 50%; transform: scale(0); opacity: 0; pointer-events: none; }
        .btn-premium-hover:active::after { animation: ripple 0.5s ease-out forwards; }

        .glass-panel { background: rgba(12, 12, 16, 0.88); backdrop-filter: blur(24px) saturate(180%); -webkit-backdrop-filter: blur(24px) saturate(180%); border: 1px solid rgba(255, 255, 255, 0.07); box-shadow: 0 12px 40px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.05); }
        
        /* Admin Panel Tab Styles */
        .admin-tab-btn { color: #71717a; }
        .active-admin-tab { background: rgba(12,74,110,0.4); color: #bae6fd; border: 1px solid rgba(12,74,110,0.6); }
        .ua-tab-btn { color: #71717a; }
        .ua-active-tab { background: rgba(39,39,42,0.8); color: #e4e4e7; border: 1px solid rgba(255,255,255,0.08); }

        /* Enhanced animations */
        @keyframes adminPulse { 0%,100%{box-shadow:0 0 15px rgba(14,165,233,0.3)} 50%{box-shadow:0 0 30px rgba(14,165,233,0.7)} }
        @keyframes logEntry { 0%{opacity:0;transform:translateX(-12px)} 100%{opacity:1;transform:translateX(0)} }
        @keyframes countUp { 0%{opacity:0;transform:translateY(8px)scale(0.9)} 100%{opacity:1;transform:translateY(0)scale(1)} }
        .admin-card-enter { animation: logEntry 0.3s ease both; }
        .count-up-anim { animation: countUp 0.4s cubic-bezier(0.34,1.56,0.64,1) both; }

        /* Scrollbar for admin panel */
        #admin-panel ::-webkit-scrollbar { width: 3px; }
        #admin-panel ::-webkit-scrollbar-track { background: transparent; }
        #admin-panel ::-webkit-scrollbar-thumb { background: rgba(12,74,110,0.6); border-radius: 4px; }

        /* Ban badge */
        .ban-reason-badge { background: rgba(12,74,110,0.25); border: 1px solid rgba(12,74,110,0.5); color: #bae6fd; font-size: 9px; font-weight: 800; padding: 2px 8px; border-radius: 6px; text-transform: uppercase; letter-spacing: 0.05em; }

        /* Log action colors */
        .log-ban { border-left: 3px solid #38bdf8; }
        .log-delete { border-left: 3px solid #f97316; }
        .log-assign { border-left: 3px solid #22c55e; }
        .log-revoke { border-left: 3px solid #eab308; }
        .log-notify { border-left: 3px solid #3b82f6; }
        .log-default { border-left: 3px solid #71717a; }

        /* Çevrim içi göstergesi */
        .online-dot { width: 10px; height: 10px; background: #22c55e; border-radius: 50%; border: 2px solid #09090b; animation: onlinePulse 2s infinite; display: inline-block; flex-shrink: 0; }
        .online-dot-sm { width: 8px; height: 8px; background: #22c55e; border-radius: 50%; border: 1.5px solid #09090b; animation: onlinePulse 2s infinite; display: inline-block; flex-shrink: 0; }
        .recent-dot { width: 8px; height: 8px; background: #eab308; border-radius: 50%; border: 1.5px solid #09090b; display: inline-block; flex-shrink: 0; }
        .offline-dot { width: 8px; height: 8px; background: #52525b; border-radius: 50%; border: 1.5px solid #09090b; display: inline-block; flex-shrink: 0; }
        .online-label { color: #22c55e; font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em; }
        .recent-label { color: #eab308; font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
        
        @keyframes rainbow-text { 0% { background-position: 0% 50%; } 100% { background-position: 200% 50%; } }
        @keyframes rainbow-shadow {
            0% { box-shadow: 0 0 15px red; border-color: red; filter: drop-shadow(0 0 5px red); }
            20% { box-shadow: 0 0 15px orange; border-color: orange; filter: drop-shadow(0 0 5px orange); }
            40% { box-shadow: 0 0 15px yellow; border-color: yellow; filter: drop-shadow(0 0 5px yellow); }
            60% { box-shadow: 0 0 15px #00ff00; border-color: #00ff00; filter: drop-shadow(0 0 5px #00ff00); }
            80% { box-shadow: 0 0 15px #00a2ff; border-color: #00a2ff; filter: drop-shadow(0 0 5px #00a2ff); }
            100% { box-shadow: 0 0 15px red; border-color: red; filter: drop-shadow(0 0 5px red); }
        }
        /* Gerçek alev efekti — parlayan border + üst parçacıklar */
        @keyframes fire-border {
            0%   { box-shadow: 0 0 10px 2px #c0390080, 0 0 20px 4px #e0500040; border-color: #c03900; }
            50%  { box-shadow: 0 0 16px 4px #d04000aa, 0 0 28px 6px #f0600055; border-color: #d04000; }
            100% { box-shadow: 0 0 10px 2px #c0390080, 0 0 20px 4px #e0500040; border-color: #c03900; }
        }
        @keyframes ice-border {
            0%   { box-shadow: 0 0 10px 2px #4488bb70, 0 0 20px 4px #2266aa30; border-color: #4488bb; }
            50%  { box-shadow: 0 0 16px 4px #5599cc90, 0 0 28px 6px #3377bb40; border-color: #5599cc; }
            100% { box-shadow: 0 0 10px 2px #4488bb70, 0 0 20px 4px #2266aa30; border-color: #4488bb; }
        }
        @keyframes fire-flicker { 0%,100%{filter:brightness(1)} 50%{filter:brightness(1.08)} }
        @keyframes ice-shimmer  { 0%,100%{filter:brightness(1)} 50%{filter:brightness(1.06) hue-rotate(5deg)} }
        @keyframes particle-rise { 0%{transform:translateY(0) translateX(0) scale(1);opacity:0.9} 100%{transform:translateY(-60px) translateX(var(--tx)) scale(0);opacity:0} }
        @keyframes particle-float { 0%{transform:translateY(0) translateX(0) scale(0.8);opacity:0.7} 100%{transform:translateY(40px) translateX(var(--tx)) scale(0.2);opacity:0} }

        .effect-fire {
            animation: fire-border 1.5s ease-in-out infinite, fire-flicker 2s ease-in-out infinite !important;
            border-width: 3px !important;
        }
        .effect-ice {
            animation: ice-border 2s ease-in-out infinite, ice-shimmer 2.5s ease-in-out infinite !important;
            border-width: 3px !important;
        }

        /* Parçacık container */
        .avatar-particle-wrap { position: relative; display: inline-block; }
        .particle-canvas { position: absolute; top: -30px; left: 50%; transform: translateX(-50%); width: 120px; height: 80px; pointer-events: none; z-index: 50; }
        .text-prem-rainbow { background: linear-gradient(90deg, #ff0055, #ffaa00, #55ff00, #00eeff, #aa00ff, #ff0055); background-size: 200% auto; color: transparent; -webkit-background-clip: text; animation: rainbow-text 3s linear infinite; font-weight: 900 !important; filter: drop-shadow(0 0 5px rgba(255,255,255,0.5)); }
        .text-prem-gold { color: #fbbf24 !important; text-shadow: 0 0 15px rgba(251, 191, 36, 1), 0 0 5px #fbbf24 !important; font-weight: 900 !important; }
        .text-prem-blue { color: #3b82f6 !important; text-shadow: 0 0 15px rgba(59, 130, 246, 1), 0 0 5px #3b82f6 !important; font-weight: 900 !important; }
        .text-prem-green { color: #22c55e !important; text-shadow: 0 0 15px rgba(34, 197, 94, 1), 0 0 5px #22c55e !important; font-weight: 900 !important; }
        .text-prem-pink { color: #ec4899 !important; text-shadow: 0 0 15px rgba(236, 72, 153, 1), 0 0 5px #ec4899 !important; font-weight: 900 !important; }
        .border-prem-rainbow { animation: rainbow-shadow 2.5s linear infinite; border-width: 4px; border-style: solid; }
        .border-prem-gold { border: 4px solid #fbbf24; box-shadow: 0 0 20px #fbbf24, inset 0 0 10px #fbbf24; }
        .border-prem-blue { border: 4px solid #3b82f6; box-shadow: 0 0 20px #3b82f6, inset 0 0 10px #3b82f6; }
        .border-prem-green { border: 4px solid #22c55e; box-shadow: 0 0 20px #22c55e, inset 0 0 10px #22c55e; }
        .border-prem-pink { border: 4px solid #ec4899; box-shadow: 0 0 20px #ec4899, inset 0 0 10px #ec4899; }
        .text-dlx-blue { background: linear-gradient(45deg, #60a5fa, #bfdbfe, #3b82f6); -webkit-background-clip: text; color: transparent; font-weight: 800 !important; text-shadow: 0 0 5px rgba(59,130,246,0.5); }
        .text-dlx-yellow { background: linear-gradient(45deg, #fde047, #fef08a, #eab308); -webkit-background-clip: text; color: transparent; font-weight: 800 !important; text-shadow: 0 0 5px rgba(234,179,8,0.5); }
        .text-dlx-pink { background: linear-gradient(45deg, #f472b6, #fbcfe8, #ec4899); -webkit-background-clip: text; color: transparent; font-weight: 800 !important; text-shadow: 0 0 5px rgba(236,72,153,0.5); }
        .text-dlx-green { background: linear-gradient(45deg, #4ade80, #bbf7d0, #22c55e); -webkit-background-clip: text; color: transparent; font-weight: 800 !important; text-shadow: 0 0 5px rgba(34,197,94,0.5); }
        .border-dlx-blue { border: 3px solid #3b82f6; border-style: inset; box-shadow: 0 0 10px #3b82f6; }
        .border-dlx-yellow { border: 3px solid #eab308; border-style: inset; box-shadow: 0 0 10px #eab308; }
        .border-dlx-pink { border: 3px solid #ec4899; border-style: inset; box-shadow: 0 0 10px #ec4899; }
        .border-dlx-green { border: 3px solid #22c55e; border-style: inset; box-shadow: 0 0 10px #22c55e; }
        
        .tab-btn { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        .market-img-scroll { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; gap: 10px; }
        .market-img-scroll img { scroll-snap-align: center; max-width: 100%; border-radius: 8px; }
        .horizontal-scroll-container { display: flex; overflow-x: auto; scroll-behavior: smooth; -ms-overflow-style: none; scrollbar-width: none; }
        .horizontal-scroll-container::-webkit-scrollbar { display: none; }
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 4px; }
        .map-add-mode { cursor: crosshair !important; }
        .progress-bar-bg { background-color: #27272a; border-radius: 9999px; height: 8px; width: 100%; overflow: hidden; margin-top: 8px; }
        .progress-bar-fill { background: linear-gradient(90deg, #0ea5e9, #0284c7); height: 100%; transition: width 0.5s ease; }
        
        /* Safe area padding for bottom nav */
        .pb-safe { padding-bottom: env(safe-area-inset-bottom, 8px); }
        #bottom-nav { padding-bottom: max(8px, env(safe-area-inset-bottom)); }
        
        /* Mobile tap highlight fix */
        * { -webkit-tap-highlight-color: transparent; }
        
        /* Premium input focus */
        input:focus, textarea:focus, select:focus { outline: none; }
        
        /* Smooth modal backdrop */
        .modal-backdrop { background: rgba(0,0,0,0.75); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); }
        
        /* Seviye atlaması kutlama */
        @keyframes levelUpPulse {
            0%   { transform: scale(0.5) rotate(-5deg); opacity: 0; }
            40%  { transform: scale(1.15) rotate(3deg); opacity: 1; }
            70%  { transform: scale(0.95) rotate(-1deg); }
            100% { transform: scale(1) rotate(0deg); opacity: 1; }
        }
        @keyframes levelUpFloat {
            0%   { transform: translateY(0) scale(1); opacity: 1; }
            100% { transform: translateY(-80px) scale(0.5); opacity: 0; }
        }
        @keyframes storyRing {
            0%   { box-shadow: 0 0 0 3px #0ea5e9, 0 0 0 5px #0ea5e940; }
            50%  { box-shadow: 0 0 0 3px #f59e0b, 0 0 0 6px #f59e0b50; }
            100% { box-shadow: 0 0 0 3px #0ea5e9, 0 0 0 5px #0ea5e940; }
        }
        @keyframes igStoryRingSpin {
            0%   { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .level-up-anim { animation: levelUpPulse 0.7s cubic-bezier(0.34,1.56,0.64,1) both; }
        /* Instagram gradient story ring */
        .story-ring {
            border-radius: 50%;
            position: relative;
            background: linear-gradient(45deg, #f09433, #e6683c, #dc2743, #cc2366, #bc1888) border-box;
            border: 2.5px solid transparent;
            background-clip: padding-box;
            box-shadow: 0 0 0 2.5px #f09433, 0 0 12px rgba(220,39,67,0.5);
            animation: storyRing 2.5s ease-in-out infinite;
        }
        .story-seen { opacity: 0.5; filter: grayscale(60%); }

        /* ── REELS GRID VIEW ── */
        #reels-feed.grid-mode {
            display: grid !important;
            grid-template-columns: repeat(4, 1fr);
            gap: 2px;
            overflow-y: auto;
            scroll-snap-type: none;
            height: 100%;
            align-content: start;
        }
        #reels-feed.grid-mode > div {
            height: 160px !important;
            cursor: pointer;
            scroll-snap-align: unset !important;
            position: relative;
        }
        #reels-feed.grid-mode > div > video,
        #reels-feed.grid-mode > div > img {
            object-fit: cover !important;
            width: 100% !important;
            height: 100% !important;
        }
        #reels-feed.grid-mode > div > .absolute { display: none !important; }
        #reels-feed.grid-mode > div > video { pointer-events: none; }
        .reel-fullscreen-overlay {
            position: fixed;
            inset: 0;
            z-index: 100;
            background: #000;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        /* Play/Pause flash icon */
        .reel-play-flash {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            pointer-events: none;
            z-index: 20;
            opacity: 0;
            transition: opacity 0.15s;
        }
        .reel-play-flash.show {
            opacity: 1;
            animation: flashFade 0.5s ease-out forwards;
        }
        @keyframes flashFade {
            0%   { opacity: 1; transform: translate(-50%,-50%) scale(1); }
            60%  { opacity: 0.7; transform: translate(-50%,-50%) scale(1.15); }
            100% { opacity: 0; transform: translate(-50%,-50%) scale(0.9); }
        }

        /* Özel tema rengi */
        .theme-red    { --accent: #0ea5e9; --accent-light: #38bdf8; }
        .theme-blue   { --accent: #2563eb; --accent-light: #3b82f6; }
        .theme-green  { --accent: #16a34a; --accent-light: #22c55e; }
        .theme-purple { --accent: #7c3aed; --accent-light: #8b5cf6; }
        .theme-orange { --accent: #ea580c; --accent-light: #f97316; }
        .theme-pink   { --accent: #db2777; --accent-light: #ec4899; }
        body { --accent: #0ea5e9; --accent-light: #38bdf8; }

        @keyframes confettiFall {
            0%   { transform: translateY(0) rotate(0deg) scale(1); opacity: 1; }
            100% { transform: translateY(60vh) rotate(720deg) scale(0.3); opacity: 0; }
        }
        @keyframes scaleIn {
            0%   { opacity: 0; transform: scale(0.7); }
            70%  { transform: scale(1.04); }
            100% { opacity: 1; transform: scale(1); }
        }
        @keyframes bounce {
            0%   { transform: translateY(0px) scale(1); }
            100% { transform: translateY(-14px) scale(1.08); }
        }
        @keyframes wheelSpinGlow {
            0%,100% { box-shadow: 0 0 35px rgba(14,165,233,0.5), 0 0 60px rgba(234,179,8,0.2); }
            50%      { box-shadow: 0 0 55px rgba(234,179,8,0.9), 0 0 100px rgba(14,165,233,0.6), 0 0 8px rgba(255,255,255,0.4); }
        }
        @keyframes confettiRect {
            0%   { transform: translateY(0) rotate(0deg); opacity: 1; }
            100% { transform: translateY(70vh) rotate(900deg); opacity: 0; }
        }
        .wheel-spinning-canvas {
            animation: wheelSpinGlow 0.35s ease-in-out infinite !important;
        }
        @keyframes trialBanner {
            0%   { transform: translateY(-100%); opacity: 0; }
            15%  { transform: translateY(0); opacity: 1; }
            85%  { transform: translateY(0); opacity: 1; }
            100% { transform: translateY(-100%); opacity: 0; }
        }
        .trial-banner { animation: trialBanner 5s ease-in-out forwards; }
        .wheel-slice {
            position: absolute;
            top: 50%;
            left: 50%;
            width: 50%;
            height: 20px;
            transform-origin: 0% 50%;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 15px;
            box-sizing: border-box;
            color: white;
            font-weight: 900;
            font-size: 10px;
            text-shadow: 1px 1px 3px black;
            text-transform: uppercase;
        }

        /* ═══════════════════════════════════════════════════════
           FREERIDER TR — BUZ CAM MAVİSİ PREMIUM TEMA v3
           Ice Glass Blue Ultra Premium Edition
           ═══════════════════════════════════════════════════════ */

        /* ── Buz kristal doku efektleri ── */
        @keyframes iceShimmer {
            0%   { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        @keyframes frostPulse {
            0%,100% { 
                box-shadow: 0 0 12px rgba(14,165,233,0.35), 0 0 24px rgba(56,189,248,0.12),
                            inset 0 0 20px rgba(56,189,248,0.04);
            }
            50% { 
                box-shadow: 0 0 24px rgba(14,165,233,0.55), 0 0 48px rgba(56,189,248,0.18),
                            inset 0 0 30px rgba(56,189,248,0.06);
            }
        }
        @keyframes iceGlow {
            0%,100% { filter: drop-shadow(0 0 4px rgba(56,189,248,0.6)); }
            50%      { filter: drop-shadow(0 0 10px rgba(56,189,248,0.9)); }
        }
        @keyframes crystalFloat {
            0%,100% { transform: translateY(0px) rotate(0deg); }
            33%     { transform: translateY(-4px) rotate(1deg); }
            66%     { transform: translateY(-2px) rotate(-1deg); }
        }
        @keyframes auroraShift {
            0%   { background-position: 0% 50%; }
            50%  { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        @keyframes frostLine {
            0%   { opacity: 0; transform: scaleX(0); }
            50%  { opacity: 1; transform: scaleX(1); }
            100% { opacity: 0; transform: scaleX(0); }
        }
        @keyframes iceRipple {
            0%   { transform: scale(0); opacity: 0.7; }
            100% { transform: scale(4); opacity: 0; }
        }
        @keyframes glacierPulse {
            0%,100% { opacity: 0.06; }
            50%     { opacity: 0.12; }
        }

        .ice-glow  { animation: iceGlow 2s ease-in-out infinite; }
        .frost-pulse { animation: frostPulse 3s ease-in-out infinite; }
        .crystal-float { animation: crystalFloat 4s ease-in-out infinite; }

        /* ── Buz cam ultra glass panel ── */
        .glass-panel {
            background: linear-gradient(
                135deg,
                rgba(8,18,36,0.94) 0%,
                rgba(5,14,28,0.97) 50%,
                rgba(8,18,36,0.94) 100%
            ) !important;
            backdrop-filter: blur(32px) saturate(200%) brightness(1.05) !important;
            -webkit-backdrop-filter: blur(32px) saturate(200%) brightness(1.05) !important;
            border: 1px solid rgba(56,189,248,0.09) !important;
            box-shadow:
                0 24px 64px rgba(0,0,0,0.72),
                inset 0 1px 0 rgba(125,211,252,0.08),
                inset 0 -1px 0 rgba(14,165,233,0.04),
                0 0 0 0.5px rgba(56,189,248,0.06) !important;
        }

        /* ── Buz shimmer efekti (özel kartlar için) ── */
        .ice-shimmer-bg {
            background: linear-gradient(
                90deg,
                rgba(14,165,233,0.03) 0%,
                rgba(56,189,248,0.08) 30%,
                rgba(125,211,252,0.12) 50%,
                rgba(56,189,248,0.08) 70%,
                rgba(14,165,233,0.03) 100%
            );
            background-size: 200% 100%;
            animation: iceShimmer 4s linear infinite;
        }

        /* ── Aurora arkaplan efekti ── */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background: 
                radial-gradient(ellipse 60% 40% at 20% 80%, rgba(14,165,233,0.04) 0%, transparent 60%),
                radial-gradient(ellipse 40% 30% at 80% 20%, rgba(56,189,248,0.03) 0%, transparent 60%);
            pointer-events: none;
            z-index: 0;
            animation: glacierPulse 6s ease-in-out infinite;
        }

        /* ── Arka Plan Dokusu ── */
        body {
            background:
                radial-gradient(ellipse 80% 50% at 50% -10%, rgba(2,132,199,0.18) 0%, transparent 60%),
                radial-gradient(ellipse 50% 30% at 85% 90%, rgba(120,0,0,0.12) 0%, transparent 50%),
                #000;
        }

        /* ── Gelişmiş Glass Panel ── */
        .glass-panel {
            background: linear-gradient(135deg, rgba(18,18,22,0.92) 0%, rgba(10,10,14,0.96) 100%);
            backdrop-filter: blur(28px) saturate(200%);
            -webkit-backdrop-filter: blur(28px) saturate(200%);
            border: 1px solid rgba(255,255,255,0.06);
            box-shadow:
                0 24px 60px rgba(0,0,0,0.7),
                inset 0 1px 0 rgba(255,255,255,0.06),
                inset 0 -1px 0 rgba(0,0,0,0.4);
        }

        /* ── App Header Gradient Border ── */
        #main-app > div:first-child {
            background: linear-gradient(180deg, rgba(3,12,24,0.95) 0%, rgba(15,15,20,0.88) 100%);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid transparent;
            background-clip: padding-box;
            box-shadow: 0 1px 0 rgba(14,165,233,0.35), 0 4px 20px rgba(0,0,0,0.5);
        }

        /* ── FREERIDER markası parlar ── */
        @keyframes brandPulse {
            0%,100% { text-shadow: 0 0 8px rgba(14,165,233,0.4); }
            50%      { text-shadow: 0 0 20px rgba(14,165,233,0.9), 0 0 40px rgba(14,165,233,0.3); }
        }
        #main-app .teko-font.text-2xl { animation: brandPulse 4s ease-in-out infinite; }

        /* ── Gelişmiş Bottom Nav (Floating Pill) ── */
        #bottom-nav {
            background: linear-gradient(180deg, rgba(8,8,12,0.0) 0%, rgba(0,0,0,0.98) 100%) !important;
            border-top: none !important;
            box-shadow: none !important;
            padding-top: 4px;
            padding-bottom: max(12px, env(safe-area-inset-bottom));
        }
        #bottom-nav::before {
            content: '';
            position: absolute;
            inset: 0;
            border-top: 1px solid rgba(14,165,233,0.2);
            pointer-events: none;
        }
        #bottom-nav button {
            position: relative;
            border-radius: 14px;
            padding: 8px 10px 6px;
            transition: all 0.3s cubic-bezier(0.34,1.56,0.64,1);
        }
        #bottom-nav button.text-white {
            background: linear-gradient(135deg, rgba(2,132,199,0.35), rgba(120,0,0,0.2)) !important;
            box-shadow: 0 0 16px rgba(14,165,233,0.35), inset 0 1px 0 rgba(255,255,255,0.07);
        }
        #bottom-nav button.text-white span:first-child {
            filter: drop-shadow(0 0 6px rgba(14,165,233,0.8));
            transform: scale(1.15);
            display: inline-block;
        }
        #bottom-nav button span:first-child {
            transition: transform 0.3s cubic-bezier(0.34,1.56,0.64,1), filter 0.3s ease;
        }
        #bottom-nav button:active { transform: scale(0.88) !important; }

        /* ── Gelişmiş Yükleme Ekranı ── */
        #app-loading-screen {
            background: radial-gradient(ellipse 70% 60% at 50% 40%, rgba(3,105,161,0.4) 0%, #000 70%);
        }

        /* ── Animasyonlar ── */
        @keyframes floatUp {
            0%,100% { transform: translateY(0px); }
            50%      { transform: translateY(-8px); }
        }
        @keyframes glowPulse {
            0%,100% { box-shadow: 0 0 15px rgba(14,165,233,0.4), 0 0 30px rgba(14,165,233,0.1); }
            50%      { box-shadow: 0 0 30px rgba(14,165,233,0.8), 0 0 60px rgba(14,165,233,0.3); }
        }
        @keyframes morphBorder {
            0%,100% { border-radius: 24px; }
            50%      { border-radius: 32px; }
        }
        @keyframes slideUpSpring {
            0%   { opacity:0; transform: translateY(32px) scale(0.95); }
            60%  { opacity:1; transform: translateY(-4px) scale(1.01); }
            100% { opacity:1; transform: translateY(0) scale(1); }
        }
        @keyframes fadeSlideLeft {
            0%   { opacity:0; transform: translateX(24px); }
            100% { opacity:1; transform: translateX(0); }
        }
        @keyframes fadeSlideRight {
            0%   { opacity:0; transform: translateX(-24px); }
            100% { opacity:1; transform: translateX(0); }
        }
        @keyframes cardEnter {
            0%   { opacity:0; transform: translateY(20px) scale(0.96); }
            70%  { opacity:1; transform: translateY(-2px) scale(1.01); }
            100% { opacity:1; transform: translateY(0) scale(1); }
        }
        @keyframes shimmerSweep {
            0%   { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        @keyframes neonBlink {
            0%,95%,100% { opacity:1; }
            97%          { opacity:0.6; }
        }
        @keyframes iconBounce {
            0%,100% { transform: translateY(0) rotate(0deg); }
            25%     { transform: translateY(-5px) rotate(-8deg); }
            75%     { transform: translateY(-3px) rotate(6deg); }
        }
        @keyframes scanline {
            0%   { transform: translateY(-100%); }
            100% { transform: translateY(100vh); }
        }
        @keyframes gradientShift {
            0%   { background-position: 0% 50%; }
            50%  { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .float-anim   { animation: floatUp 3s ease-in-out infinite; }
        .glow-pulse   { animation: glowPulse 2.5s ease-in-out infinite; }
        .card-enter   { animation: cardEnter 0.45s cubic-bezier(0.34,1.56,0.64,1) both; }
        .slide-up-anim { animation: slideUpSpring 0.5s cubic-bezier(0.34,1.3,0.64,1) both; }
        .scale-in-anim { animation: slideUpSpring 0.4s cubic-bezier(0.34,1.56,0.64,1) both; }

        /* ── Gelişmiş Buton Hover ── */
        .btn-premium-hover {
            transition: all 0.25s cubic-bezier(0.34,1.2,0.64,1);
            position: relative;
            overflow: hidden;
        }
        .btn-premium-hover::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(255,255,255,0.06) 0%, transparent 50%, rgba(255,255,255,0.02) 100%);
            opacity: 0;
            transition: opacity 0.2s;
            pointer-events: none;
            border-radius: inherit;
        }
        .btn-premium-hover:hover::before { opacity: 1; }
        .btn-premium-hover:hover {
            transform: translateY(-2px) scale(1.02);
            box-shadow: 0 8px 24px rgba(14,165,233,0.4), 0 2px 8px rgba(0,0,0,0.4);
        }
        .btn-premium-hover:active {
            transform: translateY(1px) scale(0.97);
            box-shadow: 0 2px 8px rgba(14,165,233,0.2);
        }
        .btn-premium-hover::after {
            content: '';
            position: absolute;
            top: 50%; left: 50%;
            width: 4px; height: 4px;
            background: rgba(255,255,255,0.6);
            border-radius: 50%;
            transform: scale(0); opacity: 0;
            pointer-events: none;
        }
        .btn-premium-hover:active::after { animation: ripple 0.5s ease-out forwards; }

        /* ── Shimmer Loading Skeleton ── */
        .skeleton {
            background: linear-gradient(90deg, #0a1525 25%, #0d1e36 50%, #0a1525 75%);
            background-size: 200% 100%;
            animation: shimmerSweep 1.5s infinite;
            border-radius: 8px;
        }

        /* ── Gradient Progress Bar ── */
        .progress-bar-fill {
            background: linear-gradient(90deg, #0ea5e9, #f97316, #eab308) !important;
            background-size: 200% 100%;
            animation: gradientShift 2s ease infinite;
            box-shadow: 0 0 8px rgba(14,165,233,0.5);
        }

        /* ── Kart Hover Efekti ── */
        .hover-card {
            transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
        }
        .hover-card:hover {
            transform: translateY(-3px) scale(1.01);
            box-shadow: 0 16px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.06);
        }

        /* ── Modal Backdrop Gelişmiş ── */
        .modal-backdrop {
            background: rgba(0,0,0,0.82);
            backdrop-filter: blur(12px) saturate(150%);
            -webkit-backdrop-filter: blur(12px) saturate(150%);
        }

        /* ── Özel Scrollbar ── */
        .custom-scrollbar::-webkit-scrollbar { width: 3px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(0,0,0,0.2); }
        .custom-scrollbar::-webkit-scrollbar-thumb {
            background: linear-gradient(180deg, #0ea5e9, #0c4a6e);
            border-radius: 3px;
        }

        /* ── Input Glow Focus ── */
        input:focus, textarea:focus, select:focus {
            box-shadow: 0 0 0 2px rgba(14,165,233,0.3), 0 0 12px rgba(14,165,233,0.15) !important;
            border-color: rgba(14,165,233,0.7) !important;
        }

        /* ── Sidebar Gelişmiş ── */
        #sidebar {
            background: linear-gradient(180deg, rgba(2,6,16,0.98) 0%, rgba(5,5,8,0.99) 100%) !important;
            border-right: 1px solid rgba(14,165,233,0.2) !important;
            box-shadow: 4px 0 40px rgba(0,0,0,0.8) !important;
        }
        #sidebar button.tab-btn {
            transition: all 0.25s cubic-bezier(0.4,0,0.2,1);
            border-left: 2px solid transparent;
        }
        #sidebar button.tab-btn:hover {
            background: rgba(14,165,233,0.08) !important;
            border-left-color: rgba(14,165,233,0.5);
            transform: translateX(3px);
        }
        #sidebar button.bg-zinc-900 {
            background: linear-gradient(135deg, rgba(2,132,199,0.25), rgba(3,105,161,0.15)) !important;
            border-left: 2px solid rgba(14,165,233,0.7);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
        }

        /* ── Profil Kartı Efekti ── */
        #screen-profile .glass-panel {
            border: 1px solid rgba(255,255,255,0.07);
            transition: border-color 0.3s ease;
        }
        #screen-profile .glass-panel:hover {
            border-color: rgba(14,165,233,0.2);
        }

        /* ── Leaderboard Row ── */
        @keyframes goldShine {
            0%,100% { box-shadow: 0 0 10px rgba(251,191,36,0.3); }
            50%      { box-shadow: 0 0 20px rgba(251,191,36,0.7), 0 0 40px rgba(251,191,36,0.2); }
        }

        /* ── Toast Bildirimleri ── */
        @keyframes toastSlide {
            0%   { opacity:0; transform: translateX(-50%) translateY(-20px) scale(0.9); }
            60%  { opacity:1; transform: translateX(-50%) translateY(4px) scale(1.02); }
            100% { opacity:1; transform: translateX(-50%) translateY(0) scale(1); }
        }

        /* ── Reel Kart Overlay Gradient ── */
        #reels-feed .absolute.inset-0 {
            background: linear-gradient(
                to top,
                rgba(0,0,0,0.88) 0%,
                rgba(0,0,0,0.3) 40%,
                transparent 70%
            ) !important;
        }

        /* ── Story Ring Gelişmiş ── */
        .story-ring {
            animation: storyRing 2.5s ease-in-out infinite;
            box-shadow: 0 0 12px rgba(14,165,233,0.4);
        }

        /* ── bg-glass Gelişmiş ── */
        .bg-glass {
            background: rgba(4, 10, 24, 0.88) !important;
            backdrop-filter: blur(20px) saturate(180%) !important;
            -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
            border-color: rgba(255,255,255,0.06) !important;
        }

        /* ── bg-darker ── */
        .bg-darker {
            background: linear-gradient(180deg, #03080f 0%, #020609 100%) !important;
        }

        /* ── Dalgalı Separator ── */
        .wave-sep {
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(14,165,233,0.5), rgba(251,191,36,0.3), rgba(14,165,233,0.5), transparent);
            margin: 16px 0;
        }

        /* ── Yükleme Animasyonu Gelişmiş ── */
        @keyframes loadRing {
            0%   { transform: rotate(0deg) scale(1); }
            50%  { transform: rotate(180deg) scale(1.05); }
            100% { transform: rotate(360deg) scale(1); }
        }
        #app-loading-screen .animate-spin {
            animation: loadRing 1.2s cubic-bezier(0.4,0,0.6,1) infinite !important;
            box-shadow: 0 0 20px rgba(14,165,233,0.6);
        }

        /* ── Harita Overlay Gradient ── */
        #screen-map::after {
            content: '';
            position: absolute;
            bottom: 0; left: 0; right: 0;
            height: 60px;
            background: linear-gradient(to top, rgba(2,8,22,0.4), transparent);
            pointer-events: none;
            z-index: 5;
        }

        /* ════════════════════════════════════════════════════════
           OVERFLOW & TAŞMA DÜZELTMELERİ
           ════════════════════════════════════════════════════════ */

        /* Global overflow kontrol */
        *, *::before, *::after {
            box-sizing: border-box;
        }

        /* Flex child taşma engelleyici */
        .flex > * { min-width: 0; }
        .flex-1   { min-width: 0; }

        /* Text taşma önleme */
        .truncate-safe {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            min-width: 0;
        }

        /* İçerik taşma engel */
        #screen-chat, #screen-leaderboard, #screen-profile,
        #screen-market, #screen-news, #screen-missions,
        #screen-reels, #screen-plus, #screen-invite {
            overflow-x: hidden !important;
            overflow-y: auto !important;
        }

        /* Mesaj balonları taşma engeli */
        .chat-bubble-wrap {
            max-width: calc(100% - 60px) !important;
            overflow-wrap: break-word !important;
            word-break: break-word !important;
        }

        /* Resim taşma engeli */
        img {
            max-width: 100%;
            height: auto;
        }

        /* Modal içi overflow */
        .glass-panel {
            max-width: calc(100vw - 32px) !important;
            overflow-x: hidden !important;
        }

        /* Kullanıcı adı taşma */
        [id$="-username"], .username-text {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 100%;
        }

        /* Yatay scroll container'lar */
        .horizontal-scroll-container {
            overflow-x: auto !important;
            overflow-y: hidden !important;
            max-width: 100% !important;
        }

        /* Grid ve flex taşma */
        .grid { overflow: hidden; }

        /* Bottom nav güvenli alan */
        #bottom-nav {
            width: 100% !important;
            max-width: 100% !important;
            overflow: hidden !important;
        }

        /* Ana konteyner taşma engeli */
        .max-w-md {
            overflow-x: hidden !important;
        }

        /* Toast overflow fix */
        #toast-notification {
            max-width: calc(100vw - 32px) !important;
            left: 50% !important;
            transform: translateX(-50%) !important;
        }
    </style>
</head>
<body class="h-[100dvh] w-full overflow-hidden bg-black relative">
    <!-- Premium Yükleme Ekranı v2 -->
    <div id="app-loading-screen" class="fixed inset-0 z-[9999] flex flex-col items-center justify-center" style="background:radial-gradient(ellipse 70% 60% at 50% 40%,rgba(3,105,161,0.5) 0%,#000 70%);transition:opacity 0.6s ease;">
        <!-- Arka dekor halkalar - buz kristal efekti -->
        <div class="absolute w-96 h-96 rounded-full" style="border:1px solid rgba(56,189,248,0.06);animation:ping 4s cubic-bezier(0,0,0.2,1) infinite;animation-delay:0.6s"></div>
        <div class="absolute w-64 h-64 rounded-full border border-sky-700/20 animate-ping" style="animation-duration:2.5s;box-shadow:0 0 20px rgba(14,165,233,0.05)" style="animation-duration:2.5s;"></div>
        <div class="absolute w-48 h-48 rounded-full border border-sky-600/25 animate-ping" style="animation-duration:2s;animation-delay:0.3s;box-shadow:0 0 15px rgba(56,189,248,0.08)" style="animation-duration:2s;animation-delay:0.3s;"></div>
        <!-- Logo container -->
        <div class="relative mb-8 z-10">
            <div class="w-24 h-24 rounded-full border-[3px] border-transparent" style="background:conic-gradient(from 0deg,#0ea5e9,#f97316,#eab308,#0ea5e9);padding:3px;border-radius:50%;box-shadow:0 0 40px rgba(14,165,233,0.6),0 0 80px rgba(14,165,233,0.2);">
                <div class="w-full h-full rounded-full bg-black flex items-center justify-center">
                    <span class="text-3xl" style="filter:drop-shadow(0 0 8px rgba(14,165,233,0.8))">🏔️</span>
                </div>
            </div>
            <!-- Dönen halkalar -->
            <div class="absolute inset-0 animate-spin" style="animation-duration:1.5s;">
                <div class="w-24 h-24 rounded-full border-t-2 border-r-2 border-sky-400/60 border-b-transparent border-l-transparent" style="filter:blur(0.5px)"></div>
            </div>
            <div class="absolute inset-0 animate-spin" style="animation-duration:2.2s;animation-direction:reverse;">
                <div class="w-24 h-24 rounded-full border-t-transparent border-r-transparent border-b-2 border-l-2 border-cyan-400/50" style="filter:blur(0.5px)"></div>
            </div>
        </div>
        <!-- Brand -->
        <div class="z-10 text-center">
            <div class="teko-font text-white text-5xl tracking-[0.15em] drop-shadow-xl" style="text-shadow:0 0 30px rgba(14,165,233,0.7)">FREERIDER<span style="color:#0ea5e9;text-shadow:0 0 20px #0ea5e9,0 0 40px #0ea5e9aa;">TR</span></div>
            <div class="flex items-center justify-center gap-2 mt-3">
                <div class="h-px w-12 bg-gradient-to-r from-transparent to-sky-500/60"></div>
                <div class="text-zinc-400 text-[10px] uppercase tracking-[0.3em] font-bold animate-pulse">Yükleniyor</div>
                <div class="h-px w-12 bg-gradient-to-l from-transparent to-sky-500/60"></div>
            </div>
            <div class="flex justify-center gap-1 mt-3">
                <div class="w-1.5 h-1.5 bg-sky-400 rounded-full animate-bounce" style="animation-delay:0s"></div>
                <div class="w-1.5 h-1.5 bg-sky-300 rounded-full animate-bounce" style="animation-delay:0.15s"></div>
                <div class="w-1.5 h-1.5 bg-cyan-300 rounded-full animate-bounce" style="animation-delay:0.3s"></div>
            </div>
        </div>
    </div>
    <audio id="notif-sound" src="https://cdn.freesound.org/previews/256/256113_3263906-lq.mp3" preload="auto"></audio>
    <input type="file" id="chat-photo-upload" accept="image/*" class="hidden" onchange="handleChatPhotoUpload(this)">

    <div id="sidebar-overlay" class="hidden fixed inset-0 modal-backdrop z-[1000] backdrop-blur-sm transition-opacity duration-300" onclick="toggleSidebar()"></div>
    <div id="sidebar" class="fixed inset-y-0 left-0 w-64 bg-zinc-950 border-r border-zinc-800 z-[1001] transform -translate-x-full transition-transform duration-500 cubic-bezier(0.16, 1, 0.3, 1) flex flex-col shadow-2xl glass-panel">
        <div class="p-5 border-b border-zinc-800 flex items-center gap-3 shrink-0">
            <span class="text-3xl drop-shadow-lg">🏔️</span>
            <span class="teko-font text-white text-3xl tracking-widest font-bold mt-1">MENÜ</span>
          <button onclick="toggleSidebar()" class="bg-zinc-800/80 hover:bg-zinc-700 transition px-3 py-1 rounded-xl text-white text-2xl mr-2 border border-zinc-700 focus:outline-none shadow-md">☰</button>
        </div>
        <div class="flex-1 overflow-y-auto py-4 flex flex-col gap-2 px-3 custom-scrollbar">
            <button id="tab-btn-0" onclick="switchTab(0)" class="w-full py-3 px-4 flex items-center gap-4 text-white bg-zinc-900 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center">🗺️</span> Harita</button>
            <button id="tab-btn-1" onclick="switchTab(1)" class="w-full py-3 px-4 flex items-center gap-4 text-zinc-500 hover:bg-zinc-900/50 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center">💬</span> Chat</button>
            <button id="tab-btn-2" onclick="switchTab(2)" class="w-full py-3 px-4 flex items-center gap-4 text-zinc-500 hover:bg-zinc-900/50 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center">🛒</span> Pazar</button>
            <button id="tab-btn-3" onclick="switchTab(3)" class="w-full py-3 px-4 flex items-center gap-4 text-zinc-500 hover:bg-zinc-900/50 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center">🏆</span> Lider Tablosu</button>
            <button id="tab-btn-4" onclick="switchTab(4)" class="w-full py-3 px-4 flex items-center gap-4 text-zinc-500 hover:bg-zinc-900/50 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center">📰</span> Haberler</button>
            <button id="tab-btn-5" onclick="switchTab(5)" class="w-full py-3 px-4 flex items-center gap-4 text-zinc-500 hover:bg-zinc-900/50 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center">🎯</span> Görevler ve Çark</button>
            <button id="tab-btn-9" onclick="switchTab(9)" class="w-full py-3 px-4 flex items-center gap-4 text-pink-400 hover:bg-pink-900/20 border border-transparent hover:border-pink-500/30 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center">🎬</span> Reels</button>
            <button id="tab-btn-8" onclick="switchTab(8)" class="w-full py-3 px-4 flex items-center gap-4 text-purple-400 hover:bg-purple-900/30 border border-transparent hover:border-purple-500/30 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center drop-shadow-[0_0_10px_purple]">🤝</span> Davet Et Kazan</button>
            <button id="tab-btn-6" onclick="switchTab(6)" class="w-full py-3 px-4 flex items-center gap-4 text-yellow-500 hover:bg-yellow-900/30 border border-transparent hover:border-yellow-500/30 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center drop-shadow-[0_0_10px_yellow]">🌟</span> Freerider Plus</button>
            <button id="tab-btn-7" onclick="switchTab(7)" class="w-full py-3 px-4 flex items-center gap-4 text-zinc-500 hover:bg-zinc-900/50 rounded-xl tab-btn font-bold transition-all"><span class="text-xl w-6 text-center">👤</span> Profilim</button>
        </div>
        <div id="sidebar-weather" class="mx-3 mb-2 rounded-2xl px-4 py-3 border border-zinc-800 bg-zinc-900/60 hidden">
            <div class="text-[9px] font-black uppercase tracking-widest text-zinc-500 mb-1">HAVA DURUMU</div>
            <div id="sidebar-weather-content" class="flex items-center gap-2">
                <span id="sidebar-weather-icon" class="text-2xl">⏳</span>
                <div>
                    <div id="sidebar-weather-temp" class="text-white font-black text-sm teko-font"></div>
                    <div id="sidebar-weather-desc" class="text-zinc-400 text-[10px] font-bold"></div>
                </div>
            </div>
        </div>
        <div class="p-4 border-t border-zinc-800 flex flex-col gap-2">
                <button onclick="document.getElementById('social-modal').classList.remove('hidden'); toggleSidebar();" class="w-full bg-zinc-900 border border-pink-700/40 hover:bg-pink-900/20 transition text-pink-400 py-3 rounded-xl font-bold text-xs tracking-widest flex items-center justify-center gap-2">
                    <span>📸</span> Hesaplarımızı Takip Et
                </button>
                <button onclick="window.open('https://whatsapp.com/channel/0029VbCTLFCJUM2kLBD7TC1Z', '_blank')" class="w-full bg-zinc-900 border border-green-700/40 hover:bg-green-900/20 transition text-green-400 py-3 rounded-xl font-bold text-xs tracking-widest flex items-center justify-center gap-2">
                    <span>💬</span> WP Kanalı
                </button>
                <button onclick="openSupportModal(); toggleSidebar();" class="w-full bg-zinc-900 border border-blue-700/40 hover:bg-blue-900/20 transition text-blue-400 py-3 rounded-xl font-bold text-xs tracking-widest flex items-center justify-center gap-2">
                    <span>🎧</span> Destek & Geri Bildirim
                </button>

            </div>
    </div>

    <div class="max-w-md mx-auto h-[100dvh] flex flex-col shadow-2xl bg-darker border-x border-zinc-900/50 relative overflow-x-hidden">
        <div id="login-screen" class="flex-1 flex flex-col overflow-y-auto z-50 relative slide-up-anim">
            <video autoplay loop muted playsinline class="absolute inset-0 w-full h-full object-cover z-0 opacity-40">
                <source src="https://cdn.freeridertr.com.tr/video%20ana/istockphoto-2221026101-640_adpp_is.mp4">
            </video>
            
            <div class="absolute inset-0 bg-gradient-to-b from-black/90 via-black/60 to-[#020b19] z-0"></div>

            <div class="flex flex-col items-center justify-center pt-16 pb-8 relative z-10 shrink-0">
                <a href="https://instagram.com/om3r_10fr" target="_blank" class="absolute top-4 right-4 bg-sky-900/80 text-white text-[11px] font-bold py-2 px-4 rounded-full flex items-center gap-2 z-20 border border-sky-400/50 shadow-[0_0_15px_rgba(14,165,233,0.5)] btn-premium-hover">
                    <span class="text-white">📸</span> Takip Et
                </a>
                
                <div class="text-center flex flex-col items-center scale-in-anim">
                    <div class="w-24 h-24 mx-auto rounded-full overflow-hidden border-4 border-sky-500 shadow-[0_0_40px_rgba(14,165,233,0.8)] relative mb-4 bg-zinc-950 flex justify-center items-center">
                        <span class="text-5xl drop-shadow-lg">🏔️</span>
                    </div>
                    <h1 class="teko-font text-6xl text-white tracking-widest drop-shadow-[0_10px_10px_rgba(0,0,0,1)]">FREERIDER<span class="text-sky-500">TR</span></h1>
                    <p class="text-zinc-300 text-xs uppercase tracking-widest mt-2 font-black drop-shadow-md">HARDCORE DOWNHILL TOPLULUĞU</p>
                </div>
            </div>
            
            <!-- Kullanıcı İstatistikleri Çubuğu -->
            <div class="relative z-10 px-6 mb-3">
                <div class="flex items-center justify-center gap-4 bg-black/60 border border-zinc-800 rounded-2xl px-5 py-3 backdrop-blur-md">
                    <div class="flex items-center gap-2">
                        <div class="w-2 h-2 rounded-full bg-green-500 animate-pulse shadow-[0_0_6px_rgba(34,197,94,0.8)]"></div>
                        <div class="text-center">
                            <div id="login-active-users" class="text-green-400 font-black text-lg teko-font leading-none">--</div>
                            <div class="text-[9px] text-zinc-500 uppercase tracking-widest font-bold">Aktif</div>
                        </div>
                    </div>
                    <div class="w-px h-8 bg-zinc-700"></div>
                    <div class="flex items-center gap-2">
                        <span class="text-lg">👥</span>
                        <div class="text-center">
                            <div id="login-total-users" class="text-white font-black text-lg teko-font leading-none">--</div>
                            <div class="text-[9px] text-zinc-500 uppercase tracking-widest font-bold">Toplam Üye</div>
                        </div>
                    </div>
                    <div class="w-px h-8 bg-zinc-700"></div>
                    <div class="flex items-center gap-2">
                        <span class="text-lg">🏔️</span>
                        <div class="text-center">
                            <div class="text-sky-300 font-black text-lg teko-font leading-none">TR#1</div>
                            <div class="text-[9px] text-zinc-500 uppercase tracking-widest font-bold">Platform</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="p-6 flex-1 relative z-10 flex flex-col justify-end pb-12">
                <div class="glass-panel p-6 rounded-3xl">
                    <div class="flex bg-zinc-900/80 rounded-xl p-1 mb-8 shadow-inner border border-zinc-800">
                        <button onclick="showLoginTab()" id="login-tab-btn" class="flex-1 py-3 bg-gradient-to-r from-sky-700 to-sky-500 text-white rounded-lg font-black text-sm shadow-[0_0_15px_rgba(2,132,199,0.5)] tracking-widest uppercase transition-all">GİRİŞ YAP</button>
                        <button onclick="showRegisterTab()" id="register-tab-btn" class="flex-1 py-3 bg-transparent text-zinc-400 rounded-lg font-bold text-sm tracking-widest uppercase transition-all hover:text-white">KAYIT OL</button>
                    </div>
                    
                    <div id="login-form" class="scale-in-anim">
                        <input id="login-username" type="text" placeholder="Kullanıcı Adı" class="w-full bg-black/50 border border-zinc-700 rounded-xl px-5 py-4 mb-3 outline-none text-white focus:border-sky-500 focus:bg-black/80 transition-all font-bold">
                        <input id="login-password" type="password" placeholder="Şifre" class="w-full bg-black/50 border border-zinc-700 rounded-xl px-5 py-4 mb-4 outline-none text-white focus:border-sky-500 focus:bg-black/80 transition-all font-bold">
                        
                        <div class="flex justify-between items-center mb-8 px-1">
                            <div class="flex items-center gap-2">
                                <input type="checkbox" id="remember-me" class="w-4 h-4 accent-sky-500 rounded cursor-pointer">
                                <label for="remember-me" class="text-xs text-zinc-400 font-bold cursor-pointer uppercase tracking-wider">Savaşa Hazır (Hatırla)</label>
                            </div>
                            <a href="javascript:void(0)" onclick="openForgotPasswordModal()" class="text-xs text-blue-400 hover:text-blue-300 transition hover:underline">Şifremi Unuttum?</a>
                        </div>
                        
                        <button onclick="handleLogin()" class="w-full bg-gradient-to-r from-sky-700 to-sky-500 btn-premium-hover text-white py-4 rounded-xl font-black shadow-[0_0_20px_rgba(14,165,233,0.6)] text-lg tracking-widest w-full">SİSTEME DAL</button>
                    </div>
                    
                    <div id="register-form" class="hidden scale-in-anim">
                        <input id="reg-name" type="text" placeholder="Ad Soyad" class="w-full bg-black/50 border border-zinc-700 rounded-xl px-5 py-4 mb-3 outline-none text-white focus:border-sky-500 transition-all font-bold">
                        <input id="reg-username" type="text" placeholder="Kullanıcı Adı" class="w-full bg-black/50 border border-zinc-700 rounded-xl px-5 py-4 mb-3 outline-none text-white focus:border-sky-500 transition-all font-bold">
                        <input id="reg-city" type="text" placeholder="Şehir" class="w-full bg-black/50 border border-zinc-700 rounded-xl px-5 py-4 mb-3 outline-none text-white focus:border-sky-500 transition-all font-bold">
                        <input id="reg-password" type="password" placeholder="Şifre" class="w-full bg-black/50 border border-zinc-700 rounded-xl px-5 py-4 mb-3 outline-none text-white focus:border-sky-500 transition-all font-bold">
                        
                        <input id="reg-email" type="email" placeholder="E-posta (@gmail.com — İsteğe Bağlı)" class="w-full bg-black/50 border border-zinc-700 rounded-xl px-5 py-4 mb-1 outline-none text-white focus:border-sky-500 transition-all font-bold">
                        <div class="mb-3 px-1 space-y-1">
                            <p class="text-[10px] text-yellow-400/80 leading-tight">⚠️ <b>Gmail girmezsen şifreni sıfırlayamazsın.</b> Daha sonra profil ayarlarından ekleyebilirsin.</p>
                            <p class="text-[10px] text-zinc-500 leading-tight">Referans kodu kullanmak için @gmail.com zorunludur.</p>
                        </div>

                        <input id="reg-ref-code" type="text" placeholder="Referans Kodu (İsteğe Bağlı)" class="w-full bg-black/50 border border-purple-500/50 rounded-xl px-5 py-4 mb-3 outline-none text-purple-100 focus:border-purple-400 focus:shadow-[0_0_15px_rgba(168,85,247,0.3)] transition-all font-bold" oninput="checkRefCodeInput()">
                        
                        <div id="reg-ref-reward-container" class="hidden mb-3 p-4 bg-purple-900/30 border border-purple-500/50 rounded-xl backdrop-blur-sm">
                            <p class="text-[10px] text-purple-300 font-bold uppercase tracking-widest mb-2 flex items-center gap-2"><span class="animate-pulse">🎁</span> Referans Ödülünü Seç</p>
                            <select id="reg-ref-reward" class="w-full bg-black/80 border border-purple-700 rounded-lg px-3 py-3 text-white text-sm outline-none focus:border-purple-400 transition cursor-pointer">
                                <option value="xp_500">🌟 500 Başlangıç XP'si</option>
                                <option value="prem_dlx_2">🔥 2 Gün Deluxe Premium</option>
                                <option value="prem_ult_1">👑 1 Gün Ultra+ Premium</option>
                                <option value="prem_std_7">⭐ 1 Hafta Standart Premium</option>
                            </select>
                        </div>
                        
                        <div class="flex items-start gap-2 mb-3 px-1">
                            <input type="checkbox" id="reg-marketing" class="w-4 h-4 mt-0.5 accent-sky-500 rounded cursor-pointer">
                            <label for="reg-marketing" class="text-xs text-zinc-400 font-medium cursor-pointer hover:text-white transition">
                                Haberlerden ve güncellemelerden haberdar olmak istiyorum.
                            </label>
                        </div>
                        
                        <div class="flex items-start gap-2 mb-3 px-1 border-t border-zinc-800 pt-3">
                            <input type="checkbox" id="reg-kvkk" class="w-4 h-4 mt-0.5 accent-sky-500 rounded cursor-pointer">
                            <label for="reg-kvkk" class="text-xs text-zinc-400 font-medium cursor-pointer hover:text-white transition">
                                <a onclick="openKvkkModal()" class="text-sky-400 hover:text-sky-300 underline font-bold transition">Kullanıcı Sözleşmesi ve KVKK</a> metnini okudum, kabul ediyorum.
                            </label>
                        </div>
                        <div class="flex items-start gap-2 mb-6 px-1">
                            <input type="checkbox" id="reg-privacy" class="w-4 h-4 mt-0.5 accent-sky-500 rounded cursor-pointer">
                            <label for="reg-privacy" class="text-xs text-zinc-400 font-medium cursor-pointer hover:text-white transition">
                                <a href="/privacy-policy" target="_blank" class="text-blue-400 hover:text-blue-300 underline font-bold transition">Gizlilik Sözleşmesi</a> ve <a href="/terms" target="_blank" class="text-blue-400 hover:text-blue-300 underline font-bold transition">Kullanım Şartları</a>'nı okudum, kabul ediyorum.
                            </label>
                        </div>
                        
                        <button onclick="handleRegister()" class="w-full bg-gradient-to-r from-sky-700 to-sky-500 btn-premium-hover text-white py-4 rounded-xl font-black shadow-[0_0_20px_rgba(14,165,233,0.6)] text-lg tracking-widest w-full">ARAMIZA KATIL</button>
                    </div>


                    
                </div>
            </div>
        </div>

        <div id="main-app" class="hidden flex flex-col h-[100dvh] w-full slide-up-anim">
            <!-- ── PREMIUM HEADER ── -->
            <div class="px-4 py-2.5 flex items-center justify-between z-[100] shrink-0 gap-2" style="background:linear-gradient(180deg,rgba(2,8,18,0.97) 0%,rgba(8,8,12,0.95) 100%);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid rgba(14,165,233,0.2);box-shadow:0 1px 0 rgba(14,165,233,0.1),0 4px 24px rgba(0,0,0,0.5);">
                <!-- Sol: Hamburger + Logo -->
                <div class="flex items-center gap-2 min-w-0 flex-1">
                    <button onclick="toggleSidebar()" class="w-9 h-9 flex items-center justify-center rounded-xl text-zinc-300 hover:text-white transition-all hover:bg-white/5 active:scale-90 shrink-0" style="font-size:18px">☰</button>
                    <div class="flex items-center gap-1 ml-0.5 min-w-0">
                        <span class="text-lg shrink-0" style="filter:drop-shadow(0 0 6px rgba(14,165,233,0.7))">🏔️</span>
                        <span class="teko-font text-white tracking-widest font-bold truncate" style="font-size:19px;letter-spacing:0.10em;text-shadow:0 0 15px rgba(14,165,233,0.4)">FREERIDER<span style="color:#38bdf8;text-shadow:0 0 10px #38bdf8">TR</span></span>
                    </div>
                </div>
                <!-- Sağ: Kullanıcı Adı + Avatar (shrink-0 ile ezilmez) -->
                <div onclick="switchTab(7)" class="flex items-center gap-2 cursor-pointer group shrink-0" style="transition:all 0.2s">
                    <div class="text-right group-hover:opacity-80 transition-opacity">
                        <div id="top-username" class="font-bold text-sm text-white transition-all leading-tight truncate max-w-[90px]"></div>
                        <div id="top-title" class="text-[9px] font-black uppercase text-zinc-500 tracking-widest leading-tight"></div>
                    </div>
                    <div class="relative shrink-0">
                        <div class="w-9 h-9 rounded-full overflow-hidden shadow-lg transition-all group-hover:scale-105" style="border:2px solid rgba(14,165,233,0.5);box-shadow:0 0 12px rgba(14,165,233,0.3);">
                            <img id="top-avatar" src="" class="w-full h-full object-cover" onerror="this.src='https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg'">
                        </div>
                    </div>
                </div>
            </div>

            <div class="flex-1 relative overflow-hidden bg-zinc-950 z-0">
                <div id="screen-map" class="absolute inset-0 flex flex-col z-10 slide-up-anim">
                    <div class="absolute top-4 left-4 flex flex-col gap-2 z-[999]">
                        <button onclick="showNearbyRoutes()" title="Yakın Rotalar"
                            class="w-10 h-10 bg-glass rounded-full text-xl border border-zinc-700/50 shadow-xl backdrop-blur-md hover:bg-zinc-800 btn-premium-hover flex items-center justify-center">📍</button>
                    </div>

                    <!-- Hava durumu widget haritadan kaldırıldı — sidebar'da görünüyor -->
                    <div id="weather-widget" style="display:none!important;" class="hidden">
                        <div id="weather-icon"></div>
                        <div>
                            <div id="weather-temp"></div>
                            <div id="weather-desc"></div>
                            <div id="weather-advice"></div>
                        </div>
                    </div>
                    
                    <div id="radar-info" class="hidden absolute top-16 left-4 right-4 bg-green-900/90 border border-green-500/70 p-3 rounded-2xl z-[999] flex items-center justify-between backdrop-blur-md shadow-[0_0_20px_rgba(34,197,94,0.3)] slide-up-anim">
                        <div class="flex items-center gap-2">
                            <span class="text-green-400 animate-pulse text-xl drop-shadow-md">📡</span>
                            <div>
                                <div class="text-white text-xs font-bold tracking-wide">Sürüş Modu Aktif</div>
                                <div class="text-green-300 text-[9px] uppercase tracking-widest font-bold">Konumun diğerlerine gözüküyor</div>
                            </div>
                        </div>
                        <button onclick="toggleRidingMode()" class="bg-green-700 hover:bg-green-600 text-white text-[10px] px-3 py-1.5 rounded-lg font-bold btn-premium-hover">BİTİR</button>
                    </div>
                    
                    <div id="map" class="flex-1 w-full h-full"></div>
                    
                    <div class="absolute bottom-6 right-4 flex flex-col gap-2 z-[999] items-end pointer-events-none">
                        <button onclick="autoZoomToUserLocation()" class="bg-glass w-10 h-10 rounded-full text-lg border border-zinc-700/50 shadow-xl flex items-center justify-center pointer-events-auto mb-1 btn-premium-hover">🎯</button>
                        <button onclick="toggleRidingMode()" id="btn-riding-mode" class="bg-green-600/90 backdrop-blur hover:bg-green-500 btn-premium-hover px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(34,197,94,0.4)] flex items-center justify-center text-[10px] uppercase tracking-widest font-bold text-white border border-green-400/50 pointer-events-auto">📡 RADAR (SÜRÜŞTEYİM)</button>
                        <button onclick="toggleAddEventMode()" id="btn-add-event-mode" class="bg-blue-600/90 backdrop-blur hover:bg-blue-500 btn-premium-hover px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(59,130,246,0.4)] flex items-center justify-center text-[10px] uppercase tracking-widest font-bold text-white border border-blue-400/50 pointer-events-auto">📅 BULUŞMA EKLE</button>
                        <button onclick="toggleAddMarkerMode()" id="btn-add-marker-mode" class="bg-sky-600/90 backdrop-blur hover:bg-red-500 btn-premium-hover px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(14,165,233,0.4)] flex items-center justify-center text-[10px] uppercase tracking-widest font-bold text-white border border-red-400/50 pointer-events-auto">📍 RAMPA EKLE</button>
                        <button onclick="quickAddMarkerCurrentLocation()" id="btn-add-marker-current" class="bg-orange-600/90 backdrop-blur hover:bg-orange-500 btn-premium-hover px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(234,88,12,0.4)] flex items-center justify-center text-[10px] uppercase tracking-widest font-bold text-white border border-orange-400/50 pointer-events-auto">🎯 KENDİ KONUMUMU EKLE</button>
                    </div>
                </div>

                <div id="screen-chat" class="hidden absolute inset-0 flex flex-col z-20 bg-darker slide-up-anim">
                    <div class="bg-zinc-900/50 p-2 flex justify-between items-center border-b border-zinc-800 shrink-0 z-10">
                        <div class="flex w-full bg-zinc-950 rounded-lg p-1">
                            <button onclick="switchChatTab('group')" id="chat-tab-group" class="flex-1 py-2 bg-zinc-800 text-white rounded font-bold text-xs transition-all shadow-sm">GRUP SOHBETİ</button>
                            <button onclick="switchChatTab('dm')" id="chat-tab-dm" class="flex-1 py-2 text-zinc-500 rounded font-bold text-xs transition-all hover:text-white">ÖZEL (DM)</button>
                        </div>
                    </div>
                    
                    <!-- Story Bar -->
                    <div id="story-bar" class="flex gap-3 overflow-x-auto px-4 py-3 shrink-0 border-b border-zinc-800/50 bg-black/20" style="scrollbar-width:none;-ms-overflow-style:none;">
                        <!-- Add story button -->
                        <div onclick="openAddStoryModal()" class="flex flex-col items-center gap-1 shrink-0 cursor-pointer">
                            <div class="w-14 h-14 rounded-full bg-zinc-900 border-2 border-dashed border-zinc-600 flex items-center justify-center text-2xl hover:border-sky-400 transition-colors">+</div>
                            <span class="text-[9px] text-zinc-500 font-bold uppercase tracking-widest">Story</span>
                        </div>
                        <div id="story-items" class="flex gap-3 items-center"></div>
                    </div>

                    <div id="chat-group-area" class="flex-1 flex flex-col overflow-hidden relative">
                        <div id="pinned-message-area" class="hidden bg-gradient-to-r from-yellow-600 to-yellow-500 text-black px-4 py-2 font-bold text-xs flex justify-between items-center z-20 shadow-md border-b border-yellow-400">
                            <div class="flex items-center gap-2 truncate">
                                <span class="animate-bounce">📌</span> <span id="pinned-message-text" class="truncate drop-shadow-sm"></span>
                            </div>
                        </div>

                        <div id="chat-messages" class="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar scroll-smooth"></div>
                        
                        <div class="bg-glass p-2 flex flex-wrap items-center gap-1 border-t border-zinc-800 shrink-0 pb-safe">
                            <button onclick="openPhotoUpload('group')" class="bg-zinc-800/80 hover:bg-zinc-700 transition w-10 h-10 md:w-12 md:h-12 rounded-xl text-lg flex items-center justify-center border border-zinc-700 btn-premium-hover">📸</button>
                            <button onclick="toggleVoiceRecord('group')" id="voice-btn" class="bg-zinc-800/80 hover:bg-zinc-700 transition w-10 h-10 md:w-12 md:h-12 rounded-xl text-lg flex items-center justify-center border border-zinc-700 btn-premium-hover">🎤</button>
                            <input id="chat-input" type="text" placeholder="Mesaj veya AI'a soru..." class="flex-1 w-full bg-zinc-950/80 backdrop-blur border border-zinc-700 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-zinc-400 transition min-w-[120px] shadow-inner">
                            <button onclick="askAIGroup()" class="bg-gradient-to-r from-cyan-600 to-blue-600 hover:opacity-80 transition text-white px-3 md:px-4 py-3 rounded-xl font-bold text-[10px] md:text-xs shadow-[0_0_15px_rgba(6,182,212,0.5)] btn-premium-hover">🤖 AI SOR</button>
                            <button onclick="sendChatMessage()" class="bg-white hover:bg-gray-200 transition text-black px-3 md:px-5 py-3 rounded-xl font-bold text-[10px] md:text-xs shadow-md btn-premium-hover">GÖNDER</button>
                        </div>
                    </div>

                    <div id="chat-dm-list-area" class="hidden flex-1 overflow-y-auto p-4 custom-scrollbar slide-up-anim">
                        <div class="text-[10px] text-zinc-500 mb-4 font-bold uppercase tracking-widest border-b border-zinc-800 pb-2">Mesaj Kutun</div>
                        <div id="dm-users-list" class="space-y-2"></div>
                    </div>
                    
                    <div id="chat-dm-thread-area" class="hidden flex-1 flex flex-col overflow-hidden bg-darker absolute inset-0 z-30 slide-up-anim">
                        <div class="glass-panel p-3 flex items-center gap-3 border-b border-zinc-800 shrink-0 z-10">
                            <button onclick="closeDmThread()" class="text-zinc-400 bg-zinc-900 w-8 h-8 rounded-full flex items-center justify-center hover:text-white transition hover:scale-110">←</button>
                            <div class="font-bold text-white flex-1 text-sm tracking-wide drop-shadow-md" id="dm-thread-name"></div>
                        </div>
                        
                        <div id="dm-messages" class="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar scroll-smooth"></div>
                        
                        <div class="glass-panel p-2 flex items-center gap-1 border-t border-zinc-800 shrink-0 pb-safe">
                            <button onclick="openPhotoUpload('dm')" class="bg-zinc-800/80 hover:bg-zinc-700 transition w-12 h-12 rounded-xl text-xl flex items-center justify-center border border-zinc-700 btn-premium-hover">📸</button>
                            <input id="dm-input" type="text" placeholder="Özel mesaj yaz..." class="flex-1 w-full bg-zinc-950 border border-zinc-700 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-zinc-400 transition shadow-inner">
                            <button onclick="sendDmMessage()" class="bg-white hover:bg-gray-200 transition text-black px-5 py-3 rounded-xl font-bold text-sm btn-premium-hover shadow-md">GÖNDER</button>
                        </div>
                    </div>
                </div>

                <div id="screen-market" class="hidden absolute inset-0 bg-darker overflow-y-auto p-4 z-20 custom-scrollbar slide-up-anim">
                    <div class="flex justify-between items-center mb-6 border-b border-zinc-800 pb-3">
                        <h2 class="text-3xl teko-font tracking-wide text-white drop-shadow-md">EKİPMAN PAZARI</h2>
                        <button onclick="openMarketModal()" class="bg-white hover:bg-gray-200 transition text-black text-xs px-4 py-2 rounded-lg font-bold shadow-lg btn-premium-hover">+ İLAN VER</button>
                    </div>
                    <div id="market-list" class="grid grid-cols-2 gap-3 pb-10"></div>
                </div>

                <div id="screen-rank" class="hidden absolute inset-0 bg-darker overflow-y-auto p-4 z-20 custom-scrollbar slide-up-anim">
                    <!-- Kullanıcı Sayacı Bandı -->
                    <div class="flex gap-3 mb-4">
                        <div class="flex-1 bg-zinc-900/80 border border-zinc-800 rounded-xl p-3 flex items-center gap-2">
                            <div class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                            <div>
                                <div id="rank-active-users" class="text-green-400 font-black text-base teko-font leading-none">--</div>
                                <div class="text-[9px] text-zinc-500 uppercase tracking-widest font-bold">Aktif Kullanıcı</div>
                            </div>
                        </div>
                        <div class="flex-1 bg-zinc-900/80 border border-zinc-800 rounded-xl p-3 flex items-center gap-2">
                            <span class="text-base">👥</span>
                            <div>
                                <div id="rank-total-users" class="text-white font-black text-base teko-font leading-none">--</div>
                                <div class="text-[9px] text-zinc-500 uppercase tracking-widest font-bold">Toplam Üye</div>
                            </div>
                        </div>
                    </div>
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-3xl teko-font tracking-wide text-white drop-shadow-md">🏆 LİDER TABLOSU</h2>
                        <button onclick="document.getElementById('rewards-modal').classList.remove('hidden')" class="bg-gradient-to-r from-yellow-600 to-orange-500 hover:opacity-90 transition text-white px-4 py-2 rounded-xl text-[10px] font-black tracking-widest uppercase shadow-md btn-premium-hover flex items-center gap-1">
                            <span class="text-sm">🎁</span> ÖDÜLLER
                        </button>
                    </div>
                    <div class="flex w-full bg-zinc-950 rounded-lg p-1 mb-6 border border-zinc-800 shadow-inner">
                        <button onclick="switchLeaderboard('weekly')" id="rank-tab-weekly" class="flex-1 py-2 bg-zinc-800 text-white rounded font-bold text-xs transition-all shadow-sm">HAFTALIK</button>
                        <button onclick="switchLeaderboard('month')" id="rank-tab-month" class="flex-1 py-2 text-zinc-500 rounded font-bold text-xs transition-all hover:text-white">AYLIK</button>
                        <button onclick="switchLeaderboard('all')" id="rank-tab-all" class="flex-1 py-2 text-zinc-500 rounded font-bold text-xs transition-all hover:text-white">TÜM ZAMANLAR</button>
                    </div>
                    <div id="leaderboard" class="space-y-3 pb-10"></div>
                </div>
                
                <div id="screen-news" class="hidden absolute inset-0 bg-darker overflow-y-auto p-4 z-20 custom-scrollbar slide-up-anim">
                    <h2 class="text-3xl mb-6 text-white teko-font tracking-wide border-b border-zinc-800 pb-3 drop-shadow-md">📰 HABERLER & DUYURULAR</h2>
                    <div id="news-list" class="space-y-4 pb-10"></div>
                </div>

                <div id="screen-missions" class="hidden absolute inset-0 bg-darker flex flex-col z-20 slide-up-anim">

                    <!-- INLINE ŞANS ÇARKI — sabit üst bölge, kaydırmaz -->
                    <div class="glass-panel rounded-3xl p-5 border border-yellow-700/40 shadow-[0_0_30px_rgba(234,179,8,0.15)] shrink-0 mx-4 mt-4">
                        <div class="flex items-center justify-between mb-3">
                            <h2 class="text-2xl text-yellow-400 teko-font tracking-wide drop-shadow-[0_0_8px_rgba(234,179,8,0.5)]">🎡 ŞANS ÇARKI</h2>
                            <p id="spin-inline-info" class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest text-right"></p>
                        </div>
                        <div class="flex flex-col items-center">
                            <div class="relative mb-4" style="perspective:800px;">
                                <canvas id="wheel-canvas-3d" width="260" height="260" style="border-radius:50%;box-shadow:0 0 35px rgba(14,165,233,0.5),0 0 60px rgba(234,179,8,0.2);cursor:pointer;" onclick="spinWheelAction()"></canvas>
                                <!-- Pointer (ibre) -->
                                <div class="absolute top-0 left-1/2 z-20" style="transform:translateX(-50%) translateY(-4px);width:0;height:0;border-left:13px solid transparent;border-right:13px solid transparent;border-top:28px solid #ffffff;filter:drop-shadow(0 3px 8px rgba(0,0,0,1)) drop-shadow(0 0 6px rgba(234,179,8,0.8));"></div>
                                <!-- Center cap -->
                                <div class="absolute inset-0 flex items-center justify-center pointer-events-none">
                                    <div class="w-12 h-12 rounded-full bg-gradient-to-br from-zinc-700 to-zinc-900 border-4 border-zinc-600 shadow-[0_0_15px_rgba(0,0,0,0.8)] z-30 flex items-center justify-center text-xl">🎯</div>
                                </div>
                            </div>
                            <!-- Sesler: base64 data URI yerine güvenilir CDN -->
                            <audio id="spin-tick-sound" preload="auto">
                                <source src="https://cdn.freesound.org/previews/220/220173_4100837-lq.mp3" type="audio/mpeg">
                            </audio>
                            <audio id="spin-win-sound" preload="auto">
                                <source src="https://cdn.freesound.org/previews/270/270404_5123851-lq.mp3" type="audio/mpeg">
                            </audio>
                            <button id="spin-btn" onclick="spinWheelAction()" class="w-full bg-gradient-to-r from-yellow-600 to-sky-500 hover:opacity-90 transition-all text-white py-4 rounded-xl font-black shadow-[0_0_25px_rgba(234,179,8,0.5)] text-lg tracking-widest btn-premium-hover">ÇARKI ÇEVİR</button>
                            <p class="text-[10px] text-zinc-600 font-bold uppercase tracking-widest text-center mt-2">Tüm hesaplamalar sunucuda güvenli yapılır.</p>
                        </div>
                    </div>  <!-- glass-panel çark sonu -->

                    <!-- Kaydırılabilir görev listesi -->
                    <div class="flex-1 overflow-y-auto custom-scrollbar px-4 pt-4 pb-10">
                        <div class="bg-gradient-to-r from-sky-700 to-sky-500 rounded-3xl p-6 mb-6 relative overflow-hidden shadow-[0_0_20px_rgba(14,165,233,0.3)]">
                            <div class="absolute -right-4 -bottom-4 text-8xl opacity-20">🎯</div>
                            <h2 class="text-3xl text-white teko-font tracking-wide mb-1 relative z-10 drop-shadow-md">GÖREVLER VE ÖDÜLLER</h2>
                            <p class="text-xs text-white/90 relative z-10 font-medium">Aktivite yap, görevleri tamamla ve XP kazan!</p>
                        </div>
                        <div id="missions-list" class="space-y-3"></div>
                    </div>
                </div>
                
                <div id="screen-referral" class="hidden absolute inset-0 bg-darker overflow-y-auto p-4 z-20 custom-scrollbar slide-up-anim" style="max-width:100%;box-sizing:border-box;">
                    <div class="bg-gradient-to-r from-purple-800 to-indigo-900 rounded-3xl p-6 mb-6 relative overflow-hidden shadow-[0_0_30px_rgba(88,28,135,0.4)] border border-purple-500/50">
                        <div class="absolute -right-4 -bottom-4 text-8xl opacity-20">🤝</div>
                        <h2 class="text-4xl text-white teko-font tracking-wide mb-1 relative z-10 drop-shadow-md">DAVET ET, KAZAN!</h2>
                        <p class="text-xs text-zinc-200 relative z-10 font-medium leading-relaxed">Arkadaşlarını FreeriderTR'ye davet et, ikiniz de <b class="text-yellow-400 font-bold">XP veya Premium ödül</b> kazanın! <br><br><span class="bg-black/40 px-2 py-1 rounded border border-purple-500/30 text-[10px] uppercase tracking-wider inline-block">Spam Koruması: Kayıt olan kişi @gmail.com kullanmalıdır.</span></p>
                    </div>
                    
                    <div class="glass-panel p-5 rounded-2xl border border-zinc-800 shadow-xl mb-6">
                        <h3 class="text-sm text-purple-400 font-bold uppercase tracking-widest mb-3 flex items-center gap-2"><span class="animate-pulse">📌</span> Senin Referans Kodun</h3>
                        <div class="flex items-center gap-3">
                            <input type="text" id="my-ref-code" readonly class="flex-1 min-w-0 bg-black/60 border border-purple-900/50 rounded-xl px-4 py-3 text-white text-lg font-black tracking-widest text-center shadow-inner overflow-hidden" value="">
                            <button onclick="copyRefCode()" class="bg-white hover:bg-gray-200 text-black px-5 py-3 rounded-xl font-bold transition-all shadow-md btn-premium-hover">KOPYALA</button>
                        </div>
                        <div class="mt-4 bg-zinc-900/50 rounded-lg p-3 border border-zinc-800/50">
                            <p id="ref-monthly-limit" class="text-xs text-zinc-400 text-center uppercase tracking-widest font-bold"></p>
                            <div class="w-full bg-zinc-800 h-1.5 rounded-full mt-2 overflow-hidden">
                                <div id="ref-monthly-bar" class="bg-gradient-to-r from-purple-600 to-indigo-500 h-full transition-all duration-500" style="width: 0%;"></div>
                            </div>
                        </div>
                    </div>

                    <div class="glass-panel p-5 rounded-2xl border border-yellow-900/50 shadow-[0_0_20px_rgba(161,98,7,0.2)]">
                        <h3 class="text-sm text-yellow-500 font-bold uppercase tracking-widest mb-3 flex justify-between items-center">
                            <span>🎁 Alınabilir Ödüllerin</span>
                            <span id="claimable-ref-count" class="bg-gradient-to-r from-yellow-500 to-yellow-600 text-black px-3 py-1 rounded-lg text-xs font-black shadow-md">0</span>
                        </h3>
                        
                        <div id="ref-claim-area" class="mt-4 transition-all duration-300">
                            <select id="ref-reward-select" class="w-full bg-black/80 border border-yellow-900/50 rounded-xl px-4 py-4 mb-4 text-white text-sm outline-none focus:border-yellow-500 transition shadow-inner cursor-pointer font-medium">
                                <option value="xp_500">🌟 500 XP (Anında Hesabına Yüklenir)</option>
                                <option value="prem_dlx_2">🔥 2 Gün Deluxe Premium Üyelik</option>
                                <option value="prem_ult_1">👑 1 Gün Ultra+ Premium Üyelik</option>
                                <option value="prem_std_7">⭐ 1 Hafta Standart Premium Üyelik</option>
                            </select>
                            <button onclick="claimRefReward()" class="w-full bg-gradient-to-r from-yellow-600 to-yellow-500 hover:opacity-90 transition-all text-black py-4 rounded-xl font-black text-sm shadow-[0_0_15px_rgba(234,179,8,0.5)] tracking-widest btn-premium-hover flex items-center justify-center gap-2">
                                <span>ÖDÜLÜ AL</span> <span class="text-lg">🎯</span>
                            </button>
                        </div>
                    </div>
                </div>

                <div id="screen-premium" class="hidden absolute inset-0 bg-darker overflow-y-auto p-4 z-20 custom-scrollbar slide-up-anim">
                    <div class="glass-panel rounded-3xl p-6 border border-zinc-800 text-center mt-4 shadow-2xl">
                        <div class="text-6xl mb-2 drop-shadow-[0_0_20px_rgba(255,255,255,0.4)] animate-bounce">🌟</div>
                        <h2 class="text-5xl text-prem-rainbow teko-font tracking-wide mb-2 drop-shadow-md">FREERIDER PLUS</h2>
                        <p class="text-[11px] text-zinc-300 mb-6 px-2 leading-relaxed font-medium">Sunucu maliyetlerini karşılamak ve sizlere <b class="text-white">tamamen reklamsız bir deneyim</b> sunabilmek için abonelik sistemi yapılmıştır. Anlayışınız ve desteğiniz için teşekkür ederiz. 🙏</p>
                        
                        <!-- İndirim Banner -->
                        <div class="bg-gradient-to-r from-red-900/60 to-orange-900/60 border border-red-500/50 rounded-2xl px-4 py-3 mb-5 flex items-center gap-3 shadow-[0_0_20px_rgba(239,68,68,0.3)]">
                            <span class="text-2xl animate-bounce">🔥</span>
                            <div>
                                <div class="text-red-300 font-black text-sm uppercase tracking-widest">ÖZEL LANSMAN İNDİRİMİ!</div>
                                <div class="text-zinc-300 text-[10px] font-medium">Tüm paketlerde %50 indirim — sınırlı süre!</div>
                            </div>
                            <span class="ml-auto text-red-400 font-black text-xs bg-red-900/60 px-2 py-1 rounded-lg border border-red-700/50">-50%</span>
                        </div>

                        <div class="space-y-4 mb-6">

                            <!-- STANDART PAKETİ -->
                            <div class="text-left bg-zinc-950 p-5 rounded-2xl border border-blue-900/30 transition hover:bg-zinc-900 hover:border-blue-500/50 hover:shadow-[0_0_20px_rgba(59,130,246,0.2)]">
                                <div class="flex justify-between items-center mb-3">
                                    <h3 class="font-bold text-blue-400 text-lg flex items-center gap-2"><span>⭐</span> Standart Paket</h3>
                                    <div class="flex flex-col items-end gap-0.5">
                                        <span class="text-zinc-500 text-[10px] line-through font-bold">50 TL / Ay</span>
                                        <span class="bg-blue-900/40 text-blue-200 px-3 py-1.5 rounded-lg text-xs font-bold border border-blue-500/30">25 TL / Ay</span>
                                    </div>
                                </div>
                                <ul class="text-xs text-zinc-400 space-y-2 mt-3 leading-relaxed">
                                    <li class="flex gap-2"><span>💎</span> <span><b class="text-white">İsim Rengi:</b> Profilinde ve her mesajının yanında 4 farklı özel renk seçeneği. Artık herkes seni tanıyacak!</span></li>
                                    <li class="flex gap-2"><span>🤖</span> <span><b class="text-white">Sınırsız Freerider AI:</b> Ücretsiz üyelikte günde yalnızca 10 soru hakkın var. Standart ile bisiklet soruları, parça tavsiyeleri ve rota önerileri için günde sınırsız AI erişimi.</span></li>
                                    <li class="flex gap-2"><span>🎬</span> <span><b class="text-white">Video Reels Paylaşımı:</b> Reels sekmesinde yalnızca Standart ve üzeri üyeler video yükleyebilir. Sürüş videolarını topluluğa göster!</span></li>
                                    <li class="flex gap-2"><span>📸</span> <span><b class="text-white">Zengin Pazaryeri İlanları:</b> Bisiklet veya parça satarken ilanına <b>2 fotoğraf</b> ekleyebilirsin. Ücretsiz üyeler yalnızca 1 fotoğraf ekleyebilir.</span></li>
                                    <li class="flex gap-2"><span>🚲</span> <span><b class="text-white">Dijital Garaj (1 Bisiklet):</b> Profilinde "Bisikletlerim" bölümünde bisikletini çoklu fotoğrafla sergile. Marka, model, vites, jant, lastik — tüm detayları ekle.</span></li>
                                    <li class="flex gap-2"><span>📍</span> <span><b class="text-white">Haritaya Rampa / Rota Ekleme:</b> Keşfettiğin veya bildiğin parkurları haritaya işaretle. Tüm Türkiye'deki sürücüler görebilir.</span></li>
                                    <li class="flex gap-2"><span>🎡</span> <span><b class="text-white">Günlük Şans Çarkı:</b> Her gün ücretsiz 1 çark hakkın var. Standart üyeler günde <b>2 çark</b> çevirebilir! XP, premium süre, özel ödüller kazanabilirsin.</span></li>
                                    <li class="flex gap-2"><span>🏆</span> <span><b class="text-white">Haftalık / Aylık Liderlik Ödülü:</b> Haftalık XP yarışmasında ilk 3'e girersen otomatik olarak 1 haftalık premium ödül kazanırsın.</span></li>
                                    <li class="flex gap-2"><span>💬</span> <span><b class="text-white">Grup Sohbeti & Özel Mesaj:</b> Topluluğun tüm sohbetlerine, özel DM'lere ve Freerider AI ile bire bir sohbete sınırsız erişim.</span></li>
                                    <li class="flex gap-2"><span>🗓️</span> <span><b class="text-white">Etkinlik Oluşturma:</b> Kendi düzenlediğin buluşmaları, yarışmaları veya sürüş günlerini etkinlik takviminde paylaşabilirsin.</span></li>
                                    <li class="flex gap-2"><span>🛒</span> <span><b class="text-white">Pazaryeri Alım-Satım:</b> Sınırsız ilan açma ve tüm ilanları görme. Türkiye'nin en büyük MTB ikinci el pazarına erişim.</span></li>
                                    <li class="flex gap-2"><span>🌐</span> <span><b class="text-white">Reklamsız Deneyim:</b> Uygulama tamamen reklamsızdır. Hiçbir banner, pop-up veya reklam yok — sadece saf topluluk deneyimi.</span></li>
                                    <li class="flex gap-2"><span>📊</span> <span><b class="text-white">XP & Rozet Sistemi:</b> Mesaj at, rota ekle, etkinliğe katıl, AI kullan — her aktivite XP kazandırır. Unvanını yükselt, rozet topla.</span></li>
                                    <li class="flex gap-2"><span>🔔</span> <span><b class="text-white">Anlık Push Bildirimleri:</b> Biri sana DM attığında, ilanına ilgi gösterildiğinde veya katılmak istediğin etkinlik başlamadan önce bildirim alırsın.</span></li>
                                </ul>
                                <div class="mt-4 bg-blue-950/40 border border-blue-800/50 rounded-xl p-3">
                                    <div class="text-blue-300 text-[10px] font-black uppercase tracking-widest mb-1">💡 Standart için Kimler Uygun?</div>
                                    <div class="text-zinc-400 text-[10px] leading-relaxed">Uygulamayı aktif kullanan, AI'ya soru soran, reels paylaşmak isteyen ve bisikletini dijital garajda sergilemek isteyen her sürücü için mükemmel başlangıç paketi.</div>
                                </div>
                            </div>

                            <!-- DELUXE PAKETİ -->
                            <div class="text-left bg-zinc-950 p-5 rounded-2xl border border-purple-900/50 shadow-[0_0_15px_rgba(168,85,247,0.1)] transition hover:bg-zinc-900 hover:border-purple-500/70 hover:shadow-[0_0_25px_rgba(168,85,247,0.3)]">
                                <div class="flex justify-between items-center mb-3">
                                    <h3 class="font-bold text-purple-400 text-lg flex items-center gap-2"><span>🌟</span> Deluxe Paket</h3>
                                    <div class="flex flex-col items-end gap-0.5">
                                        <span class="text-zinc-500 text-[10px] line-through font-bold">100 TL / Ay</span>
                                        <span class="bg-purple-900/50 text-purple-100 px-3 py-1.5 rounded-lg text-xs font-bold border border-purple-500/50 shadow-md">50 TL / Ay</span>
                                    </div>
                                </div>
                                <div class="text-[9px] text-purple-300 font-bold uppercase tracking-widest mb-3 bg-purple-900/20 rounded-lg px-3 py-1.5 border border-purple-700/30">✨ Standart'taki HER ŞEY dahil + aşağıdaki ekstralar:</div>
                                <ul class="text-xs text-zinc-400 space-y-2.5 mt-1 leading-relaxed">
                                   <li class="flex gap-2"><span>👑</span> <span><b class="text-white">Elite Rozeti:</b> Profilinde ve chatte parlayan Deluxe çerçeve.</span></li>
                                   <li class="flex gap-2"><span>🎨</span> <span><b class="text-white">Simli Renkler:</b> Hareketli ve simli isim renkleri.</span></li>
                                   <li class="flex gap-2"><span>🚀</span> <span><b class="text-white">Pazar Bump:</b> İlanlarını tek tuşla listenin en üstüne taşıma.</span></li>
                                   <li class="flex gap-2"><span>📸</span> <span><b class="text-white">Gelişmiş İlan:</b> Her bir ilanına 4 fotoğraf.</span></li>
                                   <li class="flex gap-2"><span>⚙️</span> <span><b class="text-white">Detaylı Donanım:</b> Bisiklet eklerken Maşa, Şok ve Fren detayları.</span></li>
                                   <li class="flex gap-2"><span>🔥</span> <span><b class="text-white">Özel İkonlar:</b> Rampa eklerken 💀, 🔥, 👑 gibi ikonlar.</span></li>
                                   <li class="flex gap-2"><span>🚲</span> <span><b class="text-white">Geniş Garaj:</b> 2 farklı bisikleti garaja ekleme.</span></li>
                                   <li class="flex gap-2"><span>🎙️</span> <span><b class="text-white">Sesli Mesaj:</b> Grup sohbetinde ses kaydı gönderme.</span></li>
                                </ul>
                            </div>

                            <!-- ULTRA+ PAKETİ -->
                            <div class="text-left bg-zinc-950 p-5 rounded-2xl border border-yellow-500/60 relative overflow-hidden shadow-[0_0_20px_rgba(234,179,8,0.2)] transition hover:bg-zinc-900 hover:shadow-[0_0_30px_rgba(234,179,8,0.4)] hover:border-yellow-400">
                                <div class="absolute -right-7 top-4 bg-yellow-500 text-black font-black text-[9px] py-1.5 px-10 rotate-45 shadow-lg tracking-widest uppercase">V.I.P LOUNGE</div>
                                <div class="flex justify-between items-center mb-3">
                                    <h3 class="font-bold text-yellow-500 text-lg flex items-center gap-2"><span>👑</span> Ultra+ Paket</h3>
                                    <div class="flex flex-col items-end gap-0.5 mr-8">
                                        <span class="text-zinc-500 text-[10px] line-through font-bold">150 TL / Ay</span>
                                        <span class="bg-gradient-to-r from-yellow-400 to-yellow-600 text-black px-3 py-1.5 rounded-lg text-xs font-black shadow-lg">75 TL / Ay</span>
                                    </div>
                                </div>
                                <div class="text-[9px] text-yellow-300 font-bold uppercase tracking-widest mb-3 bg-yellow-900/20 rounded-lg px-3 py-1.5 border border-yellow-700/30">👑 Deluxe'teki HER ŞEY dahil + aşağıdaki ekstralar:</div>
                                <ul class="text-xs text-zinc-400 space-y-2.5 mt-1 leading-relaxed">
                                  <li class="flex gap-2"><span>⚡</span> <span><b class="text-white">Sistem Efsanesi:</b> En üst düzey rütbe ve altın parıltılı kart.</span></li>
                                  <li class="flex gap-2"><span>🔥</span> <span><b class="text-white">Canlı Efektler:</b> Alev veya Buz animasyonları.</span></li>
                                  <li class="flex gap-2"><span>🎨</span> <span><b class="text-white">Renk Özgürlüğü:</b> İstediğin HEX koduyla renk belirleme.</span></li>
                                  <li class="flex gap-2"><span>📌</span> <span><b class="text-white">Mesaj Sabitleme:</b> Gruptaki mesajlarını sabitleme.</span></li>
                                  <li class="flex gap-2"><span>👁️</span> <span><b class="text-white">Görüntülenme Analizi:</b> Profil/ilan tıklanma istatistikleri.</span></li>
                                  <li class="flex gap-2"><span>🌈</span> <span><b class="text-white">Gökkuşağı Radar:</b> Haritada taçlı/gökkuşağı radar.</span></li>
                                  <li class="flex gap-2"><span>✅</span> <span><b class="text-white">Mavi Onay Tiki:</b> Doğrulanmış (Verified) rozeti.</span></li>
                                  <li class="flex gap-2"><span>🚲</span> <span><b class="text-white">Koleksiyoner Garajı:</b> Tam 4 adet bisiklet ekleme hakkı.</span></li>
                                  <li class="flex gap-2"><span>📸</span> <span><b class="text-white">Maksimum Galeri:</b> İlanlara 10 fotoğraf.</span></li>
                                </ul>
                            </div>
                        </div>
                        
                        <!-- SATIN ALMA BÖLÜMÜ: üyelik yoksa göster -->
                        <div id="premium-buy-section">
                            <select id="premium-tier-select" class="w-full bg-black border border-zinc-700 rounded-xl px-5 py-4 mb-4 outline-none text-white text-sm focus:border-zinc-400 transition font-bold shadow-inner cursor-pointer">
                                <option value="freeridertr_standard_pack_monthly">⭐ Standart Paket — 25 TL/Ay (İndirimli)</option>
                                <option value="freeridertr_deluxe_pack_monthly">🌟 Deluxe Paket — 50 TL/Ay (İndirimli)</option>
                                <option value="freeridertr_ultra_pack_monthly">👑 Ultra+ Paket — 75 TL/Ay (İndirimli)</option>
                            </select>
                            <button onclick="requestPremium()" class="w-full bg-gradient-to-r from-green-700 to-emerald-500 hover:opacity-90 transition py-4 rounded-xl font-bold text-white text-lg shadow-[0_0_20px_rgba(34,197,94,0.35)] tracking-wide btn-premium-hover flex items-center justify-center gap-2">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" style="width:22px;height:22px;"><path d="M3.18 23.76c.3.17.64.24.99.2l12.45-12.45L12.6 7.5 3.18 23.76zm17.01-10.7-3.45-1.99-3.62 3.62 3.62 3.62 3.44-1.98c.98-.57.98-2.1.01-2.67zM3.54.32C3.22.13 2.84.08 2.51.25L14.98 12.7l-3.62 3.62 3.45-1.99.01-.01z"/></svg>
                                GOOGLE PLAY'DEN SATIN AL
                            </button>
                            <p class="text-[10px] text-zinc-500 mt-4 text-center font-medium">Google Play Store güvencesiyle. Satın alım mobil uygulama üzerinden gerçekleştirilir ve otomatik aktive edilir.</p>
                        </div>

                        <!-- AKTİF ÜYELİK BÖLÜMÜ: üyelik varsa göster -->
                        <div id="premium-settings-section" class="hidden scale-in-anim">

                            <!-- Mevcut üyelik durum kartı -->
                            <div id="current-plan-card" class="glass-panel p-5 rounded-2xl border border-zinc-700 shadow-xl mt-2 mb-4">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="text-[10px] text-zinc-500 uppercase tracking-widest font-bold">Aktif Paketiniz</span>
                                    <span id="current-plan-badge" class="text-xs font-black px-3 py-1 rounded-lg"></span>
                                </div>
                                <div id="current-plan-name" class="text-xl font-black text-white mb-1"></div>
                                <div id="current-plan-expiry" class="text-[11px] text-zinc-400 font-medium"></div>
                            </div>

                            <!-- Yükselt butonu: Standart veya Deluxe kullanıcısına göster -->
                            <div id="upgrade-plan-section" class="hidden mb-4">
                                <div class="bg-gradient-to-r from-yellow-900/40 to-amber-900/30 border border-yellow-700/50 rounded-2xl p-4 mb-3 flex items-center gap-3">
                                    <span class="text-2xl">⬆️</span>
                                    <div>
                                        <div class="text-yellow-400 font-black text-sm">Üyeliğini Yükselt!</div>
                                        <div id="upgrade-hint-text" class="text-[11px] text-zinc-400 mt-0.5"></div>
                                    </div>
                                </div>
                                <select id="upgrade-tier-select" class="w-full bg-black border border-yellow-700/60 rounded-xl px-5 py-4 mb-3 outline-none text-white text-sm focus:border-yellow-500 transition font-bold shadow-inner cursor-pointer"></select>
                                <button onclick="requestUpgrade()" class="w-full bg-gradient-to-r from-yellow-600 to-amber-500 hover:opacity-90 transition py-4 rounded-xl font-black text-black text-sm shadow-[0_0_20px_rgba(234,179,8,0.4)] tracking-widest btn-premium-hover flex items-center justify-center gap-2">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" style="width:18px;height:18px;"><path d="M3.18 23.76c.3.17.64.24.99.2l12.45-12.45L12.6 7.5 3.18 23.76zm17.01-10.7-3.45-1.99-3.62 3.62 3.62 3.62 3.44-1.98c.98-.57.98-2.1.01-2.67zM3.54.32C3.22.13 2.84.08 2.51.25L14.98 12.7l-3.62 3.62 3.45-1.99.01-.01z"/></svg>
                                    ÜYELİĞİ YÜKSELTt — GOOGLE PLAY
                                </button>
                            </div>

                            <!-- Renk & efekt ayarları -->
                            <div class="glass-panel p-5 rounded-2xl border border-zinc-700 shadow-xl text-left">
                                <h3 class="text-white font-bold mb-3 text-sm flex items-center gap-2"><span class="animate-pulse">🎨</span> Plus Profil Ayarları</h3>
                                <div id="color-options" class="flex flex-wrap gap-2"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ============================================================ -->
                <!-- REELS EKRANI (TikTok/Instagram tarzı) -->
                <!-- ============================================================ -->
                <div id="screen-reels" class="hidden fixed inset-0 bg-black z-[9990] flex flex-col">
                    <!-- Tam ekran feed -->
                    <div id="reels-feed" class="w-full h-full overflow-y-auto snap-y snap-mandatory custom-scrollbar" style="scroll-snap-type:y mandatory;">
                        <div id="reels-loading" class="flex items-center justify-center h-full">
                            <div class="text-center">
                                <div class="w-10 h-10 rounded-full border-4 border-pink-900/40 border-t-pink-500 animate-spin mx-auto mb-3"></div>
                                <p class="text-zinc-400 text-sm font-bold">Reels yükleniyor...</p>
                            </div>
                        </div>
                    </div>
                    <!-- Overlay butonlar — position:absolute (screen-reels zaten inset-0) -->
                    <!-- ✕ Kapat — çentikten 20px daha aşağı (72px) -->
                    <button onclick="closeReels()" style="position:absolute;top:calc(env(safe-area-inset-top, 0px) + 72px);right:16px;z-index:9999;width:44px;height:44px;border-radius:50%;background:rgba(0,0,0,0.65);color:#fff;font-size:18px;font-weight:bold;border:1px solid rgba(255,255,255,0.25);display:flex;align-items:center;justify-content:center;box-shadow:0 2px 12px rgba(0,0,0,0.5);backdrop-filter:blur(4px);cursor:pointer;">✕</button>
                    <!-- 🔊 Ses -->
                    <button id="reel-sound-btn" onclick="toggleReelSound()" style="position:absolute;top:calc(env(safe-area-inset-top, 0px) + 72px);right:68px;z-index:9999;width:44px;height:44px;border-radius:50%;background:rgba(0,0,0,0.65);font-size:22px;border:1px solid rgba(255,255,255,0.25);display:flex;align-items:center;justify-content:center;box-shadow:0 2px 12px rgba(0,0,0,0.5);backdrop-filter:blur(4px);cursor:pointer;">🔊</button>
                    <!-- 📷+ Reels Paylaş — ses butonunun hemen yanında, belirgin kamera ikonu -->
                    <button id="reels-upload-top-btn" onclick="openReelUploadModal()" title="Reels Paylaş"
                        style="position:absolute;top:calc(env(safe-area-inset-top, 0px) + 72px);right:120px;z-index:9999;width:44px;height:44px;border-radius:50%;background:rgba(0,0,0,0.5);border:1.5px solid rgba(236,72,153,0.6);display:flex;align-items:center;justify-content:center;box-shadow:0 0 12px rgba(236,72,153,0.4),0 2px 8px rgba(0,0,0,0.5);backdrop-filter:blur(4px);cursor:pointer;font-size:18px;">
                        📷<span style="position:absolute;top:-3px;right:-3px;width:15px;height:15px;background:#e91e8c;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:900;color:#fff;border:1.5px solid #000;line-height:1;">+</span>
                    </button>
                    <!-- ⊞ Grid/Feed geçiş butonu -->
                    <button id="grid-view-btn" onclick="window.toggleReelsGridView()" style="position:absolute;top:calc(env(safe-area-inset-top, 0px) + 72px);right:172px;z-index:9999;width:44px;height:44px;border-radius:50%;background:rgba(0,0,0,0.65);border:1px solid rgba(255,255,255,0.25);display:flex;align-items:center;justify-content:center;box-shadow:0 2px 12px rgba(0,0,0,0.5);backdrop-filter:blur(4px);cursor:pointer;" title="Izgara Görünümü">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:18px;height:18px;"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                    </button>
                    <!-- Reels FAB: sol alt köşe, navigasyonun hemen üstü -->
                    <button onclick="openReelUploadModal()" id="reels-fab-btn"
                        class="fixed z-[9999] btn-premium-hover"
                        title="Reel Paylaş"
                        style="bottom:calc(70px + env(safe-area-inset-bottom, 0px));left:16px;width:48px;height:48px;border-radius:50%;background:linear-gradient(135deg,#be185d,#0ea5e9);display:flex;align-items:center;justify-content:center;box-shadow:0 0 20px rgba(236,72,153,0.65),0 4px 14px rgba(0,0,0,0.5);border:1.5px solid rgba(255,255,255,0.18);backdrop-filter:blur(6px);">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="width:22px;height:22px;">
                            <path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>
                        </svg>
                    </button>
                    <!-- Boş durum -->
                    <div id="reels-empty" class="hidden fixed inset-0 flex flex-col items-center justify-center gap-4 z-[9991]">
                        <div class="text-6xl">🎬</div>
                        <p class="text-white font-black teko-font text-2xl tracking-widest">İlk Reels'i Sen Paylaş!</p>
                        <p class="text-zinc-400 text-sm text-center px-8">Bisiklet videolarını ve fotoğraflarını toplulukla paylaş!</p>
                        <button onclick="openReelUploadModal()" class="bg-gradient-to-r from-pink-700 to-sky-500 text-white px-6 py-3 rounded-xl font-black text-sm tracking-widest btn-premium-hover">+ REEL PAYLAŞ</button>
                    </div>
                </div>

                <div id="screen-profile" class="hidden absolute inset-0 bg-darker overflow-y-auto z-20 custom-scrollbar slide-up-anim">
                    <div class="p-6 text-center pb-20">
                        <div class="relative inline-block mt-4 group">
                            <div id="profile-avatar-wrap" class="avatar-particle-wrap relative inline-block">
                            <img id="profile-avatar" src="" class="w-32 h-32 mx-auto rounded-full object-cover cursor-pointer bg-zinc-900 transition-all duration-300 group-hover:opacity-80 group-hover:scale-105 shadow-xl" onclick="openProfilePicUpload()">
                            </div>
                            <div class="absolute inset-0 bg-black/50 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-300">
                                <span class="text-2xl text-white drop-shadow-md">📸</span>
                            </div>
                            <input id="pic-upload" type="file" accept="image/*" class="hidden" onchange="uploadProfilePic(this)">
                        </div>

                        <!-- Avatar seçim butonları -->
                        <div class="flex gap-2 justify-center mt-3">
                            <button onclick="openRpmModal()" class="bg-gradient-to-r from-purple-700 to-indigo-700 hover:opacity-90 text-white text-[10px] font-black px-4 py-2 rounded-xl shadow-[0_0_15px_rgba(139,92,246,0.4)] btn-premium-hover flex items-center gap-2 tracking-widest">
                                <span>🎭</span> 3D AVATAR OLUŞTUR
                            </button>
                            <button onclick="openProfilePicUpload()" class="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] font-bold px-4 py-2 rounded-xl border border-zinc-700 btn-premium-hover flex items-center gap-2 tracking-widest">
                                <span>📸</span> FOTOĞRAF
                            </button>
                        </div>
                        <p class="text-[9px] text-zinc-600 mt-1 font-bold uppercase tracking-widest">Ücretsiz · Hesap gerekmez</p>
                        
                        <div id="profile-name-container" class="flex justify-center items-center gap-2 mt-5">
                            <div id="profile-name" class="text-4xl font-bold text-white teko-font tracking-wide drop-shadow-md transition-all"></div>
                            <div id="profile-verified-badge" class="hidden"></div>
                        </div>
                        
                        <div id="profile-bio" class="text-zinc-300 mt-2 text-sm font-medium px-4 leading-relaxed"></div>
                        
                        <div class="flex flex-wrap justify-center gap-3 mt-8 px-2">
                            <div class="glass-panel p-4 rounded-2xl border border-zinc-800/50 flex-1 min-w-[120px] max-w-[160px] shadow-lg hover:border-zinc-600 transition-all duration-300">
                                <div id="profile-xp" class="text-4xl teko-font text-white tracking-wide drop-shadow-sm leading-tight">0</div>
                                <div class="text-[10px] text-zinc-400 font-bold uppercase tracking-widest mt-1">Toplanan XP</div>
                            </div>
                            <div class="glass-panel p-4 rounded-2xl border border-zinc-800/50 flex-1 min-w-[120px] max-w-[160px] shadow-lg hover:border-zinc-600 transition-all duration-300">
                                <div id="profile-title" class="text-base font-bold mt-1 drop-shadow-sm transition-colors leading-snug break-words">Çaylak</div>
                            <div id="profile-xp-progress" class="w-full mt-1"></div>
                                <div class="text-[10px] text-zinc-400 font-bold uppercase tracking-widest mt-1.5">Mevcut Ünvan</div>
                            </div>
                        </div>
                        
                                
                        <div class="mt-4 text-left glass-panel p-4 rounded-2xl border border-zinc-800/50">
                            <div class="flex justify-between items-center mb-4">
                                <h3 class="text-xs font-bold text-zinc-400 uppercase tracking-widest flex items-center gap-2"><span>🚲</span> Garajım</h3>
                                <button onclick="openAddBikeModal()" class="bg-zinc-800 hover:bg-zinc-700 transition text-white text-[10px] px-3 py-1.5 rounded-lg font-bold shadow-md btn-premium-hover">+ Yeni Ekle</button>
                            </div>
                            <div id="garage-list" class="grid grid-cols-2 gap-3"></div>
                        </div>

                        <div class="mt-3 text-left glass-panel p-4 rounded-2xl border border-zinc-800/50">
                            <h3 class="text-xs font-bold text-zinc-400 mb-4 uppercase tracking-widest flex items-center gap-2"><span>🏅</span> Kazanılan Rozetler</h3>
                            <div id="profile-badges" class="flex flex-wrap gap-2"></div>
                        </div>

                        <div class="mt-4 space-y-2">
                            
                            <button onclick="openSettingsModal()" class="w-full bg-zinc-900 hover:bg-zinc-800 transition py-4 rounded-xl font-bold text-white text-sm border border-zinc-700 shadow-md btn-premium-hover">⚙️ PROFİLİ DÜZENLE</button>

                            
                            <button onclick="logout()" class="w-full bg-black hover:bg-red-950/40 transition text-sky-400 py-4 rounded-xl font-bold text-sm border border-sky-900/50 shadow-md btn-premium-hover mt-4">SİSTEMDEN ÇIKIŞ YAP</button>

                                                        <button id="notif-perm-btn" onclick="handleNotifPermission()" class="w-full bg-zinc-900 border border-zinc-700 hover:bg-zinc-800 transition text-zinc-300 py-4 rounded-xl font-bold text-sm mt-4 btn-premium-hover flex items-center justify-center gap-2">
                                <span id="notif-btn-icon">🔔</span>
                                <span id="notif-btn-text">Bildirimleri Aç</span>
                            </button>

                            <div id="streak-freeze-badge" class="hidden mt-3 bg-blue-950/50 border border-blue-700/50 rounded-xl px-4 py-3 flex items-center gap-3">
                                <span class="text-2xl">🛡️</span>
                                <div><div class="text-blue-300 font-black text-sm">Seri Koruma Kalkani</div><div id="streak-freeze-count" class="text-[10px] text-zinc-400 font-bold">0 adet</div></div>
                            </div>
                            <button id="admin-btn" onclick="showAdminPanel()" class="hidden w-full bg-gradient-to-r from-sky-800 to-zinc-900 hover:opacity-90 transition text-white py-4 rounded-xl font-bold text-sm shadow-[0_0_20px_rgba(14,165,233,0.4)] mt-6 btn-premium-hover border border-sky-800/60">👑 YÖNETİCİ PANELİ</button>
                        </div>
                    </div>
                </div>
            </div>

        </div>

        <div id="social-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-zinc-700 relative text-center scale-in-anim">
                <button onclick="document.getElementById('social-modal').classList.add('hidden')" class="absolute top-4 right-4 bg-black/50 backdrop-blur border border-zinc-700 hover:bg-zinc-700 transition w-8 h-8 rounded-full flex items-center justify-center text-zinc-300 hover:text-white z-10 hover:scale-110">✕</button>
                <h3 class="text-3xl text-white mb-6 teko-font tracking-wide">📸 INSTAGRAM HESAPLARIMIZ</h3>
                <div class="space-y-3">
                    <button onclick="window.open('https://instagram.com/om3r_10fr', '_blank')" class="w-full bg-gradient-to-r from-pink-600 to-orange-500 py-4 rounded-xl font-bold text-white shadow-md btn-premium-hover">@om3r_10fr</button>
                    <button onclick="window.open('https://instagram.com/om3r10_fr', '_blank')" class="w-full bg-gradient-to-r from-pink-600 to-orange-500 py-4 rounded-xl font-bold text-white shadow-md btn-premium-hover">@om3r10_fr</button>
                    <button onclick="window.open('https://instagram.com/freeridertr1', '_blank')" class="w-full bg-gradient-to-r from-pink-600 to-orange-500 py-4 rounded-xl font-bold text-white shadow-md btn-premium-hover">@freeridertr1</button>
                </div>
            </div>
        </div>

        <div id="rewards-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-zinc-700 relative text-center scale-in-anim">
                <button onclick="document.getElementById('rewards-modal').classList.add('hidden')" class="absolute top-4 right-4 bg-black/50 backdrop-blur border border-zinc-700 hover:bg-zinc-700 transition w-8 h-8 rounded-full flex items-center justify-center text-zinc-300 hover:text-white z-10 hover:scale-110">✕</button>
                <h3 class="text-4xl text-white mb-2 teko-font tracking-wide text-yellow-500 drop-shadow-md">🎁 SIRALAMA ÖDÜLLERİ</h3>
                <p class="text-xs text-zinc-300 mb-6 font-medium">Sıralamada ilk 3'e giren pedalşörler yöneticiler tarafından ödüllendirilir.</p>
                
                <div class="bg-black/50 border border-zinc-700 rounded-2xl p-4 mb-4 text-left shadow-inner">
                    <h4 class="text-sm font-bold text-blue-400 mb-2 uppercase tracking-widest border-b border-zinc-800 pb-2">📅 Haftalık Yarış</h4>
                    <div class="space-y-2 text-xs text-white">
                        <p class="flex justify-between items-center"><span>🥇 1. Olan:</span> <span class="bg-yellow-500 text-black px-2 py-0.5 rounded font-bold shadow-md">1 Hafta Ultra+</span></p>
                        <p class="flex justify-between items-center"><span>🥈 2. Olan:</span> <span class="bg-purple-600 text-white px-2 py-0.5 rounded font-bold shadow-md">1 Hafta Deluxe</span></p>
                        <p class="flex justify-between items-center"><span>🥉 3. Olan:</span> <span class="bg-purple-600 text-white px-2 py-0.5 rounded font-bold shadow-md">1 Hafta Deluxe</span></p>
                    </div>
                </div>
                
                <div class="bg-black/50 border border-zinc-700 rounded-2xl p-4 text-left shadow-inner">
                    <h4 class="text-sm font-bold text-orange-400 mb-2 uppercase tracking-widest border-b border-zinc-800 pb-2">🏆 Aylık Yarış</h4>
                    <div class="space-y-2 text-xs text-white">
                        <p class="flex justify-between items-center"><span>🥇 1. Olan:</span> <span class="bg-purple-600 text-white px-2 py-0.5 rounded font-bold shadow-md">1 Ay Deluxe</span></p>
                        <p class="flex justify-between items-center"><span>🥈 2. Olan:</span> <span class="bg-purple-600 text-white px-2 py-0.5 rounded font-bold shadow-md">1 Ay Deluxe</span></p>
                        <p class="flex justify-between items-center"><span>🥉 3. Olan:</span> <span class="bg-purple-600 text-white px-2 py-0.5 rounded font-bold shadow-md">1 Ay Deluxe</span></p>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="onboarding-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md transition-opacity">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 shadow-[0_0_40px_rgba(0,0,0,0.8)] relative text-center scale-in-anim overflow-y-auto max-h-[92dvh]">
                <div class="text-6xl mb-3 drop-shadow-[0_0_15px_rgba(255,255,255,0.3)] animate-bounce">👋</div>
                <h2 class="text-4xl text-white mb-2 teko-font tracking-wide drop-shadow-md">FREERIDER<span class="text-sky-500">TR</span>'YE HOŞ GELDİN!</h2>
                <p class="text-xs text-zinc-300 mb-4 font-medium">Türkiye'nin en büyük Hardcore Downhill & Freeride topluluğundasın.</p>

                <div class="bg-gradient-to-r from-yellow-600/20 to-amber-500/20 border border-yellow-500/50 rounded-2xl p-4 mb-4 text-left">
                    <div class="flex items-center gap-2 mb-2">
                        <span class="text-2xl">🎁</span>
                        <span class="text-yellow-400 font-black text-sm uppercase tracking-widest">3 Günlük Ücretsiz Ultra+ Aktif!</span>
                    </div>
                    <p class="text-xs text-zinc-300 leading-relaxed">Sınırsız AI, özel isim rengi, alev efekti, şans çarkı ve tüm premium özellikler <b class="text-yellow-300">3 gün boyunca tamamen ücretsiz</b>. Denemen bitince Plus sayfasından devam edebilirsin.</p>
                    <div id="onboarding-trial-date" class="mt-2 text-[10px] text-yellow-500 font-bold uppercase tracking-widest"></div>
                </div>

                <div class="space-y-2 text-left mb-5">
                    <div class="bg-zinc-950/80 p-3 rounded-xl border border-zinc-800 flex items-start gap-3">
                        <span class="text-xl mt-0.5 shrink-0">🗺️</span>
                        <div><div class="text-white font-bold text-xs teko-font tracking-widest mb-0.5">HARİTA & RADAR</div><p class="text-[10px] text-zinc-400 leading-relaxed">Çevrendeki rampaları keşfet! Radar modunu açarsan seni canlı haritada görürler.</p></div>
                    </div>
                    <div class="bg-zinc-950/80 p-3 rounded-xl border border-zinc-800 flex items-start gap-3">
                        <span class="text-xl mt-0.5 shrink-0">💬</span>
                        <div><div class="text-white font-bold text-xs teko-font tracking-widest mb-0.5">SOHBET & AI</div><p class="text-[10px] text-zinc-400 leading-relaxed">Toplulukla kaynaş, DM at, Freerider AI'a bisiklet soruları sor.</p></div>
                    </div>
                    <div class="bg-zinc-950/80 p-3 rounded-xl border border-zinc-800 flex items-start gap-3">
                        <span class="text-xl mt-0.5 shrink-0">🎯</span>
                        <div><div class="text-white font-bold text-xs teko-font tracking-widest mb-0.5">GÖREVLER & ŞANS ÇARKI</div><p class="text-[10px] text-zinc-400 leading-relaxed">Her gün görev tamamla, çarkı çevir ve XP ile ödüller kazan!</p></div>
                    </div>
                </div>

                <button onclick="completeOnboarding()" class="w-full bg-gradient-to-r from-yellow-600 to-sky-500 btn-premium-hover text-white py-4 rounded-xl font-black shadow-[0_0_20px_rgba(234,179,8,0.5)] text-lg tracking-widest">🚴 DENEMEYİ BAŞLAT!</button>
                <p class="text-[10px] text-zinc-600 mt-2">Kredi kartı gerekmez · Otomatik ücretlendirme yok</p>
            </div>
        </div>

        <div id="email-verify-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[10000] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 shadow-2xl text-center scale-in-anim">
                <h3 class="text-4xl text-white mb-2 teko-font tracking-wide drop-shadow-md">📧 E-POSTA DOĞRULAMA</h3>
                <p class="text-xs text-zinc-300 mb-6 font-medium">E-posta adresinize 6 haneli bir doğrulama kodu gönderdik. Lütfen kodu aşağıya girin.</p>
                <input id="verify-code-input" type="text" placeholder="6 Haneli Kod" class="w-full bg-black/60 border border-zinc-600 rounded-xl px-5 py-4 mb-6 text-white text-center text-2xl tracking-widest outline-none focus:border-white transition shadow-inner font-bold" maxlength="6">
                <div class="grid grid-cols-2 gap-3">
                    <button onclick="skipVerification()" class="py-4 bg-zinc-800 hover:bg-zinc-700 transition rounded-xl font-bold text-white text-sm shadow-md btn-premium-hover">SONRA YAP</button>
                    <button onclick="submitVerificationCode()" class="py-4 bg-sky-700 hover:bg-sky-600 transition rounded-xl font-bold text-white text-sm shadow-[0_0_15px_rgba(14,165,233,0.4)] btn-premium-hover">DOĞRULA</button>
                </div>
            </div>
        </div>

        <div id="forgot-password-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[10000] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 shadow-2xl scale-in-anim">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-4xl text-white teko-font tracking-wide drop-shadow-md">🔐 ŞİFREMİ UNUTTUM</h3>
                    <button onclick="closeForgotPasswordModal()" class="text-zinc-400 hover:text-white w-8 h-8 flex items-center justify-center bg-zinc-800 rounded-full transition hover:scale-110">✕</button>
                </div>
                
                <div id="fp-step-1" class="slide-up-anim">
                    <p class="text-xs text-zinc-300 mb-5 leading-relaxed font-medium">Sisteme kayıtlı ve doğrulanmış e-posta adresinizi girin. Size bir sıfırlama kodu göndereceğiz.</p>
                    <input id="fp-email" type="email" placeholder="E-posta Adresiniz" class="w-full bg-black/60 border border-zinc-600 rounded-xl px-5 py-4 mb-5 text-white text-sm outline-none focus:border-white transition shadow-inner font-bold">
                    <button onclick="requestPasswordReset()" class="w-full bg-white hover:bg-gray-200 transition text-black py-4 rounded-xl font-bold shadow-[0_0_15px_rgba(255,255,255,0.3)] text-sm tracking-wide btn-premium-hover">KOD GÖNDER</button>
                </div>
                
                <div id="fp-step-2" class="hidden slide-up-anim">
                    <p class="text-xs text-zinc-300 mb-4 font-medium">E-postanıza gelen 6 haneli kodu ve yeni şifrenizi girin.</p>
                    <input id="fp-code" type="text" placeholder="6 Haneli Kod" class="w-full bg-black/60 border border-zinc-600 rounded-xl px-5 py-4 mb-3 text-white text-center tracking-widest text-lg outline-none focus:border-white transition font-bold shadow-inner" maxlength="6">
                    <input id="fp-new-password" type="password" placeholder="Yeni Şifreniz" class="w-full bg-black/60 border border-zinc-600 rounded-xl px-5 py-4 mb-6 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                    <button onclick="submitNewPassword()" class="w-full bg-sky-700 hover:bg-sky-600 transition text-white py-4 rounded-xl font-bold shadow-[0_0_15px_rgba(2,132,199,0.5)] text-sm tracking-wide btn-premium-hover">ŞİFREYİ GÜNCELLE</button>
                </div>
            </div>
        </div>

        <div id="add-bike-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl border border-zinc-700 shadow-2xl scale-in-anim max-h-[92vh] flex flex-col">
                <div class="p-5 border-b border-zinc-800 shrink-0 flex items-center justify-between">
                    <h3 class="text-3xl text-white teko-font tracking-wide">🚲 BİSİKLET EKLE</h3>
                    <button onclick="document.getElementById('add-bike-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">✕</button>
                </div>
                <div class="overflow-y-auto p-5 flex-1 custom-scrollbar space-y-3">
                    <!-- Temel bilgiler -->
                    <div class="text-[10px] text-sky-300 font-bold uppercase tracking-widest mb-1">Temel Bilgiler *</div>
                    <input id="bike-model" type="text" placeholder="Marka ve Model (Örn: Trek Session 8)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-sky-400 transition font-bold">
                    <select id="bike-type" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition font-bold cursor-pointer">
                        <option value="Downhill">Downhill</option>
                        <option value="Freeride">Freeride</option>
                        <option value="Enduro">Enduro</option>
                        <option value="Dirt Jump">Dirt Jump</option>
                        <option value="Trail">Trail / XC</option>
                        <option value="Diger">Diğer</option>
                    </select>

                    <!-- Süspansiyon -->
                    <div class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest pt-2 border-t border-zinc-800">Süspansiyon</div>
                    <input id="bike-fork" type="text" placeholder="Maşa (Örn: Fox 40 Performance)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-shock" type="text" placeholder="Arka Şok (Örn: Fox Float X2)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">

                    <!-- Fren sistemi -->
                    <div class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest pt-2 border-t border-zinc-800">Fren Sistemi</div>
                    <input id="bike-brakes" type="text" placeholder="Frenler (Örn: Shimano Saint 4-Piston)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-rotor" type="text" placeholder="Disk Çapı (Örn: 200mm/200mm)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">

                    <!-- Aktarma -->
                    <div class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest pt-2 border-t border-zinc-800">Aktarma Sistemi</div>
                    <input id="bike-drivetrain" type="text" placeholder="Vites Sistemi (Örn: Shimano Deore 12V)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-chain" type="text" placeholder="Zincir (Örn: KMC e12 Turbo)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-crankset" type="text" placeholder="Krank / BB (Örn: Race Face Next R 170mm)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-cassette" type="text" placeholder="Kasnak (Örn: Shimano CS-M7100 10-51T)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">

                    <!-- Tekerlek -->
                    <div class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest pt-2 border-t border-zinc-800">Tekerlek</div>
                    <input id="bike-wheelset" type="text" placeholder="Jantlar (Örn: Stan's Flow MK4 27.5)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-tires" type="text" placeholder="Lastikler (Örn: Maxxis Assegai 27.5x2.5 WT)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-tire-size" type="text" placeholder="Lastik Boyutu / Hava Basıncı" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">

                    <!-- Cockpit -->
                    <div class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest pt-2 border-t border-zinc-800">Kokpit</div>
                    <input id="bike-handlebar" type="text" placeholder="Gidon (Örn: Race Face Atlas 800mm 20mm rise)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-stem" type="text" placeholder="Stem (Örn: Race Face Ride 50mm)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-grips" type="text" placeholder="Gidon Tutuş (Örn: ODI Ruffian Slim)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-seatpost" type="text" placeholder="Seatpost / Tele (Örn: BikeYoke Revive 160mm)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-saddle" type="text" placeholder="Sele (Örn: SDG Bel-Air 3.0)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <input id="bike-pedals" type="text" placeholder="Pedallar (Örn: Crankbrothers Stamp 7)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">

                    <!-- Ekstra -->
                    <div class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest pt-2 border-t border-zinc-800">Ağırlık & Notlar</div>
                    <input id="bike-weight" type="text" placeholder="Bisiklet Ağırlığı (Örn: 15.2 kg)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-zinc-400 transition">
                    <textarea id="bike-desc" placeholder="Özel notlar, modifikasyonlar..." class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 h-20 text-white text-sm outline-none focus:border-zinc-400 transition custom-scrollbar"></textarea>

                    <!-- Gizli premium icon -->
                    <select id="new-marker-icon" class="hidden w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none font-bold"></select>

                    <!-- Fotoğraf -->
                    <div id="bike-photo-label" class="text-[10px] text-zinc-400 font-bold uppercase tracking-widest mt-2">Bisiklet Fotoğrafları</div>
                    <input id="bike-photo" type="file" accept="image/*" multiple class="w-full bg-black/60 border border-zinc-700 rounded-xl px-3 py-3 text-xs text-zinc-300 cursor-pointer">
                    <div class="grid grid-cols-2 gap-3 pb-4">
                        <button onclick="document.getElementById('add-bike-modal').classList.add('hidden')" class="bg-zinc-900 border border-zinc-700 hover:bg-zinc-800 transition text-zinc-300 py-3 rounded-xl font-bold text-sm btn-premium-hover">İptal</button>
                        <button onclick="saveBike()" class="bg-gradient-to-r from-sky-700 to-sky-500 hover:opacity-90 transition text-white py-3 rounded-xl font-bold text-sm shadow-[0_0_15px_rgba(14,165,233,0.4)] btn-premium-hover">KAYDET</button>
                    </div>
                </div>
            </div>
        </div>

        <div id="bike-detail-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[10000] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 shadow-[0_0_40px_rgba(0,0,0,0.6)] relative max-h-[90dvh] overflow-y-auto custom-scrollbar scale-in-anim">
                <button onclick="document.getElementById('bike-detail-modal').classList.add('hidden')" class="absolute top-4 right-4 bg-black/50 backdrop-blur border border-zinc-700 hover:bg-zinc-700 transition w-8 h-8 rounded-full flex items-center justify-center text-zinc-300 hover:text-white z-10 hover:scale-110">✕</button>
                
                <div id="bd-image-container" class="market-img-scroll mb-4 shrink-0 h-48 bg-black/80 rounded-xl items-center custom-scrollbar border border-zinc-700 shadow-inner"></div>
                
                <h3 id="bd-model" class="text-4xl text-white mb-1 teko-font tracking-wide drop-shadow-md"></h3>
                <div id="bd-type" class="text-xs font-bold text-zinc-400 uppercase tracking-widest mb-6 bg-zinc-800/50 inline-block px-3 py-1 rounded-lg border border-zinc-700"></div>
                
                <div class="space-y-3 bg-black/50 p-5 rounded-2xl border border-zinc-700 shadow-inner">
                    <div>
                        <div class="text-[9px] text-zinc-500 font-bold uppercase tracking-widest mb-1">Maşa / Süspansiyon</div>
                        <div id="bd-fork" class="text-sm text-white font-medium drop-shadow-sm">Belirtilmemiş</div>
                    </div>
                    <div class="border-t border-zinc-800 pt-3 mt-1">
                        <div class="text-[9px] text-zinc-500 font-bold uppercase tracking-widest mb-1">Arka Şok</div>
                        <div id="bd-shock" class="text-sm text-white font-medium drop-shadow-sm">Belirtilmemiş</div>
                    </div>
                    <div class="border-t border-zinc-800 pt-3 mt-1">
                        <div class="text-[9px] text-zinc-500 font-bold uppercase tracking-widest mb-1">Fren Sistemi</div>
                        <div id="bd-brakes" class="text-sm text-white font-medium drop-shadow-sm">Belirtilmemiş</div>
                    </div>
                    <div class="border-t border-zinc-800 pt-3 mt-1">
                        <div class="text-[9px] text-zinc-500 font-bold uppercase tracking-widest mb-1">Açıklama / Notlar</div>
                        <div id="bd-desc" class="text-sm text-zinc-300 italic leading-relaxed">Belirtilmemiş</div>
                    </div>
                    <div class="border-t border-zinc-800 pt-3 mt-1">
                        <div class="text-[9px] text-zinc-500 font-bold uppercase tracking-widest mb-2">Tum Parcalar</div>
                        <div id="bd-extra-specs" class="space-y-0"></div>
                    </div>
                </div>
                
                <div id="bd-actions-area" class="mt-5 flex gap-3"></div>
                
            </div>
        </div>

        <!-- Premium Alt Navigasyon Çubuğu -->
        <!-- ── PREMIUM FLOATING BOTTOM NAV ── -->
        <div id="bottom-nav" class="relative shrink-0 z-[200]" style="display:none;" style="background:linear-gradient(180deg,rgba(0,0,0,0) 0%,rgba(0,0,0,0.98) 100%);padding:6px 8px max(14px,env(safe-area-inset-bottom)) 8px;">
            <!-- Gradient separator line -->
            <div style="position:absolute;top:0;left:16px;right:16px;height:1px;background:linear-gradient(90deg,transparent,rgba(14,165,233,0.4),rgba(251,191,36,0.2),rgba(14,165,233,0.4),transparent);"></div>
            <div class="flex justify-around items-center">
                <button onclick="switchTab(0)" id="bnav-0" class="flex flex-col items-center gap-0.5 px-3 py-2 rounded-2xl transition-all duration-300 text-zinc-500" style="min-width:48px">
                    <span class="text-[22px] leading-none" style="transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1),filter 0.3s ease">🗺️</span>
                    <span class="text-[9px] font-black uppercase tracking-widest mt-0.5" style="transition:all 0.2s">Harita</span>
                </button>
                <button onclick="switchTab(1)" id="bnav-1" class="flex flex-col items-center gap-0.5 px-3 py-2 rounded-2xl transition-all duration-300 text-zinc-500 relative" style="min-width:48px">
                    <span class="text-[22px] leading-none" style="transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1),filter 0.3s ease">💬</span>
                    <span class="text-[9px] font-black uppercase tracking-widest mt-0.5" style="transition:all 0.2s">Chat</span>
                </button>
                <!-- Reels - Merkez Özel Buton -->
                <button onclick="switchTab(9)" id="bnav-9" class="flex flex-col items-center gap-0.5 px-3 py-2 rounded-2xl transition-all duration-300 text-zinc-500 relative" style="min-width:52px">
                    <div class="relative">
                        <span class="text-[24px] leading-none block" style="transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1),filter 0.3s ease">🎬</span>
                    </div>
                    <span class="text-[9px] font-black uppercase tracking-widest mt-0.5" style="transition:all 0.2s">Reels</span>
                </button>
                <button onclick="switchTab(3)" id="bnav-3" class="flex flex-col items-center gap-0.5 px-3 py-2 rounded-2xl transition-all duration-300 text-zinc-500" style="min-width:48px">
                    <span class="text-[22px] leading-none" style="transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1),filter 0.3s ease">🏆</span>
                    <span class="text-[9px] font-black uppercase tracking-widest mt-0.5" style="transition:all 0.2s">Sıra</span>
                </button>
                <button onclick="switchTab(7)" id="bnav-7" class="flex flex-col items-center gap-0.5 px-3 py-2 rounded-2xl transition-all duration-300 text-zinc-500" style="min-width:48px">
                    <span class="text-[22px] leading-none" style="transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1),filter 0.3s ease">👤</span>
                    <span class="text-[9px] font-black uppercase tracking-widest mt-0.5" style="transition:all 0.2s">Profil</span>
                </button>
            </div>
        </div>

        <div id="settings-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 shadow-2xl max-h-[90vh] overflow-y-auto custom-scrollbar relative scale-in-anim">
                <h3 class="text-4xl text-white mb-5 teko-font tracking-wide drop-shadow-md">⚙️ PROFİLİ DÜZENLE</h3>
                <input id="edit-name" type="text" placeholder="İsim" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                <input id="edit-bio" type="text" placeholder="Kısa Bio..." class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                <input id="edit-password" type="password" placeholder="Yeni şifre (Değişmeyecekse boş bırak)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                
                <div class="mt-5 border-t border-zinc-700 pt-5 mb-5">
                    <h4 class="text-[10px] text-zinc-400 uppercase tracking-widest font-bold mb-3">E-Posta & Güvenlik</h4>
                    <div id="profile-email-status" class="mb-3"></div>
                   <input id="edit-email" type="email" placeholder="E-posta Adresi" oninput="checkEmailChange()" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                    <div class="flex items-start gap-2 mb-4 px-1">
                        <input type="checkbox" id="edit-marketing" class="w-4 h-4 mt-0.5 accent-sky-500 rounded cursor-pointer">
                        <label for="edit-marketing" class="text-[10px] text-zinc-400 font-medium cursor-pointer hover:text-white transition">Haberlerden ve güncellemelerden haberdar olmak istiyorum.</label>
                    </div>
                    <button onclick="requestProfileEmailVerify()" id="btn-verify-email" class="w-full bg-zinc-800 hover:bg-zinc-700 transition py-4 rounded-xl font-bold text-white text-xs border border-zinc-600 hidden uppercase tracking-widest shadow-md btn-premium-hover">DOĞRULAMA KODU GÖNDER</button>
                </div>

                <div class="grid grid-cols-2 gap-3 mt-2">
                    <button onclick="closeSettingsModal()" class="py-4 bg-zinc-800 hover:bg-zinc-700 transition rounded-xl font-bold text-white text-sm shadow-md btn-premium-hover">İPTAL</button>
                    <button onclick="saveSettings()" class="py-4 bg-white hover:bg-gray-200 transition rounded-xl font-bold text-black text-sm shadow-[0_0_15px_rgba(255,255,255,0.3)] btn-premium-hover">KAYDET</button>
                </div>

                <div class="mt-6 pt-5 border-t border-zinc-800">
                    <p class="text-[10px] text-zinc-500 mb-3 uppercase tracking-widest font-bold">Tehlikeli Bölge</p>
                    <button onclick="openDeleteAccountModal()" class="w-full bg-black border border-sky-900/60 hover:bg-red-950/40 transition text-sky-400 py-3 rounded-xl font-bold text-xs uppercase tracking-widest btn-premium-hover">🗑️ Hesabımı Kalıcı Olarak Sil</button>
                </div>
            </div>
        </div>

        <!-- HESAP SİLME ONAY MODALI -->
        <div id="delete-account-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[99999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-sky-900/50 shadow-2xl scale-in-anim">
                <div class="text-center mb-5">
                    <div class="text-5xl mb-3">⚠️</div>
                    <h3 class="text-2xl text-sky-300 teko-font tracking-wide">HESABI SİL</h3>
                    <p class="text-xs text-zinc-400 mt-2 leading-relaxed">Bu işlem <b class="text-sky-300">geri alınamaz.</b> Profilin, gönderilerin, ilanların ve tüm verilen kalıcı olarak silinir.</p>
                </div>
                <input id="delete-account-password" type="password" placeholder="Onaylamak için şifreni gir" class="w-full bg-black/60 border border-sky-800/60 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-sky-400 transition font-bold mb-4">
                <div class="grid grid-cols-2 gap-3">
                    <button onclick="document.getElementById('delete-account-modal').classList.add('hidden')" class="bg-zinc-900 border border-zinc-700 text-zinc-400 py-3 rounded-xl font-bold text-sm">Vazgeç</button>
                    <button onclick="confirmDeleteAccount()" class="bg-sky-800 hover:bg-sky-700 text-white py-3 rounded-xl font-bold text-sm btn-premium-hover uppercase tracking-widest">HESABI SİL</button>
                </div>
            </div>
        </div>

        <div id="other-profile-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-zinc-700 relative text-center overflow-y-auto max-h-[90dvh] custom-scrollbar shadow-[0_0_40px_rgba(0,0,0,0.6)] scale-in-anim">
                <button onclick="document.getElementById('other-profile-modal').classList.add('hidden')" class="absolute top-4 right-4 bg-black/50 backdrop-blur border border-zinc-700 hover:bg-zinc-700 transition text-zinc-300 hover:text-white w-8 h-8 rounded-full flex items-center justify-center hover:scale-110 z-10">✕</button>
                
                <img id="op-avatar" src="" class="w-28 h-28 mx-auto rounded-full object-cover mt-6 bg-zinc-950 shadow-xl border-4 transition-all duration-300">
                <div id="op-premium-badge" class="hidden mt-3 text-xs font-bold uppercase tracking-widest"></div>
                            <div id="op-online-status" class="hidden flex items-center gap-2 justify-center mt-2"></div>
                
                <div id="op-username-container" class="flex justify-center items-center gap-1 mt-3">
                    <div id="op-username" class="text-4xl font-bold text-white break-all teko-font tracking-wide drop-shadow-md transition-all"></div>
                    <div id="op-verified-badge" class="hidden"></div>
                </div>
                
                <div id="op-bio" class="text-zinc-300 mt-2 text-sm font-medium px-2 leading-relaxed"></div>
                
                <div class="flex justify-center gap-4 mt-8">
                    <div class="bg-black/50 p-4 rounded-2xl w-28 border border-zinc-700 shadow-inner">
                        <div id="op-xp" class="text-3xl text-white teko-font tracking-wide drop-shadow-sm"></div>
                        <div class="text-[9px] text-zinc-500 mt-1 font-bold uppercase tracking-widest">XP</div>
                    </div>
                    <div class="bg-black/50 p-4 rounded-2xl w-28 border border-zinc-700 shadow-inner">
                        <div id="op-title" class="text-sm font-bold text-zinc-300 truncate uppercase mt-1 drop-shadow-sm"></div>
                        <div class="text-[9px] text-zinc-500 mt-2 font-bold uppercase tracking-widest">ÜNVAN</div>
                    </div>
                </div>
                                
                <div class="mt-8 text-left pb-4 bg-black/40 p-5 rounded-2xl border border-zinc-700/50 shadow-inner">
                    <h3 class="text-[10px] font-bold text-zinc-400 mb-4 uppercase tracking-widest flex items-center gap-2"><span>🚲</span> Garajı</h3>
                    <div id="op-garage" class="grid grid-cols-2 gap-3"></div>
                </div>
                
                <div class="mt-6 text-left pb-4 bg-black/40 p-5 rounded-2xl border border-zinc-700/50 shadow-inner">
                    <h3 class="text-[10px] font-bold text-zinc-400 mb-4 uppercase tracking-widest flex items-center gap-2"><span>🏅</span> Kazanılan Rozetler</h3>
                    <div id="op-badges" class="flex flex-wrap gap-2"></div>
                </div>
                
                <div id="op-actions" class="border-t border-zinc-700/50 pt-6 mt-6 space-y-3"></div>
            </div>
        </div>

        <div id="chat-rules-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 py-10 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 flex flex-col shadow-2xl scale-in-anim">
                <h2 class="text-4xl text-white mb-4 teko-font tracking-wide drop-shadow-md">📜 TOPLULUK KURALLARI</h2>
                <div class="overflow-y-auto flex-1 text-sm text-zinc-300 space-y-4 mb-5 custom-scrollbar pr-2 bg-black/50 p-5 rounded-2xl border border-zinc-700 shadow-inner leading-relaxed font-medium">
                    <ul class="list-disc pl-5 space-y-3">
                        <li><b>+18 ve Cinsel İçerik Kesinlikle Yasaktır:</b> Gruba gönderilen her türlü cinsel içerik kalıcı olarak engellenir.</li>
                        <li><b>Taciz ve Zorbalık Yasaktır:</b> Diğer üyeleri özelden veya gruptan rahatsız etmek affedilmez.</li>
                        <li><b>Ayrımcılık ve Nefret Söylemi:</b> Din, dil, ırk, mezhep ayrımcılığı yapmak yasaktır. Bizi birleştiren şey bisiklet tutkusudur.</li>
                        <li><b>Spam ve Reklam Yasaktır:</b> İzin alınmadan yapılan ticari reklamlar yasaktır. Pazar sekmesini kullanın.</li>
                    </ul>
                    <p class="text-xs text-sky-300 font-bold mt-5 border-t border-zinc-800 pt-4">ÖNEMLİ: Kuralları ihlal eden üyeler uyarısız olarak sistemden KALICI olarak uzaklaştırılır.</p>
                </div>
                <div class="flex flex-col gap-3 shrink-0">
                    <button onclick="acceptChatRules()" class="w-full bg-white hover:bg-gray-200 transition text-black py-4 rounded-xl font-bold text-sm shadow-[0_0_15px_rgba(255,255,255,0.3)] btn-premium-hover">OKUDUM, KABUL EDİYORUM</button>
                    <button onclick="switchTab(0)" class="w-full bg-zinc-800 hover:bg-zinc-700 transition py-4 rounded-xl font-bold text-zinc-300 text-sm shadow-md btn-premium-hover">Vazgeç ve Geri Dön</button>
                </div>
            </div>
        </div>

        <div id="market-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 overflow-y-auto py-10 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 my-auto shadow-[0_0_40px_rgba(0,0,0,0.6)] scale-in-anim">
                <h2 class="text-4xl text-white mb-6 teko-font tracking-wide drop-shadow-md">🛒 YENİ İLAN</h2>
                <input id="mk-title" type="text" placeholder="Ürün Adı" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                <input id="mk-price" type="number" placeholder="Fiyat (TL)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                <input id="mk-contact" type="text" placeholder="İletişim Bilgisi (Tel/Insta)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                <textarea id="mk-desc" placeholder="Açıklama..." class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 h-24 mb-5 text-white text-sm outline-none focus:border-white transition custom-scrollbar font-bold shadow-inner"></textarea>
                
                <label id="mk-photo-label" class="block text-[10px] text-zinc-400 mb-2 uppercase font-bold tracking-widest">Fotoğraf Ekle</label>
                <input id="mk-photos" type="file" accept="image/*" multiple class="w-full bg-black/60 border border-zinc-700 rounded-xl px-3 py-3 mb-5 text-xs text-zinc-300 focus:border-white transition cursor-pointer">
                
                <div class="grid grid-cols-2 gap-3 mt-2">
                    <button onclick="document.getElementById('market-modal').classList.add('hidden')" class="py-4 bg-zinc-800 hover:bg-zinc-700 transition rounded-xl font-bold text-white text-sm shadow-md btn-premium-hover">İPTAL</button>
                    <button onclick="saveMarketItem()" class="py-4 bg-white hover:bg-gray-200 transition rounded-xl font-bold text-black text-sm shadow-[0_0_15px_rgba(255,255,255,0.3)] btn-premium-hover">İLANI YAYINLA</button>
                </div>
            </div>
        </div>
        
        <div id="market-detail-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 relative flex flex-col max-h-[90dvh] shadow-[0_0_40px_rgba(0,0,0,0.6)] scale-in-anim">
                <button onclick="document.getElementById('market-detail-modal').classList.add('hidden')" class="absolute top-4 right-4 bg-black/50 backdrop-blur border border-zinc-700 hover:bg-zinc-700 transition w-8 h-8 rounded-full flex items-center justify-center text-zinc-300 hover:text-white z-10 hover:scale-110">✕</button>
                
                <div id="md-photos" class="market-img-scroll mb-5 shrink-0 h-48 bg-black/80 rounded-xl items-center custom-scrollbar border border-zinc-700 shadow-inner"></div>
                
                <div class="overflow-y-auto flex-1 pr-2 custom-scrollbar">
                    <h3 id="md-title" class="text-4xl text-white mb-2 teko-font tracking-wide drop-shadow-md"></h3>
                    <div id="md-price" class="text-2xl font-black text-green-400 mb-3 bg-green-950/40 inline-block px-4 py-1.5 rounded-xl border border-green-800/50 shadow-md"></div>
                    <div id="md-views-badge" class="hidden text-xs font-bold text-yellow-400 mb-6 bg-yellow-900/30 inline-block px-3 py-1.5 rounded-xl border border-yellow-700/50 ml-2 shadow-md"></div>
                    
                    <div class="flex items-center gap-4 mb-6 bg-black/50 p-4 rounded-2xl cursor-pointer hover:bg-zinc-800 transition-colors border border-zinc-700 shadow-inner group" onclick="if(window.currentOwner) showOtherProfile(window.currentOwner)">
                        <img id="md-owner-avatar" class="w-14 h-14 rounded-full object-cover border-2 border-zinc-600 group-hover:border-zinc-400 transition-colors shadow-md">
                        <div>
                            <div class="text-[10px] text-zinc-400 uppercase font-bold tracking-widest mb-1">Satıcı</div>
                            <div id="md-owner" class="text-base font-bold text-white tracking-wide group-hover:text-blue-300 transition-colors"></div>
                        </div>
                    </div>
                    
                    <p id="md-desc" class="text-sm text-zinc-300 mb-6 whitespace-pre-wrap break-all leading-relaxed font-medium bg-black/30 p-4 rounded-xl border border-zinc-800/50"></p>
                    
                    <div class="bg-blue-950/30 border border-blue-800/50 p-5 rounded-2xl mb-4 text-center shadow-inner">
                        <div class="text-[10px] text-blue-300 mb-2 uppercase font-bold tracking-widest flex justify-center items-center gap-2"><span class="animate-pulse">📞</span> İletişim Bilgisi</div>
                        <div id="md-contact" class="font-black text-white text-xl break-all drop-shadow-sm"></div>
                    </div>
                </div>
                
                <div id="md-actions-area" class="mt-5 shrink-0 space-y-3"></div>
            </div>
        </div>

        <div id="add-marker-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 shadow-[0_0_40px_rgba(0,0,0,0.6)] scale-in-anim">
                <h2 id="modal-marker-title" class="text-4xl text-white mb-5 teko-font tracking-wide drop-shadow-md">📍 RAMPA EKLE</h2>
                <button onclick="useCurrentLocationForMarker()" class="w-full bg-blue-600/20 text-blue-300 border border-blue-500/50 py-3.5 rounded-xl mb-5 text-[10px] uppercase font-bold flex items-center justify-center gap-2 hover:bg-blue-600/40 transition shadow-md btn-premium-hover"><span class="text-lg">🎯</span> BULUNDUĞUM KONUMU İŞARETLE</button>
                <input id="new-marker-name" type="text" placeholder="Rampa veya Konum Adı" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                
                <div class="flex gap-3 mb-3">
                    <select id="new-marker-difficulty" class="flex-1 bg-black/60 border border-zinc-700 rounded-xl px-4 py-4 text-white font-bold text-xs outline-none focus:border-white transition shadow-inner cursor-pointer">
                        <option value="Kolay">🟢 Kolay Seviye</option>
                        <option value="Orta" selected>🟡 Orta Seviye</option>
                        <option value="Zor">🔴 Zor Seviye</option>
                        <option value="Tehlike">💀 Çok Tehlikeli</option>
                    </select>
                    <select id="new-marker-icon" class="hidden w-24 bg-black/60 border border-zinc-700 rounded-xl px-2 py-4 text-white text-lg text-center outline-none focus:border-white transition shadow-inner cursor-pointer">
                        <option value="🚴">🚴</option>
                        <option value="💀">💀</option>
                        <option value="🔥">🔥</option>
                        <option value="👑">👑</option>
                    </select>
                </div>
                
                <textarea id="new-marker-desc" placeholder="Açıklama / Nasıl Gidilir? / İpuçları..." class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 h-24 mb-5 text-white text-sm outline-none focus:border-white transition custom-scrollbar font-bold shadow-inner"></textarea>
                
                <label class="block text-[10px] text-zinc-400 mb-2 uppercase font-bold tracking-widest">Rampa Fotoğrafı (İsteğe Bağlı)</label>
                <input id="new-marker-photo" type="file" accept="image/*" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-3 py-3 mb-6 text-xs text-zinc-300 focus:border-white transition cursor-pointer">
                
                <div class="grid grid-cols-2 gap-3">
                    <button onclick="document.getElementById('add-marker-modal').classList.add('hidden')" class="py-4 bg-zinc-800 hover:bg-zinc-700 transition rounded-xl font-bold text-white text-sm shadow-md btn-premium-hover">İPTAL</button>
                    <button onclick="saveNewMarker()" class="py-4 bg-white hover:bg-gray-200 transition rounded-xl font-bold text-black text-sm shadow-[0_0_15px_rgba(255,255,255,0.3)] btn-premium-hover">KAYDET</button>
                </div>
            </div>
        </div>

        <div id="add-event-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 shadow-[0_0_40px_rgba(0,0,0,0.6)] scale-in-anim">
                <h2 class="text-4xl text-white mb-5 teko-font tracking-wide drop-shadow-md">📅 BULUŞMA EKLE</h2>
                <input id="ev-title" type="text" placeholder="Başlık (Örn: Sabah Antrenmanı)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                
                <div class="flex gap-3 mb-3">
                    <input id="ev-date" type="date" class="flex-1 bg-black/60 border border-zinc-700 rounded-xl px-4 py-4 outline-none text-sm text-white font-bold focus:border-white transition shadow-inner">
                    <input id="ev-time" type="time" class="w-28 bg-black/60 border border-zinc-700 rounded-xl px-3 py-4 outline-none text-sm text-white font-bold focus:border-white transition shadow-inner">
                </div>
                
                <input id="ev-max" type="number" placeholder="Kişi Sınırı (Opsiyonel)" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 mb-3 text-white text-sm outline-none focus:border-white transition font-bold shadow-inner">
                <textarea id="ev-desc" placeholder="Açıklama..." class="w-full bg-black/60 border border-zinc-700 rounded-xl px-5 py-4 h-24 mb-6 text-white text-sm outline-none focus:border-white transition custom-scrollbar font-bold shadow-inner"></textarea>
                
                <div class="grid grid-cols-2 gap-3">
                    <button onclick="document.getElementById('add-event-modal').classList.add('hidden')" class="py-4 bg-zinc-800 hover:bg-zinc-700 transition rounded-xl font-bold text-white text-sm shadow-md btn-premium-hover">İPTAL</button>
                    <button onclick="saveEvent()" class="py-4 bg-white hover:bg-gray-200 transition rounded-xl font-bold text-black text-sm shadow-[0_0_15px_rgba(255,255,255,0.3)] btn-premium-hover">OLUŞTUR</button>
                </div>
            </div>
        </div>
        
        <div id="marker-sheet" class="hidden fixed glass-panel border-t border-zinc-700 rounded-t-3xl shadow-[0_-20px_50px_rgba(0,0,0,0.8)] p-5 z-[9999] max-h-[88vh] flex flex-col slide-up-anim overflow-hidden" style="bottom:0;left:0;right:0;width:100%;max-width:100%;margin-left:auto;margin-right:auto;box-sizing:border-box;transform:none;">
            <div id="ms-danger-banner" class="hidden bg-red-950/70 border border-sky-700/50 text-red-300 text-xs font-bold px-4 py-2 rounded-xl mb-3 flex items-center gap-2 shrink-0"></div>
            <div class="flex justify-between items-start mb-5 border-b border-zinc-700 pb-4 shrink-0">
                <div class="flex-1 pr-4">
                    <h3 id="ms-title" class="text-4xl text-white teko-font tracking-wide break-words drop-shadow-md"></h3>
                    <span id="ms-difficulty" class="text-[10px] bg-zinc-800 text-zinc-300 px-3 py-1.5 rounded-lg inline-block uppercase mt-2 tracking-widest font-bold shadow-inner"></span>
                </div>
                <button onclick="closeMarkerSheet()" class="bg-black/50 hover:bg-zinc-700 transition w-10 h-10 rounded-full flex items-center justify-center text-zinc-300 hover:text-white shrink-0 border border-zinc-700 hover:scale-110 shadow-md">✕</button>
            </div>
            
            <div class="overflow-y-auto custom-scrollbar flex-1 pb-4">
                <div id="ms-image-container" class="mb-5"></div>
                <p id="ms-desc" class="text-sm text-zinc-300 bg-black/40 p-5 rounded-2xl border border-zinc-700 mb-5 whitespace-pre-wrap break-words font-medium leading-relaxed shadow-inner"></p>
                
                <div class="flex justify-between gap-3 mb-5">
                    <button id="ms-btn-like" onclick="toggleMarkerInteraction('like')" class="flex-1 bg-black/50 border border-zinc-700 hover:bg-zinc-800 transition py-4 rounded-xl flex items-center justify-center gap-2 font-bold text-base text-white shadow-md btn-premium-hover">
                        <span class="text-xl">👍</span> <span id="ms-likes-count">0</span>
                    </button>
                    <button id="ms-btn-dislike" onclick="toggleMarkerInteraction('dislike')" class="flex-1 bg-black/50 border border-zinc-700 hover:bg-zinc-800 transition py-4 rounded-xl flex items-center justify-center gap-2 font-bold text-base text-white shadow-md btn-premium-hover">
                        <span class="text-xl">👎</span> <span id="ms-dislikes-count">0</span>
                    </button>
                </div>

                <a id="ms-btn-directions" href="#" target="_blank" class="w-full flex items-center justify-center gap-2 bg-blue-600/20 hover:bg-blue-600/40 border border-blue-500/50 transition text-blue-300 py-4 rounded-xl font-bold text-sm shadow-lg mb-3 uppercase tracking-widest btn-premium-hover"><span class="text-lg">🗺️</span> YOL TARİFİ AL</a>
                
                <!-- Puan verme -->
                <div id="ms-rating" class="mt-3 mb-2">
                    <div class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest mb-2">Rampayı Puan Ver</div>
                    <div class="flex items-center gap-2">
                        <div id="ms-stars" class="flex gap-1">
                            <span onclick="rateMarker(1)" class="text-2xl cursor-pointer hover:scale-125 transition-transform">⭐</span>
                            <span onclick="rateMarker(2)" class="text-2xl cursor-pointer hover:scale-125 transition-transform">⭐</span>
                            <span onclick="rateMarker(3)" class="text-2xl cursor-pointer hover:scale-125 transition-transform">⭐</span>
                            <span onclick="rateMarker(4)" class="text-2xl cursor-pointer hover:scale-125 transition-transform">⭐</span>
                            <span onclick="rateMarker(5)" class="text-2xl cursor-pointer hover:scale-125 transition-transform">⭐</span>
                        </div>
                        <span id="ms-avg-rating" class="text-xs text-zinc-400 font-bold"></span>
                    </div>
                </div>
                <button onclick="openDangerReport()" class="w-full bg-red-950/40 border border-sky-800/50 hover:bg-sky-900/30 transition text-sky-300 py-2.5 rounded-xl font-bold text-xs mb-2 btn-premium-hover flex items-center justify-center gap-2">
                    <span>⚠️</span> Tehlike Bildir
                </button>
                <button onclick="openComments('marker', currentMarkerId)" class="w-full bg-zinc-900/80 border border-zinc-700 hover:bg-zinc-800 transition text-zinc-300 py-3 rounded-xl font-bold text-sm mb-3 btn-premium-hover flex items-center justify-center gap-2 mt-1">
                    <span>💬</span> Yorumlar
                </button>
                <div id="ms-admin-controls" class="hidden flex gap-3 mt-5 pt-5 border-t border-zinc-700">
                    <button id="ms-btn-edit" class="flex-1 bg-blue-950/50 hover:bg-blue-900/80 transition text-blue-400 py-3.5 rounded-xl text-xs font-bold border border-blue-800/50 shadow-md btn-premium-hover">DÜZENLE</button>
                    <button id="ms-btn-delete" class="flex-1 bg-red-950/50 hover:bg-sky-900/80 transition text-sky-400 py-3.5 rounded-xl text-xs font-bold border border-sky-800/50 shadow-md btn-premium-hover">SİL</button>
                </div>
            </div>
        </div>

        <div id="event-sheet" class="hidden fixed bottom-0 inset-x-0 glass-panel border-t border-zinc-700 rounded-t-3xl shadow-[0_-20px_50px_rgba(0,0,0,0.8)] p-5 z-[9999] overflow-y-auto max-h-[88vh] slide-up-anim">
            <div class="flex justify-between items-start mb-5 border-b border-zinc-700 pb-4">
                <div>
                    <h3 id="es-title" class="text-4xl text-white teko-font tracking-wide drop-shadow-md"></h3>
                    <p id="es-time" class="text-[11px] text-blue-400 font-bold mt-2 uppercase tracking-widest bg-blue-950/30 inline-block px-2 py-1 rounded border border-blue-900/50"></p>
                </div>
                <button onclick="document.getElementById('event-sheet').classList.add('hidden')" class="bg-black/50 hover:bg-zinc-700 transition w-10 h-10 rounded-full flex items-center justify-center text-zinc-300 hover:text-white border border-zinc-700 shadow-md hover:scale-110">✕</button>
            </div>
            
            <p id="es-desc" class="text-sm text-zinc-300 mb-6 bg-black/40 p-5 rounded-2xl border border-zinc-700 font-medium leading-relaxed shadow-inner"></p>
            
            <div class="mb-6 bg-zinc-900/30 p-4 rounded-2xl border border-zinc-800/50">
                <h4 class="text-[10px] font-bold text-zinc-400 mb-3 uppercase tracking-widest flex items-center gap-2"><span>👥</span> Katılacaklar</h4>
                <div id="es-attendees" class="flex flex-wrap gap-2"></div>
            </div>
            
            <button id="btn-join" onclick="toggleJoinEvent()" class="w-full bg-zinc-800 hover:bg-zinc-700 transition text-white py-4 rounded-xl font-bold text-sm shadow-lg mb-3 btn-premium-hover"></button>
            <a id="btn-directions" href="#" target="_blank" class="w-full flex items-center justify-center gap-2 bg-black hover:bg-zinc-900 border border-zinc-700 transition text-white py-4 rounded-xl font-bold text-sm shadow-lg mb-3 uppercase tracking-widest btn-premium-hover"><span class="text-lg">🗺️</span> YOL TARİFİ AL</a>
            <button onclick="openComments('event', currentEventId)" class="w-full bg-zinc-900/80 border border-zinc-700 hover:bg-zinc-800 transition text-zinc-300 py-3 rounded-xl font-bold text-xs mb-2 btn-premium-hover flex items-center justify-center gap-2">
                <span>💬</span> Yorumlar
            </button>
            <button id="btn-del-event" onclick="deleteEvent()" class="hidden w-full bg-red-950/50 hover:bg-sky-900/80 transition text-sky-400 py-3.5 rounded-xl text-xs font-bold mt-2 border border-sky-800/50 shadow-md btn-premium-hover">ETKİNLİĞİ SİL</button>
        </div>

        <div id="nearby-routes-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 relative max-h-[80dvh] flex flex-col shadow-[0_0_40px_rgba(0,0,0,0.6)] scale-in-anim">
                <button onclick="document.getElementById('nearby-routes-modal').classList.add('hidden')" class="absolute top-4 right-4 bg-black/50 backdrop-blur border border-zinc-700 hover:bg-zinc-700 transition w-8 h-8 rounded-full flex items-center justify-center text-zinc-300 hover:text-white z-10 hover:scale-110">✕</button>
                <h2 class="text-4xl text-white mb-5 teko-font tracking-wide border-b border-zinc-700 pb-3 drop-shadow-md">📍 YAKIN ROTALAR</h2>
                <div id="nr-list" class="flex-1 overflow-y-auto pr-2 space-y-3 custom-scrollbar"></div>
            </div>
        </div>

        <div id="kvkk-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 py-10 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-sky-900/50 flex flex-col shadow-[0_0_40px_rgba(14,165,233,0.3)] scale-in-anim">
                <h2 class="text-3xl text-white mb-4 teko-font tracking-wide text-sky-400 drop-shadow-md flex items-center gap-2"><span class="animate-pulse">⚠️</span> KULLANICI SÖZLEŞMESİ</h2>
                <div class="overflow-y-auto flex-1 text-xs text-zinc-300 space-y-5 mb-5 custom-scrollbar pr-3 bg-black/50 p-5 rounded-2xl border border-zinc-700 shadow-inner leading-relaxed">
                    <p><b class="text-white text-sm">1. GÜVENLİK VE SORUMLULUK REDDİ (WAIVER)</b><br>
                    Downhill ve Freeride dağ bisikleti, doğası gereği yüksek ölüm ve ağır yaralanma riski taşıyan ekstrem bir spordur. FreeriderTR platformunda (haritada) paylaşılan rampalar, atlayış noktaları ve rotalar tamamen kullanıcılar tarafından eklenmektedir. 
                    <br><br>Bu noktalarda sürüş yaparken oluşabilecek <b>hiçbir kazadan, fiziksel yaralanmadan, ekipman hasarından veya ölümden FreeriderTR yönetimi sorumlu tutulamaz.</b> Sürüş esnasında <i>Tam kapalı kask (Full-face), boyunluk (Neck brace), göğüs/sırt zırhı ve dizlik</i> kullanmak tamamen sizin bireysel sorumluluğunuzdadır.</p>
                    
                    <p><b class="text-white text-sm">2. KİŞİSEL VERİLER (KVKK)</b><br>
                    6698 sayılı Kişisel Verilerin Korunması Kanunu kapsamında; uygulamaya kayıt olurken verdiğiniz isim, şehir bilgileri, yüklediğiniz fotoğraflar, pazar ilanlarınız ve mesajlarınız sunucularımızda saklanmaktadır. <b>"Radar (Sürüşteyim)"</b> modunu açtığınızda anlık GPS konumunuz diğer kullanıcılara açık hale gelir. Verileriniz ticari amaçla 3. şahıslara satılmaz, sadece topluluk içi etkileşim için kullanılır.</p>
                    
                    <p><b class="text-white text-sm">3. TOPLULUK KURALLARI</b><br>
                    Uygulama içi sohbetlerde, pazar ilanlarında ve profil sayfalarında küfür, hakaret, yasa dışı madde ticareti ve müstehcen (+18) içerik paylaşımı kesinlikle yasaktır. İhlal durumunda hesabınız kalıcı olarak (IP ve Cihaz banı ile) sistemden uzaklaştırılır.</p>
                </div>
                <div class="shrink-0 mt-2">
                    <button onclick="closeKvkkModal()" class="w-full bg-sky-700 hover:bg-sky-600 transition text-white py-4 rounded-xl font-black text-sm shadow-[0_0_20px_rgba(2,132,199,0.5)] tracking-widest btn-premium-hover">OKUDUM VE ANLADIM</button>
                </div>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- GELİŞMİŞ YÖNETİCİ PANELİ -->
        <!-- ============================================================ -->
        <div id="admin-panel" class="hidden fixed inset-0 z-[9999] flex items-center justify-center px-3" style="background:rgba(0,0,0,0.85);backdrop-filter:blur(20px)">
            <div class="w-full max-w-lg h-[92dvh] rounded-3xl flex flex-col overflow-hidden shadow-[0_0_60px_rgba(14,165,233,0.3)] border border-sky-900/40 scale-in-anim" style="background:linear-gradient(160deg,#0f0f12 0%,#130d0d 60%,#0a0a0f 100%)">

                <!-- Header -->
                <div class="shrink-0 px-5 pt-5 pb-4 border-b border-sky-900/30" style="background:linear-gradient(90deg,rgba(12,74,110,0.25),rgba(0,0,0,0))">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 rounded-xl flex items-center justify-center text-xl shadow-[0_0_20px_rgba(14,165,233,0.6)]" style="background:linear-gradient(135deg,#0c4a6e,#0369a1)">👑</div>
                            <div>
                                <h2 class="text-2xl text-white teko-font tracking-widest leading-none">YÖNETİM MERKEZİ</h2>
                                <div id="admin-panel-role-tag" class="text-[10px] font-black uppercase tracking-widest text-sky-300 mt-0.5">Ana Yönetici</div>
                            </div>
                        </div>
                        <button onclick="document.getElementById('admin-panel').classList.add('hidden')" class="w-9 h-9 rounded-xl flex items-center justify-center text-zinc-400 hover:text-white border border-zinc-700 hover:border-sky-600 transition-all hover:scale-105" style="background:rgba(0,0,0,0.5)">✕</button>
                    </div>

                    <!-- Tab Navigation -->
                    <div class="flex gap-1 mt-4 p-1 rounded-xl" style="background:rgba(0,0,0,0.4)">
                        <button onclick="adminSwitchTab('overview')" id="atab-overview" class="admin-tab-btn flex-1 py-2 rounded-lg text-[11px] font-black uppercase tracking-wider transition-all active-admin-tab">📊 Genel</button>
                        <button onclick="adminSwitchTab('users')" id="atab-users" class="admin-tab-btn flex-1 py-2 rounded-lg text-[11px] font-black uppercase tracking-wider transition-all">👥 Kullanıcı</button>
                        <button onclick="adminSwitchTab('reels')" id="atab-reels" class="admin-tab-btn flex-1 py-2 rounded-lg text-[11px] font-black uppercase tracking-wider transition-all">🎬 Reels</button>
                        <button onclick="adminSwitchTab('logs')" id="atab-logs" class="admin-tab-btn flex-1 py-2 rounded-lg text-[11px] font-black uppercase tracking-wider transition-all">📋 Kayıt</button>
                        <button onclick="adminSwitchTab('admins')" id="atab-admins" class="admin-tab-btn admin-main-only flex-1 py-2 rounded-lg text-[11px] font-black uppercase tracking-wider transition-all">🛡️ Ekip</button>
                    </div>
                </div>

                <!-- Content Area -->
                <div class="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-4">

                    <!-- ===== GENEL TAB ===== -->
                    <div id="admin-tab-overview" class="space-y-4">
                        <!-- Stats Cards -->
                        <div class="grid grid-cols-3 gap-2">
                            <div class="rounded-2xl p-3 text-center border border-zinc-800/80" style="background:rgba(0,0,0,0.5)">
                                <div id="astat-users" class="text-2xl font-black text-white teko-font">—</div>
                                <div class="text-[9px] text-zinc-500 uppercase font-bold tracking-wider mt-1">Kullanıcı</div>
                            </div>
                            <div class="rounded-2xl p-3 text-center border border-zinc-800/80" style="background:rgba(0,0,0,0.5)">
                                <div id="astat-banned" class="text-2xl font-black text-sky-300 teko-font">—</div>
                                <div class="text-[9px] text-zinc-500 uppercase font-bold tracking-wider mt-1">Banlı</div>
                            </div>
                            <div class="rounded-2xl p-3 text-center border border-zinc-800/80" style="background:rgba(0,0,0,0.5)">
                                <div id="astat-admins" class="text-2xl font-black text-amber-400 teko-font">—</div>
                                <div class="text-[9px] text-zinc-500 uppercase font-bold tracking-wider mt-1">Yrd. Admin</div>
                            </div>
                        </div>

                        <!-- Google Play IAP Doğrulamaları -->
                        <div class="rounded-2xl border border-zinc-800/80 overflow-hidden admin-main-only">
                            <div class="px-4 py-3 flex items-center gap-2 border-b border-zinc-800/50" style="background:rgba(0,0,0,0.4)">
                                <span class="animate-pulse text-sm">📱</span>
                                <span class="text-white font-black text-xs uppercase tracking-widest">Google Play IAP — Bekleyen Onaylar</span>
                            </div>
                            <div id="admin-iap-requests" class="p-3 space-y-2 text-zinc-500 text-xs italic font-medium">Yükleniyor...</div>
                        </div>

                        <!-- Maintenance + News: Main Admin only -->
                        <div class="rounded-2xl border border-zinc-800/80 overflow-hidden admin-main-only">
                            <div class="px-4 py-3 flex items-center justify-between border-b border-zinc-800/50" style="background:rgba(0,0,0,0.4)">
                                <span class="text-white font-black text-xs uppercase tracking-widest">⚙️ Sistem Ayarları</span>
                            </div>
                            <div class="p-4 space-y-3">
                                <div class="flex items-center justify-between">
                                    <span class="text-zinc-300 text-sm font-bold">🔧 Bakım Modu</span>
                                    <input type="checkbox" id="admin-maintenance" onchange="toggleMaintenance()" class="w-6 h-6 accent-sky-500 cursor-pointer">
                                </div>
                                <button onclick="openNewsAdminModal()" class="w-full py-3 rounded-xl text-xs font-black uppercase tracking-widest border border-zinc-700 hover:border-white text-zinc-300 hover:text-white transition-all btn-premium-hover" style="background:rgba(0,0,0,0.4)">📰 Haber / Duyuru Ekle</button>
                            </div>
                        </div>

                        <!-- Sub-admin notify main -->
                        <div class="rounded-2xl border border-amber-900/40 overflow-hidden admin-sub-only" style="display:none">
                            <div class="px-4 py-3 border-b border-amber-900/30" style="background:rgba(120,53,15,0.15)">
                                <span class="text-amber-300 font-black text-xs uppercase tracking-widest">📢 Ana Admine Bildirim Gönder</span>
                            </div>
                            <div class="p-4">
                                <textarea id="admin-notify-msg" placeholder="Ana admine iletmek istediğin mesajı yaz..." class="w-full rounded-xl px-4 py-3 text-sm text-white border border-zinc-700 outline-none focus:border-amber-500 transition resize-none h-20 font-medium" style="background:rgba(0,0,0,0.5)"></textarea>
                                <button onclick="adminNotifyMain()" class="mt-2 w-full py-3 rounded-xl text-xs font-black uppercase tracking-widest border border-amber-700/60 text-amber-300 hover:bg-amber-900/30 transition-all btn-premium-hover">📨 Gönder</button>
                            </div>
                        </div>
                    </div>

                    <!-- ===== KULLANICI TAB ===== -->
                    <div id="admin-tab-users" class="hidden space-y-3">
                        <div class="relative">
                            <input id="admin-user-search" type="text" placeholder="Kullanıcı ara..." oninput="adminSearchUsers()" class="w-full rounded-2xl px-5 py-3.5 text-sm text-white border border-zinc-700 outline-none focus:border-sky-500 transition font-medium" style="background:rgba(0,0,0,0.6)">
                            <span class="absolute right-4 top-1/2 -translate-y-1/2 text-zinc-500">🔍</span>
                        </div>
                        <div id="admin-user-list" class="space-y-2">
                            <!-- Doldurulacak -->
                        </div>
                    </div>

                    <!-- ===== REELS TAB ===== -->
                    <div id="admin-tab-reels" class="hidden space-y-3">
                        <div class="flex items-center justify-between">
                            <span class="text-zinc-400 text-xs font-bold uppercase tracking-widest">Son 50 Reel</span>
                            <button onclick="loadAdminReels()" class="text-[10px] text-sky-300 font-bold border border-sky-900/40 px-3 py-1.5 rounded-lg hover:bg-sky-900/20 transition">🔄 Yenile</button>
                        </div>
                        <div id="admin-reels-list" class="space-y-2">
                            <div class="text-zinc-600 text-xs italic font-medium text-center py-4">Yükleniyor...</div>
                        </div>
                    </div>

                    <!-- ===== LOGLAR TAB ===== -->
                    <div id="admin-tab-logs" class="hidden space-y-3">
                        <div class="flex items-center justify-between">
                            <span class="text-zinc-400 text-xs font-bold uppercase tracking-widest">Admin Eylem Kayıtları</span>
                            <button onclick="loadAdminLogs()" class="text-[10px] text-blue-400 font-bold border border-blue-900/40 px-3 py-1.5 rounded-lg hover:bg-blue-900/20 transition">🔄 Yenile</button>
                        </div>
                        <div id="admin-logs-list" class="space-y-2">
                            <div class="text-zinc-600 text-xs italic font-medium text-center py-4">Yükleniyor...</div>
                        </div>
                    </div>

                    <!-- ===== EKIP (ADMİNLER) TAB ===== -->
                    <div id="admin-tab-admins" class="hidden space-y-4 admin-main-only">
                        <div class="rounded-2xl border border-zinc-800/80 overflow-hidden">
                            <div class="px-4 py-3 border-b border-zinc-800/50" style="background:rgba(0,0,0,0.4)">
                                <span class="text-white font-black text-xs uppercase tracking-widest">➕ Yardımcı Admin Ata</span>
                            </div>
                            <div class="p-4 space-y-3">
                                <input id="assign-admin-username" type="text" placeholder="Kullanıcı adı gir..." class="w-full rounded-xl px-4 py-3 text-sm text-white border border-zinc-700 outline-none focus:border-amber-500 transition font-medium" style="background:rgba(0,0,0,0.5)">
                                <button onclick="assignSubAdmin()" class="w-full py-3 rounded-xl text-xs font-black uppercase tracking-widest border border-amber-700/60 text-amber-300 hover:bg-amber-900/30 transition-all btn-premium-hover">👑 Yardımcı Admin Yap</button>
                            </div>
                        </div>

                        <div class="rounded-2xl border border-zinc-800/80 overflow-hidden">
                            <div class="px-4 py-3 flex items-center justify-between border-b border-zinc-800/50" style="background:rgba(0,0,0,0.4)">
                                <span class="text-white font-black text-xs uppercase tracking-widest">🛡️ Mevcut Yardımcı Adminler</span>
                                <button onclick="loadSubAdmins()" class="text-[10px] text-zinc-400 font-bold hover:text-white transition">🔄</button>
                            </div>
                            <div id="sub-admin-list" class="p-3 space-y-2">
                                <div class="text-zinc-600 text-xs italic font-medium text-center py-3">Yükleniyor...</div>
                            </div>
                        </div>

                        <div class="rounded-2xl border border-sky-900/30 overflow-hidden">
                            <div class="px-4 py-3 border-b border-sky-900/25" style="background:rgba(12,74,110,0.1)">
                                <span class="text-sky-300 font-black text-xs uppercase tracking-widest">🚫 Yetki Al</span>
                            </div>
                            <div class="p-4 space-y-3">
                                <input id="revoke-admin-username" type="text" placeholder="Admin kullanıcı adı..." class="w-full rounded-xl px-4 py-3 text-sm text-white border border-zinc-700 outline-none focus:border-sky-500 transition font-medium" style="background:rgba(0,0,0,0.5)">
                                <button onclick="revokeSubAdmin()" class="w-full py-3 rounded-xl text-xs font-black uppercase tracking-widest border border-sky-800/60 text-sky-300 hover:bg-sky-900/20 transition-all btn-premium-hover">❌ Adminliği Geri Al</button>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>

        <!-- Kullanıcı Aktivite Modalı -->
        <div id="user-activity-modal" class="hidden fixed inset-0 z-[99999] flex items-center justify-center px-3" style="background:rgba(0,0,0,0.9);backdrop-filter:blur(16px)">
            <div class="w-full max-w-md h-[88dvh] rounded-3xl flex flex-col overflow-hidden border border-zinc-700 shadow-2xl scale-in-anim" style="background:#0c0c10">
                <div class="shrink-0 px-5 py-4 border-b border-zinc-800 flex items-center justify-between">
                    <div>
                        <h3 class="text-xl text-white teko-font tracking-wide">🔍 Kullanıcı Aktivitesi</h3>
                        <div id="ua-username-label" class="text-xs text-zinc-500 font-bold mt-0.5"></div>
                    </div>
                    <button onclick="document.getElementById('user-activity-modal').classList.add('hidden')" class="w-9 h-9 rounded-xl bg-zinc-900 border border-zinc-700 text-zinc-400 hover:text-white flex items-center justify-center transition">✕</button>
                </div>
                <div class="flex gap-1 p-3 border-b border-zinc-800" style="background:rgba(0,0,0,0.3)">
                    <button onclick="uaTab('messages')" id="uatab-messages" class="ua-tab-btn flex-1 py-2 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all ua-active-tab">💬 Mesajlar</button>
                    <button onclick="uaTab('dms')" id="uatab-dms" class="ua-tab-btn flex-1 py-2 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all">📩 DM</button>
                    <button onclick="uaTab('reels')" id="uatab-reels" class="ua-tab-btn flex-1 py-2 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all">🎬 Reels</button>
                    <button onclick="uaTab('markers')" id="uatab-markers" class="ua-tab-btn flex-1 py-2 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all">📍 Yerler</button>
                </div>
                <div class="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-2" id="ua-content">
                    <div class="text-zinc-600 text-xs italic text-center py-6">Yükleniyor...</div>
                </div>
                <div class="shrink-0 p-3 border-t border-zinc-800 grid grid-cols-2 gap-2">
                    <button id="ua-ban-btn" onclick="adminBanFromActivity()" class="py-3 rounded-xl text-xs font-black uppercase tracking-widest border border-sky-800/60 text-sky-300 hover:bg-sky-900/20 transition">🚨 Banla</button>
                    <button onclick="document.getElementById('user-activity-modal').classList.add('hidden')" class="py-3 rounded-xl text-xs font-black uppercase tracking-widest border border-zinc-700 text-zinc-400 hover:bg-zinc-800 transition">Kapat</button>
                </div>
            </div>
        </div>
        
        <div id="news-admin-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4 backdrop-blur-md">
            <div class="glass-panel w-full max-w-md rounded-3xl p-6 border border-zinc-700 shadow-2xl scale-in-anim">
                <h2 class="text-4xl text-white mb-6 teko-font tracking-wide drop-shadow-md">📰 YENİ HABER</h2>
                <input id="news-title" type="text" placeholder="Haber Başlığı" class="w-full bg-black/60 p-4 rounded-xl mb-4 text-white font-bold border border-zinc-700 outline-none focus:border-white transition shadow-inner">
                <textarea id="news-content" placeholder="Haber İçeriği..." class="w-full bg-black/60 p-4 rounded-xl h-28 mb-4 text-white font-medium border border-zinc-700 outline-none focus:border-white transition custom-scrollbar shadow-inner"></textarea>
                
                <label class="block text-[10px] text-zinc-400 mb-2 uppercase font-bold tracking-widest">Haber Görseli (İsteğe Bağlı)</label>
                <input id="news-photo" type="file" accept="image/*" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-3 py-3 mb-6 text-xs text-zinc-300 focus:border-white transition cursor-pointer shadow-inner">
                
                <div class="flex gap-3">
                    <button onclick="document.getElementById('news-admin-modal').classList.add('hidden')" class="flex-1 bg-zinc-800 hover:bg-zinc-700 transition py-4 rounded-xl text-white font-bold shadow-md btn-premium-hover">İptal</button>
                    <button onclick="saveNews()" class="flex-1 bg-white hover:bg-gray-200 transition py-4 rounded-xl text-black font-bold shadow-[0_0_15px_rgba(255,255,255,0.3)] btn-premium-hover">YAYINLA</button>
                </div>
            </div>
        </div>

        <!-- spin sesleri missions screen'de inline -->

    <script>
        // Global Değişkenler
        // window.currentUser olarak tanımla — OneSignal init callback'i erişebilsin
        window.currentUser = null;
        let currentUser = null; 
        let map; 
        let userLat = 39.0; 
        let userLng = 35.0; 
        let tempLat; 
        let tempLng;
        let db = { 
            users: [], 
            markers: [], 
            messages: [], 
            market: [], 
            events: [], 
            news: [], 
            reports: [], 
            banned: [], 
            dms: [], 
            maintenance: false, 
            pinned_message: {},
            total_users: 300,
            active_users: 0
        };
        // Reels global state
        let reelsData = [];
        let currentReelId = null;
        let reelFileData = null;
        let reelFileType = null;
        let _prevTab = 0; // Reels'ten önce hangi tab'daydık

        // ── Toast Bildirim Sistemi ─────────────────────────────────────────────
        // showToast(message, duration?)  →  ekranın altında kısa süreli bildirim gösterir
        // Tüm fonksiyonlarda (requestPremium, verifyGooglePurchase vb.) kullanılır.
        let _toastTimer = null;
        function showToast(message, duration = 3000) {
            let toast = document.getElementById('__freerider_toast__');
            if (!toast) {
                toast = document.createElement('div');
                toast.id = '__freerider_toast__';
                toast.style.cssText = [
                    'position:fixed', 'bottom:80px', 'left:50%',
                    'transform:translateX(-50%)', 'z-index:9999999',
                    'background:rgba(24,24,27,0.97)', 'color:#f4f4f5',
                    'padding:12px 22px', 'border-radius:14px',
                    'font-size:14px', 'font-weight:700',
                    'box-shadow:0 4px 24px rgba(0,0,0,0.5)',
                    'border:1px solid rgba(255,255,255,0.1)',
                    'max-width:88vw', 'text-align:center',
                    'pointer-events:none', 'transition:opacity 0.3s',
                    'opacity:0'
                ].join(';');
                document.body.appendChild(toast);
            }
            toast.textContent = message;
            toast.style.opacity = '1';
            if (_toastTimer) clearTimeout(_toastTimer);
            _toastTimer = setTimeout(() => { toast.style.opacity = '0'; }, duration);
        }
        let markerLayers = []; 
        let currentMessageCount = 0; 
        let currentEventId = null; 
        let currentMarketId = null; 
        let currentDmUser = null; 
        let currentMarkerId = null; 
        let mediaRecorder; 
        let audioChunks = [];
        let _voiceStopping = false; // Ses gönderim aşamasında tekrar tıklamayı engeller
        window.currentOwner = null; 
        let isAddingMarkerMode = false; 
        let isAddingEventMode = false; 
        let currentPhotoContext = 'group';
        let editingBikeIndex = null;

        let editingMarkerId = null;
        let editingMarkerLat = null;
        let editingMarkerLng = null;

        let currentLeaderboardTab = 'weekly'; 
        let verificationUsername = null;

        function checkFileSize(file, maxMB = 10) {
            if(!file) return true; 
            const fileSizeMB = file.size / (1024 * 1024);
            if (fileSizeMB > maxMB) {
                alert(`⚠️ Dosya çok büyük (${fileSizeMB.toFixed(2)} MB). Lütfen sistemi yormamak için ${maxMB}MB'dan küçük bir görsel seçin.`);
                return false;
            }
            return true;
        }
        
        // =====================================================
        // ŞANS ÇARKI - SABİT ÖDÜL LİSTESİ (backend ile eşleşir)
        // =====================================================
        window.WHEEL_PRIZES = [
            {id: "xp_100",      name: "100 XP",          color: "#38bdf8"},
            {id: "prem_dlx_1",  name: "1G Deluxe",        color: "#8b5cf6"},
            {id: "xp_200",      name: "200 XP",           color: "#f59e0b"},
            {id: "prem_ult_1",  name: "1G Ultra+",        color: "#eab308"},
            {id: "xp_300",      name: "300 XP",           color: "#10b981"},
            {id: "prem_std_7",  name: "7G Standart",      color: "#3b82f6"},
            {id: "xp_500",      name: "500 XP",           color: "#38bdf8"},
            {id: "prem_dlx_7",  name: "7G Deluxe",        color: "#8b5cf6"},
            {id: "xp_1000",     name: "1000 XP",          color: "#f59e0b"},
            {id: "prem_ult_7",  name: "7G Ultra+",        color: "#eab308"},
            {id: "xp_10000",    name: "10.000 XP",        color: "#10b981"},
            {id: "prem_std_30", name: "1Ay Standart",     color: "#3b82f6"},
            {id: "xp_100000",   name: "100.000 XP",       color: "#38bdf8"},
            {id: "prem_dlx_30", name: "1Ay Deluxe",       color: "#8b5cf6"},
            {id: "prem_ult_30", name: "1Ay Ultra+",       color: "#eab308"},
            {id: "prem_std_365",name: "1Yil Standart",    color: "#3b82f6"},
            {id: "prem_ult_365",name: "1Yil Ultra+",      color: "#eab308"},
            {id: "xp_200",      name: "200 XP",           color: "#f59e0b"},
        ];


        function checkRefCodeInput() {
            const val = document.getElementById("reg-ref-code").value.trim();
            const container = document.getElementById("reg-ref-reward-container");
            if(val.length > 0) {
                container.classList.remove("hidden");
                container.classList.add("scale-in-anim");
            } else {
                container.classList.add("hidden");
            }
        }

        // =========================================================
        // GİRİŞ VE KAYIT İŞLEMLERİ
        // =========================================================
        async function handleLogin() {
            const u = document.getElementById("login-username").value.trim();
            const p = document.getElementById("login-password").value;
            const rem = document.getElementById("remember-me").checked;
            
            if(!u || !p) return alert("Kullanıcı adı ve şifre zorunludur!");
            
            try {
                const res = await sendAction('login', { username: u, password: p });
                if(res.status === 'ok') {
                    currentUser = res.user;
                    window.currentUser = currentUser; // OneSignal callback için global'e de yaz
                    localStorage.setItem("fr_user", JSON.stringify(currentUser));
                    
                    if(rem) {
                        localStorage.setItem("fr_remembered_username", u);
                        localStorage.setItem("fr_remembered_password", btoa(unescape(encodeURIComponent(p))));
                    } else {
                        localStorage.removeItem("fr_remembered_username");
                        localStorage.removeItem("fr_remembered_password");
                    }
                    
                    if(res.user.just_got_daily) {
                        alert("🎉 Harika! Günlük giriş ödülü olarak +" + res.user.just_got_daily + " XP kazandın.");
                    }
                    
                    loginSuccess();
                }
            } catch(e) { }
        }

        async function handleRegister() {
            const name = document.getElementById("reg-name").value.trim();
            const username = document.getElementById("reg-username").value.trim();
            const city = document.getElementById("reg-city").value.trim();
            const password = document.getElementById("reg-password").value;
            const email = document.getElementById("reg-email").value.trim();
            const marketing = document.getElementById("reg-marketing").checked;
            const kvkk = document.getElementById("reg-kvkk").checked;
            const privacy = document.getElementById("reg-privacy").checked;
            const refCode = document.getElementById("reg-ref-code").value.trim();
            const refReward = document.getElementById("reg-ref-reward").value;
            
            if(!name || !username || !city || !password) return alert("Lütfen Ad Soyad, Kullanıcı Adı, Şehir ve Şifre alanlarını doldurun!");
            
            // Gmail zorunlu değil, ama girilmişse geçerli olmalı
            if(email && !email.toLowerCase().endsWith('@gmail.com')) return alert("Girdiğiniz e-posta @gmail.com uzantılı değil. Lütfen Gmail adresinizi girin ya da alanı boş bırakın.");
            
            // Referans kodu varsa Gmail zorunlu
            if(refCode && !email) return alert("Referans kodu kullanabilmek için @gmail.com adresinizi girmeniz zorunludur! (Spam koruması)");
            if(refCode && !email.toLowerCase().endsWith('@gmail.com')) return alert("Referans kodu kullanabilmek için @gmail.com uzantılı e-posta girmeniz zorunludur! (Spam koruması)");
            
            if(password.length < 4) return alert("Şifre en az 4 karakter olmalıdır!");
            if(!kvkk) return alert("Kayıt olmak için Kullanıcı Sözleşmesi ve KVKK metnini onaylamanız gerekmektedir!");
            if(!privacy) return alert("Kayıt olmak için Gizlilik Sözleşmesi ve Kullanım Şartları'nı onaylamanız gerekmektedir!");
            
            try {
                const payload = {
                    name: name,
                    username: username,
                    city: city,
                    password: password,
                    email: email,
                    marketing: marketing
                };
                
                if (refCode) {
                    payload.ref_code = refCode;
                    payload.ref_reward = refReward;
                }
                
                const res = await sendAction('register', payload);
                
                if(res.status === 'ok') {
                    alert("Kayıt başarılı! Aramıza hoş geldin. Şimdi giriş yapabilirsin.");
                    showLoginTab();
                    document.getElementById("login-username").value = username;
                } else if (res.status === 'needs_verification') {
                    verificationUsername = res.username;
                    document.getElementById("verify-code-input").value = "";
                    document.getElementById("email-verify-modal").classList.remove("hidden");
                    alert("Kayıt başarılı! E-posta adresinize bir doğrulama kodu gönderdik.");
                }
            } catch(e) { 
                console.error(e);
            }
        }

        function openKvkkModal() {
            document.getElementById("kvkk-modal").classList.remove("hidden");
        }

        function closeKvkkModal() {
            document.getElementById("kvkk-modal").classList.add("hidden");
            document.getElementById("reg-kvkk").checked = true;
        }

        function showLoginTab() {
            document.getElementById("login-form").classList.remove("hidden");
            document.getElementById("register-form").classList.add("hidden");
            document.getElementById("login-tab-btn").className = "flex-1 py-3 bg-gradient-to-r from-sky-700 to-sky-500 text-white rounded-lg font-black text-sm shadow-[0_0_15px_rgba(2,132,199,0.5)] tracking-widest uppercase transition-all scale-in-anim";
            document.getElementById("register-tab-btn").className = "flex-1 py-3 bg-transparent text-zinc-400 rounded-lg font-bold text-sm tracking-widest uppercase transition-all hover:text-white";
        }

        function showRegisterTab() {
            document.getElementById("login-form").classList.add("hidden");
            document.getElementById("register-form").classList.remove("hidden");
            document.getElementById("register-tab-btn").className = "flex-1 py-3 bg-gradient-to-r from-sky-700 to-sky-500 text-white rounded-lg font-black text-sm shadow-[0_0_15px_rgba(2,132,199,0.5)] tracking-widest uppercase transition-all scale-in-anim";
            document.getElementById("login-tab-btn").className = "flex-1 py-3 bg-transparent text-zinc-400 rounded-lg font-bold text-sm tracking-widest uppercase transition-all hover:text-white";
        }



        const TITLES = [
            {min:0,     max: 99,    name: "Acemi",        color: "text-zinc-500",  icon: "🌱", next: 100},
            {min:100,   max: 499,   name: "Çaylak",       color: "text-zinc-400",  icon: "🚲", next: 500},
            {min:500,   max: 999,   name: "Sürücü",       color: "text-sky-400",   icon: "🏔️", next: 1000},
            {min:1000,  max: 1999,  name: "Deneyimli",    color: "text-blue-400",  icon: "⚡", next: 2000},
            {min:2000,  max: 3999,  name: "Rampa Savaşçısı", color: "text-indigo-400",icon: "🛡️", next: 4000},
            {min:4000,  max: 6999,  name: "Usta",         color: "text-orange-400",icon: "🔥", next: 7000},
            {min:7000,  max: 9999,  name: "Elite",        color: "text-rose-400",  icon: "💥", next: 10000},
            {min:10000, max: 19999, name: "Şampiyon",     color: "text-yellow-400",icon: "🏆", next: 20000},
            {min:20000, max: 49999, name: "Efsane",       color: "text-sky-400",   icon: "👑", next: 50000},
            {min:50000, max: 999999,name: "Downhill Efsanesi", color: "text-prem-rainbow", icon: "🌟", next: null}
        ];

        function getTitle(xp) {
            return TITLES.find(t => xp >= t.min && xp <= t.max) || TITLES[TITLES.length - 1];
        }
        
        function getTitleProgress(xp) {
            const t = getTitle(xp);
            if (!t.next) return {percent: 100, xpLeft: 0, nextName: null};
            const range = t.next - t.min;
            const prog = xp - t.min;
            return {
                percent: Math.min(Math.round((prog / range) * 100), 100),
                xpLeft: t.next - xp,
                nextName: TITLES.find(tt => tt.min === t.next)?.name || null,
                nextIcon: TITLES.find(tt => tt.min === t.next)?.icon || ''
            };
        }
        
        const verifiedTick = `<svg class="w-4 h-4 inline-block text-blue-500 drop-shadow-[0_0_5px_rgba(59,130,246,0.8)]" fill="currentColor" viewBox="0 0 20 20"><path d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"></path></svg>`;

        // === KALICI GÖREVLER (bir kere tamamlanır) ===
        const MISSIONS = [
            { id: "m1",  title: "İlk Adım",      desc: "Uygulamaya ilk kez giriş yap.",          target: 1,   type: "login_streak",   xp: 50,   icon: "👋", badge: null },
            { id: "m2",  title: "Bağımlı",        desc: "7 gün üst üste giriş yap.",              target: 7,   type: "login_streak",   xp: 200,  icon: "🔥", badge: "Seri Girişçi" },
            { id: "m3",  title: "Sadık Üye",      desc: "30 gün üst üste giriş yap.",             target: 30,  type: "login_streak",   xp: 2000, icon: "💎", badge: "Demir Üye" },
            { id: "m4",  title: "Çılgın",         desc: "100 gün üst üste giriş yap.",            target: 100, type: "login_streak",   xp: 10000,icon: "⚡", badge: "100 Gün Ustası" },
            { id: "m5",  title: "Sohbete Katıl",  desc: "Gruba 1 mesaj gönder.",                  target: 1,   type: "total_messages", xp: 20,   icon: "💬", badge: null },
            { id: "m6",  title: "Geveze",         desc: "Gruba 50 mesaj gönder.",                 target: 50,  type: "total_messages", xp: 300,  icon: "🗣️", badge: "Sohbet Tutkunu" },
            { id: "m7",  title: "Chat Efsanesi",  desc: "Gruba 200 mesaj gönder.",                target: 200, type: "total_messages", xp: 1000, icon: "👑", badge: "Chat Efsanesi" },
            { id: "m8",  title: "Kâşif",          desc: "Haritaya 1 rampa ekle.",                 target: 1,   type: "markers",        xp: 50,   icon: "📍", badge: "Harita Kâşifi" },
            { id: "m9",  title: "Haritacı",       desc: "Haritaya 10 rampa ekle.",                target: 10,  type: "markers",        xp: 500,  icon: "🗺️", badge: "Haritacı" },
            { id: "m10", title: "İlk Satış",      desc: "Pazara 1 ilan ekle.",                    target: 1,   type: "market",         xp: 50,   icon: "🛒", badge: "Esnaf" },
            { id: "m11", title: "Pazar Ustası",   desc: "Pazara 5 ilan ekle.",                    target: 5,   type: "market",         xp: 300,  icon: "💰", badge: "Pazar Ustası" },
            { id: "m12", title: "Organizatör",    desc: "1 sürüş buluşması oluştur.",             target: 1,   type: "events",         xp: 100,  icon: "🤝", badge: "Organizatör" },
            { id: "m13", title: "Topluluk Lideri",desc: "5 sürüş buluşması oluştur.",             target: 5,   type: "events",         xp: 500,  icon: "🏆", badge: "Topluluk Lideri" },
        ];

        // === GÜNLÜK GÖREVLER (her gün sıfırlanır) ===
        function getDailyMissions() {
            // Güne göre deterministik görev seti (aynı gün herkes aynı görevi görür)
            const dayNum = Math.floor(Date.now() / 86400000);
            const todayKey = new Date().toISOString().split('T')[0];
            const sets = [
                [{ id: "d1", title: "Günlük Giriş",    desc: "Bugün giriş yap.",           target: 1,  type: "daily_login",   xp: 30,  icon: "☀️" },
                 { id: "d2", title: "Sohbet Et",        desc: "Bugün 3 mesaj gönder.",       target: 3,  type: "daily_msg",     xp: 50,  icon: "💬" },
                 { id: "d3", title: "Haritayı Keşfet",  desc: "Haritada 1 nokta ekle.",      target: 1,  type: "daily_marker",  xp: 80,  icon: "📍" }],
                [{ id: "d1", title: "Günlük Giriş",    desc: "Bugün giriş yap.",           target: 1,  type: "daily_login",   xp: 30,  icon: "☀️" },
                 { id: "d4", title: "AI Sor",           desc: "AI'a 1 soru sor.",            target: 1,  type: "daily_ai",      xp: 40,  icon: "🤖" },
                 { id: "d5", title: "Pazar Gez",        desc: "Bir ilana bak.",              target: 1,  type: "daily_market",  xp: 20,  icon: "🛒" }],
                [{ id: "d1", title: "Günlük Giriş",    desc: "Bugün giriş yap.",           target: 1,  type: "daily_login",   xp: 30,  icon: "☀️" },
                 { id: "d6", title: "Aktif Ol",         desc: "Bugün 5 mesaj gönder.",       target: 5,  type: "daily_msg",     xp: 70,  icon: "🔥" },
                 { id: "d7", title: "Sürüşe Çık",       desc: "Radar modunu aç.",            target: 1,  type: "daily_radar",   xp: 60,  icon: "📡" }],
            ];
            const todaySet = sets[dayNum % sets.length];
            return { missions: todaySet, key: todayKey };
        }

        // === HAFTALIK GÖREVLER (her Pazartesi sıfırlanır) ===
        function getWeeklyMissions() {
            const weekNum = Math.floor(Date.now() / (86400000 * 7));
            const now = new Date();
            const monday = new Date(now);
            monday.setDate(now.getDate() - ((now.getDay() + 6) % 7));
            const weekKey = monday.toISOString().split('T')[0];
            const sets = [
                [{ id: "w1", title: "Haftalık Konuşmacı", desc: "Bu hafta 20 mesaj gönder.",  target: 20, type: "weekly_msg",    xp: 200, icon: "💬" },
                 { id: "w2", title: "Harita Gezgini",     desc: "Bu hafta 2 rampa ekle.",      target: 2,  type: "weekly_marker", xp: 150, icon: "🗺️" }],
                [{ id: "w3", title: "Topluluk Üyesi",     desc: "Bu hafta 1 etkinlik oluştur.",target: 1,  type: "weekly_event",  xp: 250, icon: "📅" },
                 { id: "w4", title: "Aktif Tüccar",       desc: "Bu hafta 1 ilan ver.",        target: 1,  type: "weekly_market", xp: 150, icon: "🛒" }],
                [{ id: "w5", title: "Sürüş Ustası",       desc: "Bu hafta 3 kez radar aç.",    target: 3,  type: "weekly_radar",  xp: 200, icon: "🚴" },
                 { id: "w6", title: "Soru Sorular",        desc: "Bu hafta 5 AI sorusu sor.",   target: 5,  type: "weekly_ai",     xp: 180, icon: "🤖" }],
            ];
            return { missions: sets[weekNum % sets.length], key: weekKey };
        }

        function resizeImage(file, maxSize) {
            return new Promise((resolve) => {
                if(!file) { 
                    resolve(null); 
                    return; 
                }
                const reader = new FileReader();
                
                reader.onload = (e) => {
                    const img = new Image();
                    img.onload = () => {
                        const canvas = document.createElement('canvas');
                        let width = img.width; 
                        let height = img.height;
                        
                        if (width > height && width > maxSize) { 
                            height *= maxSize / width; 
                            width = maxSize; 
                        } else if (height > maxSize) { 
                            width *= maxSize / height; 
                            height = maxSize; 
                        }
                        
                        canvas.width = width; 
                        canvas.height = height;
                        
                        const ctx = canvas.getContext('2d'); 
                        ctx.drawImage(img, 0, 0, width, height);
                        
                        resolve(canvas.toDataURL('image/jpeg', 0.72)); 
                    };
                    img.onerror = () => resolve(null);
                    img.src = e.target.result;
                };
                reader.onerror = () => resolve(null);
                reader.readAsDataURL(file);
            });
        }

        const supaUrl = '{{ supabase_url }}';
        const supaKey = '{{ supabase_key }}';
        // DUZELTME #4: window.supabase CDN'den gecikmeli yuklenebilir.
        // Direkt createClient() cagrisi "window.supabase is not defined" hatasi verir
        // ve bu, sonraki TUM JS kodunun calismasini durdurur (butonlar donuyor).
        let supaClient = null;
        if(window.supabase) {
            supaClient = window.supabase.createClient(supaUrl, supaKey);
        } else {
            console.error("[FreeriderTR] Supabase JS SDK yuklenemedi. Realtime ozellikler calismiyor.");
            // Script hatasi tum sayfayi kilitlememesi icin devam et
        }

        // ==============================================================
        // ÇEVRİM İÇİ DURUM YARDIMCI FONKSİYONLARI
        // ==============================================================
        function getOnlineStatus(user) {
            if (!user || !user.stats) return { status: 'offline', label: '' };
            const ts = user.stats.last_seen_ts;
            if (!ts) return { status: 'offline', label: '' };
            const nowSec = Math.floor(Date.now() / 1000);
            const diff = nowSec - ts;
            if (diff < 300) return { status: 'online', label: 'Şu an aktif' };
            if (diff < 3600) {
                const mins = Math.floor(diff / 60);
                return { status: 'recent', label: `${mins} dk önce aktifti` };
            }
            if (diff < 86400) {
                const hrs = Math.floor(diff / 3600);
                return { status: 'today', label: `${hrs} saat önce` };
            }
            return { status: 'offline', label: '' };
        }

        function getOnlineHTML(user, showLabel = true) {
            const s = getOnlineStatus(user);
            if (s.status === 'online') {
                return showLabel
                    ? `<span class="online-dot-sm"></span><span class="online-label">${s.label}</span>`
                    : `<span class="online-dot-sm"></span>`;
            }
            if (s.status === 'recent') {
                return showLabel
                    ? `<span class="recent-dot"></span><span class="recent-label">${s.label}</span>`
                    : `<span class="recent-dot"></span>`;
            }
            return '';
        }

        // ==============================================================
        // GERÇEK ALEV & BUZ PARTİKÜL SİSTEMİ (Ultra+)
        // ==============================================================
        const _particleTimers = {};

        function startParticles(canvasId, type) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            // Canvas wraps around the circular avatar
            const SIZE = canvas.width = canvas.height = 160;
            const CX = SIZE / 2, CY = SIZE / 2;
            const R = 68; // avatar radius
            let particles = [];
            let running = true;
            const isIce = type === 'ice';

            function mkFireParticle() {
                // Spawn along bottom arc of circle
                const angle = (Math.random() * Math.PI) + Math.PI; // bottom half: pi to 2pi
                const spawnR = R + 2;
                return {
                    x: CX + Math.cos(angle) * spawnR,
                    y: CY + Math.sin(angle) * spawnR,
                    vx: Math.cos(angle) * -(0.3 + Math.random()*0.5) + (Math.random()-0.5)*0.6,
                    vy: -(0.8 + Math.random()*1.4),
                    size: 4 + Math.random()*5,
                    life: 1,
                    decay: 0.022 + Math.random()*0.02,
                    phase: Math.random() * Math.PI * 2  // wobble phase
                };
            }

            function mkIceParticle() {
                // Spawn around full circle border
                const angle = Math.random() * Math.PI * 2;
                const spawnR = R + 1;
                return {
                    x: CX + Math.cos(angle) * spawnR,
                    y: CY + Math.sin(angle) * spawnR,
                    angle: angle,
                    vr: (Math.random()-0.5)*0.01,  // angular drift
                    r: spawnR + Math.random()*8,
                    size: 2 + Math.random()*3.5,
                    life: 1,
                    decay: 0.012 + Math.random()*0.015,
                    points: Math.floor(5 + Math.random()*3),
                    rotation: Math.random()*Math.PI
                };
            }

            function drawFireParticle(p) {
                const wobble = Math.sin(p.phase + performance.now()*0.004) * 1.2;
                p.x += p.vx + wobble * 0.15;
                p.y += p.vy;
                p.size *= 0.978;
                p.life -= p.decay;
                if(p.life <= 0) return false;
                const a = Math.max(0, p.life);
                const t = 1 - p.life;
                // fire color: deep red -> orange -> yellow at tip
                const h = 15 + t * 35;  // 15=red-orange, 50=yellow
                const l = 35 + t * 25;
                const grad = ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,p.size);
                grad.addColorStop(0, `hsla(${h},100%,${l+20}%,${a*0.9})`);
                grad.addColorStop(0.4, `hsla(${h},100%,${l}%,${a*0.6})`);
                grad.addColorStop(1, `hsla(${h-5},90%,${l-10}%,0)`);
                ctx.beginPath();
                ctx.arc(p.x, p.y, Math.max(0.1,p.size), 0, Math.PI*2);
                ctx.fillStyle = grad;
                ctx.globalAlpha = a;
                ctx.fill();
                return true;
            }

            function drawIceParticle(p) {
                p.angle += p.vr;
                p.x = CX + Math.cos(p.angle) * p.r;
                p.y = CY + Math.sin(p.angle) * p.r;
                p.life -= p.decay;
                if(p.life <= 0) return false;
                const a = Math.max(0, p.life) * 0.85;
                ctx.save();
                ctx.translate(p.x, p.y);
                ctx.rotate(p.rotation + performance.now()*0.0008);
                ctx.globalAlpha = a;
                // Draw snowflake/crystal shape
                const n = p.points;
                const s = Math.max(0.5, p.size);
                ctx.beginPath();
                for(let i=0;i<n*2;i++){
                    const r2 = i%2===0 ? s : s*0.4;
                    const ang2 = (i/n)*Math.PI;
                    i===0 ? ctx.moveTo(Math.cos(ang2)*r2,Math.sin(ang2)*r2)
                           : ctx.lineTo(Math.cos(ang2)*r2,Math.sin(ang2)*r2);
                }
                ctx.closePath();
                ctx.fillStyle = `rgba(180,230,255,${a*0.7})`;
                ctx.strokeStyle = `rgba(200,245,255,${a})`;
                ctx.lineWidth = 0.5;
                ctx.fill(); ctx.stroke();
                ctx.restore();
                return true;
            }

            function frame() {
                if (!running) return;
                ctx.clearRect(0, 0, SIZE, SIZE);
                // Spawn
                const spawnRate = isIce ? 0.35 : 0.6;
                if(Math.random() < spawnRate) particles.push(isIce ? mkIceParticle() : mkFireParticle());
                if(Math.random() < spawnRate*0.5) particles.push(isIce ? mkIceParticle() : mkFireParticle());
                // Draw & filter
                particles = particles.filter(p => isIce ? drawIceParticle(p) : drawFireParticle(p));
                ctx.globalAlpha = 1;
                requestAnimationFrame(frame);
            }
            frame();
            return () => { running = false; };
        }

        function attachParticles(wrapId, canvasId, type) {
            // stop previous if exists
            if (_particleTimers[canvasId]) { _particleTimers[canvasId](); delete _particleTimers[canvasId]; }
            const stop = startParticles(canvasId, type);
            if (stop) _particleTimers[canvasId] = stop;
        }

        // Profil avatarına parçacık ekle/kaldır
        function applyAvatarEffect(effect) {
            const wrap = document.getElementById('profile-avatar-wrap');
            let canvas = document.getElementById('profile-particle-canvas');
            if (!wrap) return;
            if (effect === 'fire' || effect === 'ice') {
                if (!canvas) {
                    canvas = document.createElement('canvas');
                    canvas.id = 'profile-particle-canvas';
                    // Centered overlay, slightly larger than avatar (128px = w-32)
                    canvas.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:160px;height:160px;pointer-events:none;z-index:50;';
                    canvas.width = 160; canvas.height = 160;
                    wrap.appendChild(canvas);
                }
                attachParticles('profile-avatar-wrap','profile-particle-canvas', effect);
            } else {
                if (canvas) { canvas.remove(); }
                if (_particleTimers['profile-particle-canvas']) { _particleTimers['profile-particle-canvas'](); }
            }
        }

        // Leaderboard/Chat avatarlarına da mini parçacık ekle
        function maybeAddMiniParticles(imgEl, username) {
            const u = db.users.find(x => x.username === username);
            if (!u || !u.stats) return;
            const effect = u.stats.avatar_effect || 'none';
            if (effect !== 'fire' && effect !== 'ice') return;
            const pid = 'pcanv-' + username.replace(/[^a-zA-Z0-9]/g,'');
            if (document.getElementById(pid)) return; // already added
            const wrap = imgEl.parentElement;
            if (!wrap) return;
            const origPos = wrap.style.position;
            wrap.style.position = 'relative';
            wrap.style.overflow = 'visible';
            const canvas = document.createElement('canvas');
            canvas.id = pid;
            canvas.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:80px;height:80px;pointer-events:none;z-index:50;';
            canvas.width = 80; canvas.height = 80;
            wrap.appendChild(canvas);
            attachParticles(wrap.id || '', pid, effect);
        }

        // ==============================================================
        // Heartbeat — her dakikada sunucuya "burdayım" gönder + lokal güncelle
        async function sendHeartbeat() {
            if (!currentUser) return;
            const nowSec = Math.floor(Date.now() / 1000);
            // Lokal güncelle - anında yansısın
            if (currentUser.stats) currentUser.stats.last_seen_ts = nowSec;
            const me = db.users.find(u => u.username === currentUser.username);
            if (me && me.stats) me.stats.last_seen_ts = nowSec;
            // Sunucuya da gönder; üyelik süresi dolmuşsa UI'ı güncelle
            try {
                const hbRes = await fetch('/api/heartbeat', { method: 'POST' });
                if (hbRes.ok) {
                    const hbData = await hbRes.json();
                    if (hbData.premium_revoked) {
                        // Üyelik sona erdi – lokal state sıfırla
                        if (currentUser.stats) {
                            currentUser.stats.premium_tier = 0;
                            currentUser.stats.premium_color = '';
                            delete currentUser.stats.premium_expire_date;
                            delete currentUser.stats.expiry_ts;
                        }
                        if (me && me.stats) {
                            me.stats.premium_tier = 0;
                            me.stats.premium_color = '';
                            delete me.stats.premium_expire_date;
                            delete me.stats.expiry_ts;
                        }
                        showToast('⚠️ Üyeliğin sona erdi. Devam etmek için yenile!');
                    }
                }
            } catch(e) {}
        }

        // ==============================================================
        // ONESIGNAL PUSH BİLDİRİM
        // ==============================================================
        async function requestPushPermission() {
            try {
                // İzin zaten verilmişse tekrar sormadan login yap
                const alreadyGranted = Notification.permission === 'granted';
                let permission = alreadyGranted;
                if (!alreadyGranted) {
                    permission = await OneSignal.Notifications.requestPermission();
                    console.log('OneSignal bildirim izni:', permission);
                }
                if (permission) {
                    if (currentUser) {
                        window.OneSignalDeferred = window.OneSignalDeferred || [];
                        window.OneSignalDeferred.push(async function(OneSignal) {
                            try {
                                await OneSignal.login(currentUser.username);
                                console.log('✅ OneSignal login (izin sonrası):', currentUser.username);
                                // İzin verildi → subscription ID'yi hemen kaydet
                                await saveOneSignalPlayerId(OneSignal);
                            } catch(e) { console.error('OneSignal login hatası:', e); }
                        });
                    }
                }
                updateNotifBtnState();
            } catch(e) { console.error('OneSignal izin hatası:', e); }
        }

        // OneSignal subscription ID'sini backend'e kaydeder
        async function saveOneSignalPlayerId(OneSignal) {
            try {
                // Kisa bir bekleme — subscription aktif olana kadar
                await new Promise(r => setTimeout(r, 800));
                const subId = OneSignal.User.PushSubscription.id;
                if (!subId) {
                    console.warn('⚠️ OneSignal subscription ID henüz hazır değil');
                    return;
                }
                const resp = await fetch('/api/save_push_id', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ player_id: subId })
                });
                const result = await resp.json();
                if (result.status === 'ok') {
                    console.log('✅ OneSignal player_id kaydedildi:', subId.slice(0,20) + '...');
                } else {
                    console.warn('⚠️ player_id kaydedilemedi:', result);
                }
            } catch(e) {
                console.error('❌ saveOneSignalPlayerId hatası:', e);
            }
        }

        async function setOneSignalUser() {
            if(!currentUser) return;
            // OneSignalDeferred kuyruğunu kullan — SDK henüz init olmasa bile güvenli çalışır
            window.OneSignalDeferred = window.OneSignalDeferred || [];
            window.OneSignalDeferred.push(async function(OneSignal) {
                try {
                    await OneSignal.login(currentUser.username);
                    console.log('✅ OneSignal kullanıcı tanımlandı:', currentUser.username);
                    const permission = OneSignal.Notifications.permission;
                    console.log('🔔 OneSignal izin durumu:', permission);
                    // İzin varsa subscription ID'yi hemen kaydet
                    if (permission) {
                        await saveOneSignalPlayerId(OneSignal);
                    }
                } catch(e) {
                    console.error('❌ OneSignal login hatası:', e);
                }
            });
        }

        function getUserPremiumTier(username) { 
            const u = db.users.find(x => x.username === username); 
            if (!u || !u.stats) return 0; 
            return parseInt(u.stats.premium_tier) || 0; 
        }
        
        function getUserPremiumColor(username) { 
            const u = db.users.find(x => x.username === username); 
            if (!u || !u.stats || !u.stats.premium_tier) return null; 
            return u.stats.premium_color || 'std-blue'; 
        }
        
        function getPremiumTextClass(color) { 
            if(!color) return ''; 
            if(color.startsWith('#')) return ''; 
            
            const map = {
                'std-blue': 'text-blue-500 drop-shadow-[0_0_5px_rgba(59,130,246,0.6)]', 'std-yellow': 'text-yellow-500 drop-shadow-[0_0_5px_rgba(234,179,8,0.6)]', 'std-pink': 'text-pink-500 drop-shadow-[0_0_5px_rgba(236,72,153,0.6)]', 'std-green': 'text-green-500 drop-shadow-[0_0_5px_rgba(34,197,94,0.6)]',
                'dlx-blue': 'text-dlx-blue', 'dlx-yellow': 'text-dlx-yellow', 'dlx-pink': 'text-dlx-pink', 'dlx-green': 'text-dlx-green',
                'ult-gold': 'text-prem-gold', 'ult-rainbow': 'text-prem-rainbow',
                'ult-blue': 'text-prem-blue', 'ult-green': 'text-prem-green', 'ult-pink': 'text-prem-pink',
                'rainbow': 'text-prem-rainbow'
            };
            return map[color] || ''; 
        }

        function getPremiumInlineStyle(color) {
            if(color && color.startsWith('#')) {
                return `color: ${color} !important; text-shadow: 0 0 10px ${color}; font-weight: 800;`;
            }
            return '';
        }
        
        function getPremiumBorderClass(username) { 
            const u = db.users.find(x => x.username === username);
            if(!u || !u.stats) return 'border-zinc-700';
            
            let classes = "";
            let color = u.stats.premium_color || 'std-blue';
            let effect = u.stats.avatar_effect || 'none';

            if(effect === 'fire') classes += " effect-fire";
            if(effect === 'ice') classes += " effect-ice";

            if(!color.startsWith('#')) {
                const map = {
                    'std-blue': 'border-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.5)]', 'std-yellow': 'border-yellow-500 shadow-[0_0_10px_rgba(234,179,8,0.5)]', 'std-pink': 'border-pink-500 shadow-[0_0_10px_rgba(236,72,153,0.5)]', 'std-green': 'border-green-500 shadow-[0_0_10px_rgba(34,197,94,0.5)]',
                    'dlx-blue': 'border-dlx-blue', 'dlx-yellow': 'border-dlx-yellow', 'dlx-pink': 'border-dlx-pink', 'dlx-green': 'border-dlx-green',
                    'ult-gold': 'border-prem-gold', 'ult-rainbow': 'border-prem-rainbow',
                    'ult-blue': 'border-prem-blue', 'ult-green': 'border-prem-green', 'ult-pink': 'border-prem-pink',
                    'rainbow': 'border-prem-rainbow'
                };
                classes += " " + (map[color] || 'border-zinc-700');
            }
            return classes.trim() || 'border-zinc-700'; 
        }

        function createColorBtn(id, label, current) {
            const isActive = id === current;
            return `<button onclick="changeColor('${id}')" class="px-3 py-1.5 rounded-lg text-[10px] uppercase tracking-widest font-bold ${isActive ? 'bg-white text-black shadow-[0_0_10px_rgba(255,255,255,0.5)]' : 'bg-zinc-800 text-zinc-300'} border border-zinc-700 hover:bg-zinc-700 transition">${label}</button>`;
        }

        function createEffectBtn(id, label, current) {
            const isActive = id === current;
            return `<button onclick="changeEffect('${id}')" class="px-3 py-1.5 rounded-lg text-[10px] uppercase tracking-widest font-bold ${isActive ? 'bg-white text-black shadow-[0_0_10px_rgba(255,255,255,0.5)]' : 'bg-zinc-800 text-zinc-300'} border border-zinc-700 hover:bg-zinc-700 transition">${label}</button>`;
        }

        async function changeColor(colorId) {
            await sendAction('update_premium_color', { color: colorId, effect: currentUser.stats.avatar_effect || 'none' });
            if(currentUser && currentUser.stats) {
                currentUser.stats.premium_color = colorId;
            }
            updateProfileUI();
        }

        async function applyCustomHex() {
            const hex = document.getElementById("custom-hex-color").value;
            await changeColor(hex);
            alert("Yeni renginiz uygulandı!");
        }

        async function changeEffect(effectId) {
            await sendAction('update_premium_color', { color: currentUser.stats.premium_color || 'std-blue', effect: effectId });
            if(currentUser && currentUser.stats) {
                currentUser.stats.avatar_effect = effectId;
            }
            updateProfileUI();
            alert("Profil efektiniz uygulandı!");
        }

        let _myLastRank = null;

        function checkLeaderboardPosition(oldRank) {
            if(!currentUser || !db.users) return;
            const sorted = [...db.users].sort((a,b) => (b.xp||0)-(a.xp||0));
            const newRank = sorted.findIndex(u => u.username === currentUser.username) + 1;
            if(newRank > 0) {
                if(oldRank && newRank < oldRank) {
                    showRankToast(newRank, oldRank, 'up');
                } else if(oldRank && newRank > oldRank) {
                    showRankToast(newRank, oldRank, 'down');
                }
                _myLastRank = newRank;
            }
        }

        function showRankToast(newRank, oldRank, dir) {
            const isUp = dir === 'up';
            const toast = document.createElement('div');
            toast.className = 'fixed top-20 left-1/2 -translate-x-1/2 z-[99999] px-5 py-3 rounded-2xl font-bold text-sm shadow-2xl flex items-center gap-3 scale-in-anim';
            toast.style.background = isUp ? 'linear-gradient(135deg,#16a34a,#15803d)' : 'linear-gradient(135deg,#0ea5e9,#0284c7)';
            toast.style.color = '#fff';
            toast.innerHTML = (isUp ? '📈' : '📉') +
                `<div><div class="text-[10px] uppercase tracking-widest opacity-80">${isUp ? 'Sıralama Yükseldi!' : 'Sıralama Düştü!'}</div>` +
                `<div>${oldRank}. sira -> ${newRank}. sıra</div></div>`;
            document.body.appendChild(toast);
            haptic(isUp ? [30,20,30,20,50] : [100,50,100]);
            setTimeout(() => { toast.style.opacity='0'; toast.style.transition='opacity 0.4s'; setTimeout(()=>toast.remove(),400); }, 3000);
        }

        // Mobil titreşim geri bildirimi
        function haptic(pattern = [10]) {
            if('vibrate' in navigator) { try { navigator.vibrate(pattern); } catch(e) {} }
        }

        // ==============================================================
        // BİLDİRİM İZİN YÖNETİMİ (PROFİL BUTONU)
        // ==============================================================
        async function handleNotifPermission() {
            if (!('Notification' in window)) {
                alert("Bu tarayıcı bildirimleri desteklemiyor.");
                return;
            }
            if (Notification.permission === 'denied') {
                alert("Bildirim izni engellendi. Lütfen tarayıcı ayarlarından FreeriderTR için bildirimlere izin verin.");
                return;
            }
            haptic([10, 50, 10]);
            await requestPushPermission();
        }

        function updateNotifBtnState() {
            const btn = document.getElementById('notif-perm-btn');
            const icon = document.getElementById('notif-btn-icon');
            const txt = document.getElementById('notif-btn-text');
            if (!btn || !('Notification' in window)) return;
            if (Notification.permission === 'granted') {
                btn.className = 'w-full bg-green-900/40 border border-green-600/50 text-green-400 py-4 rounded-xl font-bold text-sm mt-4 btn-premium-hover flex items-center justify-center gap-2 transition-all';
                if (icon) icon.textContent = '✅';
                if (txt) txt.textContent = 'Bildirimler Açık';
            } else if (Notification.permission === 'denied') {
                btn.className = 'w-full bg-red-950/40 border border-sky-800/50 text-sky-300 py-4 rounded-xl font-bold text-sm mt-4 flex items-center justify-center gap-2 transition-all cursor-not-allowed';
                if (icon) icon.textContent = '🔕';
                if (txt) txt.textContent = 'Bildirimler Engellendi';
            } else {
                btn.className = 'w-full bg-zinc-900 border border-zinc-700 hover:bg-zinc-800 transition text-zinc-300 py-4 rounded-xl font-bold text-sm mt-4 btn-premium-hover flex items-center justify-center gap-2';
                if (icon) icon.textContent = '🔔';
                if (txt) txt.textContent = 'Bildirimleri Aç';
            }
        }

        // DUZELTME #3: sendAction — silent parametre eklendi.
        // Onceki kodda alert() + throw() birlikte kullaniliyordu:
        //   - alert() kullaniciya popup gosterir
        //   - throw() cagrilan yerin catch blogu TEKRAR hata isliyordu
        // Bu cift-hata dongusu butonlara basilinca donmaya yol aciyordu.
        // silent=true gecilirse alert bastiriliyor, sadece exception firlatiliyor.
        async function sendAction(action, data, silent = false) {
            let res;
            try {
                res = await fetch('/api/data', { 
                    method: 'POST', 
                    headers: { 'Content-Type': 'application/json' }, 
                    body: JSON.stringify({ action: action, data: data }) 
                });
            } catch(networkErr) {
                if(!silent) alert("Sunucuya ulasilamiyor. Internet baglantini kontrol et.");
                throw networkErr;
            }
            const result = await res.json(); 
            if(result.status === 'error') { 
                if(result.message === 'Giris yapmaniz gerekiyor!' || result.message === 'Giris yapmalisiniz!') {
                    alert("Sunucu guncellendi veya oturumun suresi doldu. Lutfen tekrar giris yap.");
                    logout();
                    return;
                }
                if(!silent) alert(result.message); 
                throw new Error(result.message); 
            } 
            return result;
        }

        async function loadData(silent = false) {
            try {
                const res = await fetch('/api/data'); 
                const newData = await res.json();
                
                // Mevcut mesajları koru (realtime + cache)
                const existingMessages = db.messages || [];
                const existingDms = db.dms || [];
                
                db = newData;
                
                // Tüm array alanlarını garantile
                if(!db.stories)  db.stories  = [];
                if(!db.messages) db.messages = [];
                if(!db.dms)      db.dms      = [];
                if(!db.users)    db.users    = [];
                if(!db.markers)  db.markers  = [];
                if(!db.market)   db.market   = [];
                if(!db.events)   db.events   = [];
                if(!db.news)     db.news     = [];
                if(!db.banned)   db.banned   = [];
                
                // Sunucu boş veya az dönerse mevcut mesajları koru
                existingMessages.forEach(m => {
                    if(!db.messages.find(x => x.id === m.id)) db.messages.push(m);
                });
                existingDms.forEach(m => {
                    if(!db.dms.find(x => x.id === m.id)) db.dms.push(m);
                });
                
                // Mesajları ID'ye göre sırala
                db.messages.sort((a,b) => (parseInt(a.id)||0) - (parseInt(b.id)||0));
                
                // LocalStorage'a yedekle
                try {
                    localStorage.setItem('fr_msg_cache', JSON.stringify(db.messages.slice(-50)));
                } catch(e) {}
                
                if (currentUser) {
                    const me = db.users.find(u => u.username === currentUser.username);
                    if (me) { 
                        const oldRank = _myLastRank;
                        currentUser = me; 
                        localStorage.setItem("fr_user", JSON.stringify(currentUser)); 
                        updateProfileUI(); 
                        checkMissions();
                        checkLeaderboardPosition(oldRank); 
                        
                        // Referans sekmesi açıksa hemen güncelle
                        if(!document.getElementById('screen-referral').classList.contains('hidden')) {
                            renderReferralTab();
                        }
                    }
                    if (db.banned.includes(currentUser.username) || (db.maintenance && currentUser.role !== 'Admin')) {
                        logout(); 
                    }
                }
                
                if(currentMarkerId && !document.getElementById("marker-sheet").classList.contains("hidden")) {
                    const m = db.markers.find(x => x.id === currentMarkerId);
                    if(m) showMarkerSheet(m, true);
                }
                if(currentEventId && !document.getElementById("event-sheet").classList.contains("hidden")) {
                    const e = db.events.find(x => x.id === currentEventId);
                    if(e) showEventSheet(e);
                }

                // Kullanıcı sayacı güncellemesi
                updateUserCountDisplays();
                
                if(!silent) syncMap();
                return true;
            } catch(e) { 
                console.error("Veri çekme hatası:", e);
                return false; 
            }
        }

        function updateUserCountDisplays() {
            const total = db.total_users || 300;
            const active = db.active_users || 0;
            // Login ekranı
            const la = document.getElementById('login-active-users');
            const lt = document.getElementById('login-total-users');
            if(la) la.textContent = active;
            if(lt) lt.textContent = total.toLocaleString('tr-TR');
            // Leaderboard
            const ra = document.getElementById('rank-active-users');
            const rt = document.getElementById('rank-total-users');
            if(ra) ra.textContent = active;
            if(rt) rt.textContent = total.toLocaleString('tr-TR');
        }
        
        async function fetchWeather(lat, lon) {
            try {
                const response = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current_weather=true&timezone=auto`);
                const data = await response.json();
                if (data && data.current_weather) {
                    const temp = Math.round(data.current_weather.temperature);
                    const code = data.current_weather.weathercode;
                    const weatherMap = {
                        0: {icon: "☀️", desc: "Açık"}, 1: {icon: "🌤️", desc: "Az Bulutlu"},
                        2: {icon: "⛅", desc: "Parçalı"}, 3: {icon: "☁️", desc: "Bulutlu"},
                        45: {icon: "🌫️", desc: "Sisli"}, 61: {icon: "🌧️", desc: "Yağmurlu"},
                        63: {icon: "🌧️", desc: "Yoğun Yağmur"}, 71: {icon: "❄️", desc: "Karlı"},
                        80: {icon: "🌦️", desc: "Sağanak"}, 95: {icon: "⛈️", desc: "Fırtına"}
                    };
                    const status = weatherMap[code] || {icon: "🌡️", desc: "Bilinmiyor"};
                    // Update sidebar weather
                    const sidebarW = document.getElementById("sidebar-weather");
                    if(sidebarW) {
                        sidebarW.classList.remove("hidden");
                        document.getElementById("sidebar-weather-icon").textContent = status.icon;
                        document.getElementById("sidebar-weather-temp").textContent = temp + "°C";
                        document.getElementById("sidebar-weather-desc").textContent = status.desc;
                    }
                    // Update missions ride card if it still exists
                    const rideCard = document.getElementById('weather-ride-card');
                    if(rideCard) {
                        updateWeatherWidget(temp, code);
                    }
                    // Also update old weather-widget if present
                    const widget = document.getElementById("weather-widget");
                    if(widget) { widget.style.display = "flex"; widget.classList.remove("hidden"); }
                    if(document.getElementById("weather-icon")) document.getElementById("weather-icon").innerText = status.icon;
                    if(document.getElementById("weather-desc")) document.getElementById("weather-desc").innerText = status.desc;
                }
            } catch (e) { console.log("Hava durumu hatası:", e); }
        }

        function updateMyLocation() {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition((position) => {
                    const { latitude, longitude } = position.coords;
                    userLat = latitude;
                    userLng = longitude;
                    fetchWeather(latitude, longitude);
                    if(typeof sendLocationToSupabase === "function") {
                        sendLocationToSupabase(latitude, longitude);
                    }
                    if (currentUser && currentUser.stats && currentUser.stats.riding_until > Date.now()) {
                        sendAction('update_user', {
                            username: currentUser.username,
                            stats: { ...currentUser.stats, riding_lat: latitude, riding_lng: longitude }
                        }).catch(e => {});
                    }
                }, (error) => { console.log("Konum izni alinamadi."); });
            }
        }

        window.onload = async function() {
            const savedUsername = localStorage.getItem("fr_remembered_username");
            const savedPasswordEncoded = localStorage.getItem("fr_remembered_password");
            
            // Şifreyi decode et (base64) — eski düz metin kayıtları da çalışsın
            let savedPassword = null;
            if (savedPasswordEncoded) {
                try {
                    savedPassword = decodeURIComponent(escape(atob(savedPasswordEncoded)));
                } catch(e) {
                    // Eski düz metin kaydı ise direkt kullan (geçiş dönemi)
                    savedPassword = savedPasswordEncoded;
                }
            }
            
            if(savedUsername && savedPassword) { 
                document.getElementById("login-username").value = savedUsername; 
                document.getElementById("login-password").value = savedPassword; 
                document.getElementById("remember-me").checked = true; 
            }
            
            // DUZELTME #2: loadData hata firlatsa bile loading screen kapatilmali.
            // Onceki kodda await loadData() exception atarsa asagisi hic calismiyor,
            // ekran sonsuza kadar "Yukleniyor" modunda kaliyordu.
            try {
                await loadData(true);
            } catch(e) {
                console.error("[FreeriderTR] loadData basarisiz:", e);
            } finally {
                // Her durumda (hata olsa da) loading screen'i kapat
                const loadScreen = document.getElementById("app-loading-screen");
                if(loadScreen) {
                    loadScreen.style.opacity = "0";
                    setTimeout(() => { loadScreen.style.display = "none"; }, 500);
                }
            }
            
            if (savedUsername && savedPassword) {
                try {
                    const res = await sendAction('login', { username: savedUsername, password: savedPassword });
                    if(res && res.status === 'ok') {
                        currentUser = res.user;
                        window.currentUser = currentUser; // OneSignal callback için global'e de yaz
                        localStorage.setItem("fr_user", JSON.stringify(currentUser));
                        // Şifreyi güncel encode edilmiş haliyle tekrar kaydet
                        localStorage.setItem("fr_remembered_password", btoa(unescape(encodeURIComponent(savedPassword))));
                        if(res.user.just_got_daily) {
                            alert("🎉 Harika! Günlük giriş ödülü olarak +" + res.user.just_got_daily + " XP kazandın.");
                        }
                        loginSuccess();
                    } else {
                        // Şifre değişmiş veya hatalı — kayıtlı bilgileri temizle
                        localStorage.removeItem("fr_remembered_username");
                        localStorage.removeItem("fr_remembered_password");
                        document.getElementById("login-username").value = "";
                        document.getElementById("login-password").value = "";
                        document.getElementById("remember-me").checked = false;
                    }
                } catch(e) {
                    // Hata durumunda da temizle
                    localStorage.removeItem("fr_remembered_username");
                    localStorage.removeItem("fr_remembered_password");
                    document.getElementById("login-username").value = "";
                    document.getElementById("login-password").value = "";
                    document.getElementById("remember-me").checked = false;
                }
            }

            // ============================================================
            // AKILLI REALTIME SİSTEMİ
            // Tek kanal = tek bağlantı = 200 limit yerine 1 slot kullanır
            // Sayfa arka plana geçince bağlantı kesilir, öne gelince tekrar açılır
            // ============================================================
            let _realtimeChannel = null;
            let _realtimePaused = false;

            function startRealtime() {
                if (_realtimeChannel) {
                    try { supaClient.removeChannel(_realtimeChannel); } catch(e) {}
                }
                _realtimeChannel = supaClient.channel('fr-main', {
                    config: { broadcast: { self: false } }
                })
                // ---- MESAJLAR ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'messages' }, payload => {
                    if(!currentUser) return;
                    if(!db.messages) db.messages = [];
                    if (payload.eventType === 'INSERT' && payload.new) {
                        if (!db.messages.find(m => m.id === payload.new.id)) {
                            db.messages.push(payload.new);
                        }
                    } else if (payload.eventType === 'DELETE' && payload.old) {
                        db.messages = db.messages.filter(m => m.id !== payload.old.id);
                    } else if (payload.eventType === 'UPDATE' && payload.new) {
                        const idx = db.messages.findIndex(m => m.id === payload.new.id);
                        if (idx !== -1) {
                            // Eksik alanları eski veriden koru (REPLICA IDENTITY olmadan tam gelmiyor olabilir)
                            db.messages[idx] = { ...db.messages[idx], ...payload.new };
                        }
                    }
                    const chatVisible = !document.getElementById('screen-chat').classList.contains('hidden');
                    if (chatVisible) {
                        renderChat(true);
                        if (payload.eventType === 'INSERT' && payload.new && payload.new.user !== currentUser.username) {
                            try { document.getElementById("notif-sound").play().catch(e => {}); } catch(e) {}
                        }
                    } else if (payload.eventType === 'INSERT' && payload.new && payload.new.user !== currentUser.username) {
                        showChatBadge();
                        try { document.getElementById("notif-sound").play().catch(e => {}); } catch(e) {}
                    }
                })
                // ---- DM ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'dms' }, payload => {
                    if(!currentUser) return;
                    if (payload.eventType === 'INSERT') {
                        if (payload.new.participants && payload.new.participants.includes(currentUser.username)) {
                            if (!db.dms.find(m => m.id === payload.new.id)) db.dms.push(payload.new);
                            // DM badge göster (chat açık değilse)
                            const chatVisible = !document.getElementById('screen-chat').classList.contains('hidden');
                            if (!chatVisible && payload.new.sender !== currentUser.username) showChatBadge();
                        }
                    } else if (payload.eventType === 'DELETE') {
                        db.dms = db.dms.filter(m => m.id !== payload.old.id);
                    }
                    renderDmList();
                    if (currentDmUser) renderDmThread(currentDmUser);
                })
                // ---- HARİTA NOKTALARI ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'markers' }, payload => {
                    if(!currentUser) return;
                    if (payload.eventType === 'INSERT') {
                        if (!db.markers.find(m => m.id === payload.new.id)) db.markers.push(payload.new);
                    } else if (payload.eventType === 'DELETE') {
                        db.markers = db.markers.filter(m => m.id !== payload.old.id);
                    } else if (payload.eventType === 'UPDATE') {
                        const idx = db.markers.findIndex(m => m.id === payload.new.id);
                        if (idx !== -1) db.markers[idx] = payload.new;
                    }
                    if (map) syncMap();
                    if (payload.new && currentMarkerId === payload.new.id && !document.getElementById("marker-sheet").classList.contains("hidden")) {
                        showMarkerSheet(payload.new, true);
                    }
                })
                // ---- PAZAR ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'market' }, payload => {
                    if(!currentUser) return;
                    if (payload.eventType === 'INSERT') {
                        if (!db.market.find(m => m.id === payload.new.id)) db.market.unshift(payload.new);
                    } else if (payload.eventType === 'DELETE') {
                        db.market = db.market.filter(m => m.id !== payload.old.id);
                    } else if (payload.eventType === 'UPDATE') {
                        const idx = db.market.findIndex(m => m.id === payload.new.id);
                        if (idx !== -1) db.market[idx] = payload.new;
                    }
                    if (!document.getElementById('screen-market').classList.contains('hidden')) renderMarket();
                })
                // ---- STORY ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'stories' }, payload => {
                    if(!currentUser) return;
                    if(!db.stories) db.stories = [];
                    const now = Math.floor(Date.now()/1000);
                    if (payload.eventType === 'INSERT' && payload.new.expires_at > now) {
                        if (!db.stories.find(s => s.id === payload.new.id)) db.stories.unshift(payload.new);
                    } else if (payload.eventType === 'DELETE') {
                        db.stories = db.stories.filter(s => s.id !== payload.old.id);
                    }
                    if (!document.getElementById('screen-chat').classList.contains('hidden')) renderStoryBar();
                })
                // ---- ETKİNLİKLER ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'events' }, payload => {
                    if(!currentUser) return;
                    if (payload.eventType === 'INSERT') {
                        if (!db.events.find(e => e.id === payload.new.id)) db.events.push(payload.new);
                    } else if (payload.eventType === 'DELETE') {
                        db.events = db.events.filter(e => e.id !== payload.old.id);
                    } else if (payload.eventType === 'UPDATE') {
                        const idx = db.events.findIndex(e => e.id === payload.new.id);
                        if (idx !== -1) db.events[idx] = payload.new;
                    }
                    if (map) syncMap();
                    if (payload.new && currentEventId === payload.new.id && !document.getElementById("event-sheet").classList.contains("hidden")) {
                        showEventSheet(payload.new);
                    }
                })
                // ---- KULLANICILAR (XP, online, premium) ----
                .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'users' }, payload => {
                    if(!currentUser) return;
                    const updated = payload.new;
                    const idx = db.users.findIndex(u => u.username === updated.username);
                    if (idx !== -1) {
                        // Kendi verimizi tam güncelle, başkalarının garage'ini alma
                        if (updated.username === currentUser.username) {
                            db.users[idx] = updated;
                            currentUser = updated;
                            localStorage.setItem("fr_user", JSON.stringify(currentUser));
                            updateProfileUI();
                            checkMissions();
                        } else {
                            // Başkası için sadece temel alanlar
                            db.users[idx] = {
                                ...db.users[idx],
                                xp: updated.xp,
                                stats: { ...(updated.stats || {}), garage: db.users[idx]?.stats?.garage },
                                avatar: updated.avatar,
                                role: updated.role
                            };
                        }
                    } else if (updated.username !== currentUser.username) {
                        db.users.push(updated);
                    }
                    // Lider tablosu açıksa güncelle
                    if (!document.getElementById('screen-rank').classList.contains('hidden')) renderLeaderboard();
                })
                // ---- YASAKLI KULLANICILAR ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'banned' }, payload => {
                    if(!currentUser) return;
                    if (payload.eventType === 'INSERT') {
                        if (!db.banned.includes(payload.new.username)) db.banned.push(payload.new.username);
                        // Kendi hesabım banlandıysa çıkış yap
                        if (payload.new.username === currentUser.username) {
                            alert("Hesabınız banlanmıştır!");
                            logout();
                        }
                    } else if (payload.eventType === 'DELETE') {
                        db.banned = db.banned.filter(u => u !== payload.old.username);
                    }
                })
                // ---- HABERLER ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'news' }, payload => {
                    if(!currentUser) return;
                    if (payload.eventType === 'INSERT') {
                        if (!db.news.find(n => n.id === payload.new.id)) db.news.unshift(payload.new);
                    } else if (payload.eventType === 'DELETE') {
                        db.news = db.news.filter(n => n.id !== payload.old.id);
                    }
                    if (!document.getElementById('screen-news').classList.contains('hidden')) renderNews();
                })
                // ---- AYARLAR (pinned mesaj, bakım modu) ----
                .on('postgres_changes', { event: '*', schema: 'public', table: 'settings' }, payload => {
                    if(!currentUser) return;
                    if (payload.new && payload.new.id === 'pinned_message') {
                        try {
                            db.pinned_message = JSON.parse(payload.new.value || '{}');
                            renderChat(true);
                        } catch(e) {}
                    }
                    if (payload.new && payload.new.id === 'maintenance') {
                        db.maintenance = payload.new.value === 'true';
                        if (db.maintenance && currentUser.role !== 'Admin' && currentUser.role !== 'SubAdmin') {
                            alert("Sistem bakım moduna alındı. Lütfen daha sonra tekrar deneyin.");
                            logout();
                        }
                    }
                })
                .subscribe((status) => {
                    if (status === 'SUBSCRIBED') {
                        console.log('✅ Realtime bağlantısı kuruldu');
                        _realtimePaused = false;
                    } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
                        console.log('⚠️ Realtime bağlantısı kesildi, 5sn sonra tekrar denenecek...');
                        setTimeout(() => { if(!_realtimePaused) startRealtime(); }, 5000);
                    }
                });
            }

            // Sayfa görünürlüğü değişince bağlantıyı yönet (200 limit koruması)
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    // Sayfa arka plana geçti - bağlantıyı kapat, slot serbest bırak
                    _realtimePaused = true;
                    if (_realtimeChannel) {
                        try { supaClient.removeChannel(_realtimeChannel); _realtimeChannel = null; } catch(e) {}
                    }
                } else {
                    // Sayfa öne geldi - yeniden bağlan ve son veriyi çek
                    _realtimePaused = false;
                    startRealtime();
                    loadData(true); // Arka planda kaçırılan güncellemeleri al
                }
            });

            // İlk bağlantıyı kur
            startRealtime();

            // ── Çevrimdışı / Çevrimiçi Bildirimi ──
            function showOfflineBanner() {
                let b = document.getElementById('offline-banner');
                if (!b) {
                    b = document.createElement('div');
                    b.id = 'offline-banner';
                    b.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;background:#0284c7;color:#fff;text-align:center;padding:8px 16px;font-size:12px;font-weight:900;letter-spacing:0.05em;text-transform:uppercase;';
                    b.textContent = '📵 İnternet bağlantısı yok — Önbellek modunda çalışıyor';
                    document.body.appendChild(b);
                }
            }
            function hideOfflineBanner() {
                const b = document.getElementById('offline-banner');
                if (b) b.remove();
            }
            window.addEventListener('offline', showOfflineBanner);
            window.addEventListener('online', () => {
                hideOfflineBanner();
                loadData(true);
            });
            if (!navigator.onLine) showOfflineBanner();
        };

        // YANDAN AÇILIR MENÜ (SIDEBAR) FONKSİYONU
        function toggleSidebar() {
            const sidebar = document.getElementById("sidebar");
            const overlay = document.getElementById("sidebar-overlay");
            if(sidebar.classList.contains("-translate-x-full")) {
                sidebar.classList.remove("-translate-x-full");
                overlay.classList.remove("hidden");
                setTimeout(() => { overlay.style.opacity = "1"; }, 10);
            } else {
                sidebar.classList.add("-translate-x-full");
                overlay.style.opacity = "0";
                setTimeout(() => { overlay.classList.add("hidden"); }, 300);
            }
        }

        // =========================================================
        // HARİTA FONKSİYONU
        // =========================================================
        function initMap() {
            if(map) return;
            
            map = L.map('map', { 
                zoomControl: false,
                preferCanvas: true,
                tap: true,
                tapTolerance: 15,
                touchZoom: true,
                bounceAtZoomLimits: false,
                maxBoundsViscosity: 0.0
            }).setView([39.0, 35.0], 6);

            // Yol haritası — CartoDB Dark (temiz, koyu tema, MTB uyumlu)
            var roads = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                subdomains: 'abcd',
                maxZoom: 22,
                maxNativeZoom: 19,
                attribution: '© <a href="https://carto.com">CARTO</a> © <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            });

            // Uydu görüntüsü — ESRI World Imagery + etiketler üst katman
            var satelliteBase = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
                maxZoom: 22,
                maxNativeZoom: 19,
                attribution: '© <a href="https://www.esri.com">Esri</a>, Maxar'
            });
            var satelliteLabels = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png', {
                subdomains: 'abcd',
                maxZoom: 22,
                maxNativeZoom: 19,
                opacity: 0.8,
                pane: 'shadowPane'
            });
            var satellite = L.layerGroup([satelliteBase, satelliteLabels]);

            satellite.addTo(map);

            var baseMaps = {
                "🛰️ Uydu + Etiketler": satellite,
                "🌑 Koyu Harita": roads
            };

            L.control.layers(baseMaps, null, { 
                collapsed: false, 
                position: 'topright' 
            }).addTo(map);

            // Zoom butonları — sağ alt, parmak dostu
            L.control.zoom({ position: 'bottomright' }).addTo(map);

            if (typeof L.Control.Geocoder !== 'undefined') {
                L.Control.geocoder({
                    defaultMarkGeocode: true,
                    placeholder: "Yer veya Rampa ara...",
                }).addTo(map);
            }

            syncMap();
            autoZoomToUserLocation();
            
            map.on('click', function(e) { 
                if(!isAddingMarkerMode && !isAddingEventMode) return;
                tempLat = e.latlng.lat; 
                tempLng = e.latlng.lng; 
                if (isAddingMarkerMode) { 
                    toggleAddMarkerMode(); 
                    openAddMarkerModal(); 
                } else if (isAddingEventMode) { 
                    toggleAddEventMode(); 
                    openAddEventModal(); 
                } 
            });
        }

        // =========================================================
        // E-POSTA DOĞRULAMA FONKSİYONLARI
        // =========================================================
        function skipVerification() {
            document.getElementById("email-verify-modal").classList.add("hidden");
            if(!currentUser) {
                alert("Kayıt tamamlandı, ancak e-postanız henüz doğrulanmadı. Daha sonra 'Profil' menüsünden doğrulayabilirsiniz.");
                showLoginTab();
                document.getElementById("login-username").value = verificationUsername;
            }
        }

        async function submitVerificationCode() {
            const code = document.getElementById("verify-code-input").value;
            if(!code || code.length !== 6) return alert("Lütfen geçerli bir 6 haneli kod girin.");
            
            try {
                await sendAction('verify_email', { username: verificationUsername || currentUser?.username, code: code });
                alert("E-posta adresiniz başarıyla doğrulandı!");
                document.getElementById("email-verify-modal").classList.add("hidden");
                
                if(!currentUser) { 
                    showLoginTab();
                    document.getElementById("login-username").value = verificationUsername;
                } else { 
                    await loadData(true);
                    openSettingsModal();
                }
            } catch(e) {}
        }

        async function completeOnboarding() {
            document.getElementById("onboarding-modal").classList.add("hidden");
            if (currentUser && currentUser.stats) {
                currentUser.stats.onboarding = true;
                await sendAction('update_user', currentUser);
            }
        }

        async function checkMissions() {
            if(!currentUser || !currentUser.stats) return;
            let stats = currentUser.stats;
            if(!stats.missions)        stats.missions        = {};
            if(!stats.daily_missions)  stats.daily_missions  = {};
            if(!stats.weekly_missions) stats.weekly_missions = {};

            const dailyData  = getDailyMissions();
            const weeklyData = getWeeklyMissions();
            const todayKey   = dailyData.key;
            const weekKey    = weeklyData.key;

            // Günlük sıfırlama
            if(stats.daily_missions.date !== todayKey) {
                stats.daily_missions = { date: todayKey, daily_login: 1 };
            }
            // Haftalık sıfırlama
            if(stats.weekly_missions.week !== weekKey) {
                stats.weekly_missions = { week: weekKey };
            }

            // Sunucuya claim isteği gönderen yardımcı
            async function claimOnServer(mission_type, mission_id, xp) {
                try {
                    const res = await sendAction('claim_mission', { mission_type, mission_id, xp });
                    if(res && res.status === 'ok' && res.earned_xp > 0) {
                        currentUser.xp = res.new_xp;
                        stats.monthly_xp = (stats.monthly_xp || 0) + res.earned_xp;
                        stats.weekly_xp  = (stats.weekly_xp  || 0) + res.earned_xp;
                        return 'claimed';
                    }
                    if(res && res.status === 'ok' && res.already_done) return 'already_done';
                    if(res && res.status === 'ok' && res.not_ready) return 'not_ready';
                } catch(e) {}
                return 'error';
            }

            // --- Kalıcı görevler ---
            for(let m of MISSIONS) {
                if(!stats.missions[m.id]) {
                    let progress = stats[m.type] || 0;
                    if(progress >= m.target) {
                        const result = await claimOnServer('perm', m.id, m.xp);
                        if(result === 'claimed') {
                            stats.missions[m.id] = true;
                            if(m.badge) {
                                if(!stats.earned_badges) stats.earned_badges = [];
                                if(!stats.earned_badges.includes(m.badge)) stats.earned_badges.push(m.badge);
                            }
                            showMissionToast(m.title, m.xp, m.icon);
                        } else if(result === 'already_done') {
                            stats.missions[m.id] = true; // local senkronize et, toast yok
                        }
                    }
                }
            }

            // --- Günlük görevler ---
            for(let m of dailyData.missions) {
                const doneKey = 'done_' + m.id;
                if(!stats.daily_missions[doneKey]) {
                    let progress = m.type === 'daily_login' ? 1 : (stats.daily_missions[m.type] || 0);
                    if(progress >= m.target) {
                        const result = await claimOnServer('daily', m.id, m.xp);
                        if(result === 'claimed') {
                            stats.daily_missions[doneKey] = true;
                            showMissionToast(m.title + ' (Günlük)', m.xp, m.icon);
                        } else if(result === 'already_done') {
                            stats.daily_missions[doneKey] = true; // sessiz senkronize
                        }
                    }
                }
            }

            // --- Haftalık görevler ---
            for(let m of weeklyData.missions) {
                const doneKey = 'done_' + m.id;
                if(!stats.weekly_missions[doneKey]) {
                    let progress = stats.weekly_missions[m.type] || 0;
                    if(progress >= m.target) {
                        const result = await claimOnServer('weekly', m.id, m.xp);
                        if(result === 'claimed') {
                            stats.weekly_missions[doneKey] = true;
                            showMissionToast(m.title + ' (Haftalık)', m.xp, m.icon);
                        } else if(result === 'already_done') {
                            stats.weekly_missions[doneKey] = true; // sessiz senkronize
                        }
                    }
                }
            }

            updateProfileUI();
            renderMissions();
        }

        // ============================================================
        // STORY SİSTEMİ
        // ============================================================
        let _storyIndex = 0;
        let _storyList = [];
        let _storyTimer = null;

        function renderStoryBar() {
            const bar = document.getElementById('story-items');
            if(!bar || !db.stories) return;
            bar.innerHTML = '';
            const now = Math.floor(Date.now()/1000);
            const active = db.stories.filter(s => s.expires_at > now);
            if(active.length === 0) { bar.innerHTML = '<div class="text-[10px] text-zinc-600 flex items-center h-14 font-medium">Henuz story yok</div>'; return; }
            active.forEach((s, i) => {
                const u = db.users.find(x => x.username === s.user);
                const avatar = u ? u.avatar : 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg';
                const seen = s.viewers && s.viewers.includes(currentUser.username);
                const premBorder = getUserPremiumTier(s.user) > 0 ? getPremiumBorderClass(s.user) : '';
                bar.innerHTML += `
                <div onclick="viewStory(${i})" class="flex flex-col items-center gap-1 shrink-0 cursor-pointer">
                    <div class="w-14 h-14 rounded-full overflow-hidden ${seen ? 'story-seen' : 'story-ring'} ${premBorder}">
                        <img src="${avatar}" class="w-full h-full object-cover">
                    </div>
                    <span class="text-[9px] font-bold uppercase tracking-widest max-w-[56px] truncate ${seen ? 'text-zinc-600' : 'text-zinc-400'}">${s.user}</span>
                </div>`;
            });
        }

        function viewStory(startIndex) {
            _storyList = db.stories.filter(s => s.expires_at > Math.floor(Date.now()/1000));
            _storyIndex = startIndex;
            showCurrentStory();
            document.getElementById('story-view-modal').classList.remove('hidden');
        }

        function showCurrentStory() {
            if(_storyTimer) clearTimeout(_storyTimer);
            const s = _storyList[_storyIndex];
            if(!s) { closeStoryView(); return; }
            const u = db.users.find(x => x.username === s.user);
            const avatar = u ? u.avatar : 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg';
            document.getElementById('story-view-avatar').src = avatar;
            document.getElementById('story-view-username').textContent = s.user;
            const secsAgo = Math.floor(Date.now()/1000) - s.created_at;
            document.getElementById('story-view-time').textContent = secsAgo < 3600 ? Math.floor(secsAgo/60) + ' dk once' : Math.floor(secsAgo/3600) + ' saat once';
            const imgEl = document.getElementById('story-view-img');
            const txtEl = document.getElementById('story-view-text');
            if(s.image) { imgEl.src = s.image; imgEl.style.display='block'; txtEl.style.display='none'; }
            else { imgEl.style.display='none'; txtEl.style.display='flex'; document.getElementById('story-view-text-content').textContent = s.text; }
            const viewers = s.viewers || [];
            document.getElementById('story-viewer-count').textContent = viewers.length + ' kisi izledi';
            // Progress bars
            const pbContainer = document.getElementById('story-progress-bars');
            pbContainer.innerHTML = '';
            _storyList.forEach((_, i) => {
                const pb = document.createElement('div');
                pb.style.cssText = 'flex:1;height:3px;background:rgba(255,255,255,0.3);border-radius:3px;overflow:hidden;';
                const fill = document.createElement('div');
                fill.style.cssText = 'height:100%;background:#fff;border-radius:3px;';
                fill.style.width = i < _storyIndex ? '100%' : (i === _storyIndex ? '0%' : '0%');
                if(i === _storyIndex) { fill.style.transition = 'width 5s linear'; setTimeout(()=>fill.style.width='100%', 50); }
                pb.appendChild(fill); pbContainer.appendChild(pb);
            });
            // Show delete btn for own stories
            const delBtn = document.getElementById('story-delete-btn');
            if(delBtn) {
                if(s.user === currentUser.username || (currentUser.role === 'Admin')) {
                    delBtn.classList.remove('hidden');
                } else {
                    delBtn.classList.add('hidden');
                }
            }
            // Mark as viewed
            sendAction('view_story', {id: s.id}).catch(()=>{});
            // Auto advance
            _storyTimer = setTimeout(() => { _storyIndex++; showCurrentStory(); }, 5000);
        }

        async function deleteCurrentStory() {
            const s = _storyList[_storyIndex];
            if(!s) return;
            if(!confirm("Bu story'yi silmek istiyor musun?")) return;
            await sendAction('delete_story', { id: s.id });
            _storyList.splice(_storyIndex, 1);
            if(_storyList.length === 0) { closeStoryView(); return; }
            if(_storyIndex >= _storyList.length) _storyIndex = _storyList.length - 1;
            showCurrentStory();
        }

        function closeStoryView() {
            if(_storyTimer) clearTimeout(_storyTimer);
            document.getElementById('story-view-modal').classList.add('hidden');
            renderStoryBar();
        }

        document.addEventListener('DOMContentLoaded', () => {
            const sv = document.getElementById('story-view-modal');
            if(sv) {
                sv.addEventListener('click', (e) => {
                    // DUZELTME #5: currentUser henuz null iken tiklanirsa race condition olusur
                    if(!currentUser) return;
                    const rect = sv.getBoundingClientRect();
                    if(e.clientX < rect.width/2) { _storyIndex = Math.max(0,_storyIndex-1); showCurrentStory(); }
                    else { _storyIndex++; showCurrentStory(); }
                });
            }
        });

        function openAddStoryModal() {
            const premTier = getUserPremiumTier(currentUser.username);
            if(premTier < 1) {
                alert('Story paylasabilmek icin Standart, Deluxe veya Ultra+ uyelik gereklidir!');
                switchTab(6); return;
            }
            document.getElementById('add-story-modal').classList.remove('hidden');
        }

        async function submitStory() {
            const text = document.getElementById('story-text-input').value.trim();
            const file = document.getElementById('story-photo-input').files[0];
            if(!text && !file) return alert('Lutfen bir metin veya fotograf ekleyin!');
            let img = '';
            if(file) { img = await resizeImage(file, 1200); }
            await sendAction('add_story', { text, image: img });
            document.getElementById('add-story-modal').classList.add('hidden');
            document.getElementById('story-text-input').value = '';
            document.getElementById('story-photo-input').value = '';
        }

        // ============================================================
        // YORUM SİSTEMİ
        // ============================================================
        let _commentTargetType = '';
        let _commentTargetId = '';

        async function openComments(targetType, targetId) {
            if(!targetId) return;
            _commentTargetType = targetType;
            _commentTargetId = targetId;
            const label = targetType === 'marker' ? 'Rampa Yorumları' : 'Etkinlik Yorumları';
            document.getElementById('comment-modal-title').innerHTML = '💬 ' + label;
            document.getElementById('comment-list').innerHTML = '<div class="text-zinc-500 text-xs text-center py-4 animate-pulse">Yorumlar yükleniyor...</div>';
            document.getElementById('comment-modal').classList.remove('hidden');
            try {
                const res = await sendAction('get_comments', { target_id: targetId });
                renderComments(res.comments || []);
            } catch(e) { document.getElementById('comment-list').innerHTML = '<div class="text-zinc-500 text-xs text-center py-4">Yorum yuklenemedi.</div>'; }
        }

        function renderComments(comments) {
            const c = document.getElementById('comment-list');
            if(comments.length === 0) {
                c.innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-6">Henuz yorum yok. Ilk yorumu sen yaz!</div>';
                return;
            }
            c.innerHTML = '';
            comments.forEach(cm => {
                const u = db.users.find(x => x.username === cm.user);
                const avatar = u ? u.avatar : 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg';
                const isMe = cm.user === currentUser.username;
                const isAdmin2 = currentUser.role === 'Admin';
                const delBtn = (isMe || isAdmin2) ? `<button onclick="deleteComment('${cm.id}')" class="text-[9px] text-sky-400 hover:text-sky-300 ml-2">sil</button>` : '';
                const secsAgo = Math.floor(Date.now()/1000) - cm.created_at;
                const timeStr = secsAgo < 60 ? 'az once' : secsAgo < 3600 ? Math.floor(secsAgo/60)+' dk' : Math.floor(secsAgo/3600)+' saat';
                c.innerHTML += `<div class="flex gap-3 items-start slide-up-anim">
                    <img src="${avatar}" class="w-9 h-9 rounded-full object-cover border border-zinc-700 shrink-0 cursor-pointer" onclick="showOtherProfile('${cm.user}')">
                    <div class="flex-1 bg-black/40 rounded-2xl px-3 py-2 border border-zinc-800">
                        <div class="flex items-center justify-between">
                            <span class="text-xs font-bold text-white cursor-pointer hover:text-zinc-300" onclick="showOtherProfile('${cm.user}')">${cm.user}</span>
                            <span class="text-[9px] text-zinc-600">${timeStr} ${delBtn}</span>
                        </div>
                        <div class="text-sm text-zinc-300 mt-1 leading-relaxed">${cm.text}</div>
                    </div>
                </div>`;
            });
            c.scrollTop = c.scrollHeight;
        }

        async function submitComment() {
            const inp = document.getElementById('comment-input');
            const text = inp.value.trim();
            if(!text) return;
            inp.value = '';
            await sendAction('add_comment', { target_type: _commentTargetType, target_id: _commentTargetId, text });
            const res = await sendAction('get_comments', { target_id: _commentTargetId });
            renderComments(res.comments || []);
        }

        async function deleteComment(id) {
            await sendAction('delete_comment', { id });
            const res = await sendAction('get_comments', { target_id: _commentTargetId });
            renderComments(res.comments || []);
        }

        // ============================================================
        // SEVİYE ATLAMA KUTLAMA ANİMASYONU
        // ============================================================
        let _lastTitleName = null;

        function checkLevelUp() {
            if(!currentUser) return;
            const title = getTitle(currentUser.xp);
            if(_lastTitleName && _lastTitleName !== title.name) {
                showLevelUpAnimation(title);
            }
            _lastTitleName = title.name;
        }

        function showLevelUpAnimation(title) {
            const overlay = document.getElementById('levelup-overlay');
            const card = document.getElementById('levelup-card');
            document.getElementById('levelup-icon').textContent = title.icon;
            document.getElementById('levelup-name').textContent = title.name;
            document.getElementById('levelup-desc').textContent = 'Yeni unvanina ulastin!';
            overlay.classList.remove('hidden');
            overlay.style.pointerEvents = 'none';
            card.style.animation = 'none';
            card.offsetHeight;
            card.style.animation = 'levelUpPulse 0.7s cubic-bezier(0.34,1.56,0.64,1) both';
            haptic([100, 50, 100, 50, 300]);
            showSpinConfetti();
            setTimeout(() => overlay.classList.add('hidden'), 4000);
        }

        // ============================================================
        // HAVA DURUMU ROTA ÖNERİSİ
        // ============================================================
        function getWeatherRouteAdvice(weatherCode) {
            const good = [0, 1, 2];
            const ok   = [3, 45];
            const bad  = [61, 63, 71, 80, 81, 82, 95, 96, 99];
            if(good.includes(weatherCode)) return { emoji:'✅', text:'Harika hava! Suru icin ideal.', color:'text-green-400', ride: true };
            if(ok.includes(weatherCode))   return { emoji:'⚠️', text:'Bulutlu ama suru yapilabilir.', color:'text-yellow-400', ride: true };
            if(bad.includes(weatherCode))  return { emoji:'❌', text:'Yagmur/kar var! Suru tavsiye edilmez.', color:'text-sky-300', ride: false };
            return { emoji:'🌡️', text:'Hava durumu bilinmiyor.', color:'text-zinc-400', ride: false };
        }

        // Hava durumu widget'ına rota önerisi ekle
        function updateWeatherWidget(temp, weatherCode) {
            const advice = getWeatherRouteAdvice(weatherCode);
            document.getElementById('weather-temp').innerText = temp + 'degC';
            const adviceEl = document.getElementById('weather-advice');
            if(adviceEl) {
                adviceEl.innerHTML = `<span class="${advice.color} text-[9px] font-bold">${advice.emoji} ${advice.text}</span>`;
            }
            // Update ride card in missions screen
            const rideCard = document.getElementById('weather-ride-card');
            if(rideCard) {
                const bg = advice.ride ? 'from-green-900/60 to-emerald-900/40 border-green-600/40' : 'from-red-900/60 to-red-900/40 border-sky-500/40';
                const textColor = advice.ride ? 'text-green-400' : 'text-sky-300';
                rideCard.className = `rounded-3xl p-5 mb-4 border bg-gradient-to-r ${bg} relative overflow-hidden`;
                rideCard.innerHTML = `
                    <div class="absolute -right-4 -bottom-4 text-8xl opacity-10">${advice.emoji}</div>
                    <div class="text-[10px] font-black uppercase tracking-widest mb-1 ${textColor}">${advice.ride ? 'BUGÜN SÜRÜLEBİLİR' : 'BUGÜN SÜRÜŞ ÖNERİLMEZ'}</div>
                    <div class="text-white font-black text-2xl teko-font">${temp}°C · ${advice.emoji}</div>
                    <div class="${textColor} text-xs font-bold mt-1">${advice.text}</div>`;
            }
        }

        // ============================================================
        // TEMA & ARAYÜZ RENGİ (Premium)
        // ============================================================
        function applyTheme(themeName) {
            const premTier = getUserPremiumTier(currentUser.username);
            if(premTier < 1) { alert('Tema ozelligi Premium uyelerere ozgudur!'); switchTab(6); return; }
            document.body.className = document.body.className.replace(/theme-[a-z]+/g, '').trim();
            document.body.classList.add('theme-' + themeName);
            localStorage.setItem('fr_theme', themeName);
            if(currentUser.stats) {
                currentUser.stats.ui_theme = themeName;
                sendAction('update_user', { username: currentUser.username, stats: currentUser.stats }).catch(()=>{});
            }
            haptic([20]);
        }

        function loadSavedTheme() {
            const saved = localStorage.getItem('fr_theme') || (currentUser && currentUser.stats && currentUser.stats.ui_theme);
            if(saved) {
                document.body.className = document.body.className.replace(/theme-[a-z]+/g, '').trim();
                document.body.classList.add('theme-' + saved);
            }
        }

        // ============================================================
        // DESTEK MODALI
        // ============================================================
        function openSupportModal() {
            const premTier = getUserPremiumTier(currentUser.username);
            const badge = document.getElementById('support-priority-badge');
            if(premTier >= 2) {
                badge.textContent = '🔴 Oncelikli Destek - 24 saat icinde cevaplanir';
                badge.className = 'mb-4 text-center py-2 rounded-xl text-xs font-black uppercase tracking-widest bg-red-900/40 text-sky-300 border border-sky-800/50';
            } else if(premTier === 1) {
                badge.textContent = '🟡 Normal Destek - 48-72 saat icinde cevaplanir';
                badge.className = 'mb-4 text-center py-2 rounded-xl text-xs font-black uppercase tracking-widest bg-yellow-900/40 text-yellow-400 border border-yellow-800/50';
            } else {
                badge.textContent = '⚪ Ucretsiz Destek - Yoğunluğa gore cevaplanir';
                badge.className = 'mb-4 text-center py-2 rounded-xl text-xs font-black uppercase tracking-widest bg-zinc-800 text-zinc-400 border border-zinc-700';
            }
            document.getElementById('support-message').value = '';
            document.getElementById('support-modal').classList.remove('hidden');
        }

        async function submitSupport() {
            const msg = document.getElementById('support-message').value.trim();
            if(!msg) return alert('Lutfen bir mesaj yazin!');
            await sendAction('send_support', { message: msg });
            document.getElementById('support-modal').classList.add('hidden');
            alert('Destek talebiniz alindi! En kisa surede cevaplayacagiz.');
        }

        // ============================================================
        // RAMPA PUANLAMA
        // ============================================================
        async function rateMarker(rating) {
            if(!currentMarkerId) return;
            haptic([20]);
            // Update stars UI
            const stars = document.querySelectorAll('#ms-stars span');
            stars.forEach((s,i) => {
                s.textContent = i < rating ? '⭐' : '☆';
                s.style.opacity = i < rating ? '1' : '0.4';
            });
            try {
                const m = db.markers.find(x=>x.id===currentMarkerId);
                await sendAction('rate_marker', {
                    marker_id: currentMarkerId,
                    marker_name: m ? m.name : '',
                    rating
                });
                showMissionToast('Puan Verildi!', 0, '⭐');
            } catch(e) {}
        }

        function updateMarkerRating(marker) {
            const avgEl = document.getElementById('ms-avg-rating');
            const stars = document.querySelectorAll('#ms-stars span');
            if(!avgEl || !stars.length) return;
            const ratings = marker.ratings || {};
            const myRating = ratings[currentUser.username] || 0;
            const avg = marker.avg_rating || 0;
            const count = Object.keys(ratings).length;
            avgEl.textContent = avg > 0 ? avg.toFixed(1) + ' (' + count + ' oy)' : 'Henuz oy yok';
            stars.forEach((s,i) => {
                s.textContent = i < myRating ? '⭐' : '☆';
                s.style.opacity = i < myRating ? '1' : '0.4';
            });
        }

        // ============================================================
        // TEHLİKE BİLDİRİMİ
        // ============================================================
        function openDangerReport() {
            document.getElementById('danger-reason-input').value = '';
            document.getElementById('danger-modal').classList.remove('hidden');
        }

        function setDangerReason(reason) {
            document.getElementById('danger-reason-input').value = reason;
        }

        async function submitDangerReport() {
            const reason = document.getElementById('danger-reason-input').value.trim();
            if(!reason) return alert('Lutfen bir sebep secin veya yazin!');
            const m = db.markers.find(x=>x.id===currentMarkerId);
            await sendAction('report_danger', {
                marker_id: currentMarkerId,
                marker_name: m ? m.name : '',
                reason
            });
            document.getElementById('danger-modal').classList.add('hidden');
            showMissionToast('Tehlike Bildirildi', 0, '⚠️');
        }

        // ============================================================
        // TAM EKRAN FOTOĞRAF GÖRÜNTÜLEYİCİ
        // ============================================================
        let _fsImages = [];
        let _fsIndex  = 0;

        function openFullscreen(imgs, startIndex) {
            _fsImages = Array.isArray(imgs) ? imgs : [imgs];
            _fsIndex = startIndex || 0;
            _showFullscreenImg();
            document.getElementById('fullscreen-img-modal').classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }

        function closeFullscreenImg() {
            document.getElementById('fullscreen-img-modal').classList.add('hidden');
            document.body.style.overflow = '';
        }

        function _showFullscreenImg() {
            document.getElementById('fullscreen-img').src = _fsImages[_fsIndex];
            const navEl = document.getElementById('fullscreen-nav');
            if(navEl) navEl.style.display = _fsImages.length > 1 ? 'flex' : 'none';
            const ctr = document.getElementById('fullscreen-counter');
            if(ctr) ctr.textContent = _fsImages.length > 1 ? (_fsIndex+1)+' / '+_fsImages.length : '';
        }

        function fullscreenNext() { _fsIndex = (_fsIndex+1) % _fsImages.length; _showFullscreenImg(); }
        function fullscreenPrev() { _fsIndex = (_fsIndex-1+_fsImages.length) % _fsImages.length; _showFullscreenImg(); }

        // Swipe support on fullscreen
        (function(){
            let startX = 0;
            document.addEventListener('touchstart', e => {
                if(document.getElementById('fullscreen-img-modal').classList.contains('hidden')) return;
                startX = e.touches[0].clientX;
            }, {passive:true});
            document.addEventListener('touchend', e => {
                if(document.getElementById('fullscreen-img-modal').classList.contains('hidden')) return;
                const dx = e.changedTouches[0].clientX - startX;
                if(Math.abs(dx) > 50) { dx < 0 ? fullscreenNext() : fullscreenPrev(); }
            }, {passive:true});
        })();

        // ============================================================
        // EMOJI REAKSİYONLARI
        // ============================================================
        async function addReaction(msgId, emoji) {
            haptic([10]);
            try {
                await sendAction('add_reaction', {msg_id: msgId, emoji});
                // Update local state
                const msg = db.messages.find(m=>m.id===msgId);
                if(msg) {
                    if(!msg.reactions) msg.reactions = {};
                    const users = msg.reactions[emoji] || [];
                    const idx = users.indexOf(currentUser.username);
                    if(idx >= 0) users.splice(idx,1); else users.push(currentUser.username);
                    msg.reactions[emoji] = users;
                    renderChat(true);
                }
            } catch(e) {}
        }

        function showTrialExpiredModal() {
            const modal = document.getElementById('trial-expired-modal');
            if(modal) modal.classList.remove('hidden');
            // Clear trial_expired flag so it doesn't show again
            if(currentUser && currentUser.stats) {
                currentUser.stats.trial_expired = false;
                sendAction('update_user', { username: currentUser.username, stats: currentUser.stats }).catch(()=>{});
            }
        }

        function showTrialBanner() {
            const existing = document.getElementById('trial-active-banner');
            if(existing) return;
            const banner = document.createElement('div');
            banner.id = 'trial-active-banner';
            banner.className = 'fixed top-16 left-0 right-0 z-[9998] flex justify-center px-4 trial-banner';
            const expDate = currentUser.stats && currentUser.stats.premium_expire_date ? currentUser.stats.premium_expire_date : '?';
            banner.innerHTML = `<div class="bg-gradient-to-r from-yellow-600 to-amber-500 text-black px-5 py-2.5 rounded-2xl font-black text-xs shadow-[0_0_20px_rgba(234,179,8,0.6)] flex items-center gap-3 max-w-sm w-full">
                <span class="text-lg">🎁</span>
                <span class="flex-1">3 Gun Ucretsiz Ultra+ Denemen Aktif! Bitis: ${expDate}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="text-black/60 hover:text-black text-sm">✕</button>
            </div>`;
            document.body.appendChild(banner);
            setTimeout(() => { if(banner.parentElement) banner.remove(); }, 6000);
        }

        function showMissionToast(title, xp, icon) {
            const toast = document.createElement('div');
            toast.className = 'fixed top-20 left-1/2 -translate-x-1/2 z-[99999] bg-gradient-to-r from-yellow-600 to-orange-500 text-white px-6 py-3 rounded-2xl font-bold text-sm shadow-[0_0_30px_rgba(234,179,8,0.6)] flex items-center gap-3 scale-in-anim';
            toast.innerHTML = '<span class="text-2xl">' + icon + '</span><div><div class="text-[10px] uppercase tracking-widest opacity-80">Gorev Tamamlandi!</div><div>' + title + ' +' + xp + ' XP</div></div>';
            document.body.appendChild(toast);
            haptic([50, 30, 50]);
            setTimeout(() => { toast.style.opacity='0'; toast.style.transition='opacity 0.5s'; setTimeout(()=>toast.remove(),500); }, 3500);
        }
        function renderMissions() {
            const c = document.getElementById("missions-list");
            if(!c || !currentUser) return;
            const stats = currentUser.stats || {};

            const dailyData = getDailyMissions();
            const weeklyData = getWeeklyMissions();
            const dm = stats.daily_missions || {};
            const wm = stats.weekly_missions || {};
            const todayKey = dailyData.key;
            const weekKey = weeklyData.key;

            let html = '<div class="flex bg-zinc-950 rounded-xl p-1 mb-5 border border-zinc-800">';
            html += '<button onclick="setMissionTab(0)" id="mtab-0" class="flex-1 py-2 bg-zinc-800 text-white rounded-lg font-bold text-xs transition">Kalici</button>';
            html += '<button onclick="setMissionTab(1)" id="mtab-1" class="flex-1 py-2 text-zinc-500 rounded-lg font-bold text-xs transition">Gunluk</button>';
            html += '<button onclick="setMissionTab(2)" id="mtab-2" class="flex-1 py-2 text-zinc-500 rounded-lg font-bold text-xs transition">Haftalik</button>';
            html += '</div>';

            // === KALICI ===
            html += '<div id="m-perm">';
            MISSIONS.forEach(m => {
                let progress = stats[m.type] || 0;
                let isDone = stats.missions && stats.missions[m.id] === true;
                let percent = Math.min((progress / m.target) * 100, 100);
                let pbHtml = isDone ? '' : '<div class="progress-bar-bg mt-2"><div class="progress-bar-fill" style="width:' + percent + '%;"></div></div>';
                let btnHtml = isDone
                    ? '<span class="text-green-400 text-xs font-bold">TAMAM</span>'
                    : '<div class="text-right"><div class="text-white font-black teko-font text-lg">+' + m.xp + ' XP</div><div class="text-[9px] text-zinc-500">' + progress + '/' + m.target + '</div></div>';
                html += '<div class="glass-panel p-4 rounded-2xl border ' + (isDone ? 'border-green-800/40' : 'border-zinc-700') + ' flex items-center gap-3 mb-3 shadow-md">';
                html += '<div class="text-3xl w-12 h-12 flex items-center justify-center bg-black/50 rounded-xl border border-zinc-800 shrink-0">' + m.icon + '</div>';
                html += '<div class="flex-1 min-w-0"><div class="font-bold text-sm ' + (isDone ? 'text-green-400' : 'text-white') + '">' + m.title + '</div><div class="text-[10px] text-zinc-500 mt-0.5">' + m.desc + '</div>' + pbHtml + '</div>' + btnHtml + '</div>';
            });
            html += '</div>';

            // === GUNLUK ===
            html += '<div id="m-daily" class="hidden">';
            html += '<div class="text-[10px] text-zinc-500 uppercase tracking-widest font-bold mb-3">Bugunun Gorevleri: ' + todayKey + '</div>';
            dailyData.missions.forEach(m => {
                const doneKey = 'done_' + m.id;
                const isDone = dm.date === todayKey && dm[doneKey];
                const progress = m.type === 'daily_login' ? (dm.date === todayKey ? 1 : 0) : (dm.date === todayKey ? (dm[m.type] || 0) : 0);
                const percent = Math.min((progress / m.target) * 100, 100);
                let pbHtml = isDone ? '' : '<div class="progress-bar-bg mt-2"><div class="progress-bar-fill" style="width:' + percent + '%;"></div></div>';
                let btnHtml = isDone
                    ? '<span class="text-green-400 text-xs font-bold">TAMAM</span>'
                    : '<div class="text-right"><div class="text-white font-black teko-font text-lg">+' + m.xp + ' XP</div><div class="text-[9px] text-zinc-500">' + progress + '/' + m.target + '</div></div>';
                html += '<div class="glass-panel p-4 rounded-2xl border ' + (isDone ? 'border-green-800/40' : 'border-yellow-900/40') + ' flex items-center gap-3 mb-3 shadow-md">';
                html += '<div class="text-3xl w-12 h-12 flex items-center justify-center bg-black/50 rounded-xl border border-zinc-800 shrink-0">' + m.icon + '</div>';
                html += '<div class="flex-1 min-w-0"><div class="font-bold text-sm ' + (isDone ? 'text-green-400' : 'text-yellow-400') + '">' + m.title + '</div><div class="text-[10px] text-zinc-500 mt-0.5">' + m.desc + '</div>' + pbHtml + '</div>' + btnHtml + '</div>';
            });
            html += '</div>';

            // === HAFTALIK ===
            html += '<div id="m-weekly" class="hidden">';
            html += '<div class="text-[10px] text-zinc-500 uppercase tracking-widest font-bold mb-3">Bu Haftanin Gorevleri (Pzt: ' + weekKey + ')</div>';
            weeklyData.missions.forEach(m => {
                const doneKey = 'done_' + m.id;
                const isDone = wm.week === weekKey && wm[doneKey];
                const progress = wm.week === weekKey ? (wm[m.type] || 0) : 0;
                const percent = Math.min((progress / m.target) * 100, 100);
                let pbHtml = isDone ? '' : '<div class="progress-bar-bg mt-2"><div class="progress-bar-fill" style="background:linear-gradient(90deg,#7c3aed,#4f46e5);width:' + percent + '%;"></div></div>';
                let btnHtml = isDone
                    ? '<span class="text-green-400 text-xs font-bold">TAMAM</span>'
                    : '<div class="text-right"><div class="text-white font-black teko-font text-lg">+' + m.xp + ' XP</div><div class="text-[9px] text-zinc-500">' + progress + '/' + m.target + '</div></div>';
                html += '<div class="glass-panel p-4 rounded-2xl border ' + (isDone ? 'border-green-800/40' : 'border-purple-900/40') + ' flex items-center gap-3 mb-3 shadow-md">';
                html += '<div class="text-3xl w-12 h-12 flex items-center justify-center bg-black/50 rounded-xl border border-zinc-800 shrink-0">' + m.icon + '</div>';
                html += '<div class="flex-1 min-w-0"><div class="font-bold text-sm ' + (isDone ? 'text-green-400' : 'text-purple-400') + '">' + m.title + '</div><div class="text-[10px] text-zinc-500 mt-0.5">' + m.desc + '</div>' + pbHtml + '</div>' + btnHtml + '</div>';
            });
            html += '</div>';

            c.innerHTML = html;
            window._missionTab = window._missionTab || 0;
            setMissionTab(window._missionTab);
        }

        function setMissionTab(idx) {
            window._missionTab = idx;
            ['m-perm','m-daily','m-weekly'].forEach((id,i) => {
                const el = document.getElementById(id);
                if(el) el.classList.toggle('hidden', i !== idx);
            });
            [0,1,2].forEach(i => {
                const btn = document.getElementById('mtab-'+i);
                if(!btn) return;
                btn.className = i === idx
                    ? 'flex-1 py-2 bg-zinc-800 text-white rounded-lg font-bold text-xs transition'
                    : 'flex-1 py-2 text-zinc-500 rounded-lg font-bold text-xs transition';
            });
        }
        // ==============================================================
        // DAVET ET KAZAN (REFERANS) SEKMESİ İŞLEMLERİ
        // ==============================================================
        function renderReferralTab() {
            if(!currentUser) return;
            const stats = currentUser.stats || {};
            // Gerçek ref kodu stats'tan, yoksa fallback
            const refCode = stats.ref_code || currentUser.username;
            document.getElementById("my-ref-code").value = refCode;
            const refCount = stats.ref_count || 0;
            const claimable = stats.claimable_refs || 0;
            
            const maxRef = 10;
            const refPercent = Math.min((refCount / maxRef) * 100, 100);
            
            document.getElementById("ref-monthly-limit").innerText = `BU AYKİ KULLANIM: ${refCount} / ${maxRef}`;
            document.getElementById("ref-monthly-bar").style.width = `${refPercent}%`;
            document.getElementById("claimable-ref-count").innerText = claimable;
            
            const claimArea = document.getElementById("ref-claim-area");
            if(claimable > 0) {
                claimArea.style.opacity = "1";
                claimArea.style.pointerEvents = "auto";
                claimArea.style.filter = "none";
                claimArea.style.transform = "scale(1)";
                claimArea.style.transition = "all 0.3s ease";
            } else {
                claimArea.style.opacity = "0.35";
                claimArea.style.pointerEvents = "none";
                claimArea.style.filter = "grayscale(80%)";
                claimArea.style.transform = "scale(0.98)";
            }
        }

        function copyRefCode() {
            const code = document.getElementById("my-ref-code").value;
            navigator.clipboard.writeText(code);
            alert("Referans kodunuz başarıyla kopyalandı! Arkadaşlarınıza gönderebilirsiniz.");
        }

        async function claimRefReward() {
            const reward = document.getElementById("ref-reward-select").value;
            try {
                const res = await sendAction('claim_ref_reward', { reward_choice: reward });
                if(res.status === 'ok') {
                    alert("Tebrikler! Ödül başarıyla hesabınıza tanımlandı. Bol pedallı günler!");
                    loadData(true); 
                }
            } catch(e) {}
        }

        // ================================================================
        // REELS SİSTEMİ JS
        // ================================================================

        // ── Aktif IntersectionObserver listesi (eski kod uyumu — artık kullanılmıyor) ──
        const _reelObservers = [];

        // ──────────────────────────────────────────────────────────────
        // stopAllMedia() — Tüm video/ses medyayı durdurur, merkezi
        // feed observer'ı bağlantısını keser.
        // Sayfa geçişlerinde ve modal kapanışlarında çağrılır.
        // ──────────────────────────────────────────────────────────────
        function stopAllMedia() {
            document.querySelectorAll('video, audio').forEach(el => {
                try { el.pause(); } catch(_) {}
            });
            if(typeof _feedObserver !== 'undefined' && _feedObserver) {
                _feedObserver.disconnect();
                _feedObserver = null;
            }
        }

        // ──────────────────────────────────────────────────────────────
        // openReels(videoId) — Reels sayfasını açar ve belirtilen ID'li
        // videoya scroll ederek otomatik oynatır.
        // Profilden Reels'e ışınlanmak için kullanılır.
        // ──────────────────────────────────────────────────────────────
        window.openReels = async function(videoId) {
            stopAllMedia();
            // Tüm açık modalleri kapat
            ['other-profile-modal','reel-comment-modal','reel-upload-modal'].forEach(id => {
                const m = document.getElementById(id);
                if(m) m.classList.add('hidden');
            });
            // Reels ekranını aç
            const screenReels = document.getElementById('screen-reels');
            if(screenReels) {
                screenReels.style.display = 'flex';
                screenReels.style.flexDirection = 'column';
                screenReels.style.zIndex = '9990';
                screenReels.classList.remove('hidden');
            }
            const bottomNav = document.getElementById('bottom-nav');
            if(bottomNav) bottomNav.style.display = 'none';
            const soundBtn = document.getElementById('reel-sound-btn');
            if(soundBtn) { soundBtn.style.display = 'flex'; soundBtn.textContent = _reelMuted ? '🔇' : '🔊'; }
            const gridBtn = document.getElementById('grid-view-btn');
            if(gridBtn) gridBtn.style.display = 'flex';
            const uploadTopBtn = document.getElementById('reels-upload-top-btn');
            if(uploadTopBtn) uploadTopBtn.style.display = 'flex';

            // Her zaman yeniden yükle (feed güncel olsun, observer temiz başlasın)
            await loadReels();

            // loadReels render tamamlandıktan sonra scroll + oynat
            if(videoId && reelsData.length) {
                const idx = reelsData.findIndex(r => String(r.id) === String(videoId));
                const feed = document.getElementById('reels-feed');
                if(feed && idx >= 0) {
                    // 2 frame bekle: render + observer kurulumu tamamlansın
                    requestAnimationFrame(() => requestAnimationFrame(() => {
                        const cards = feed.querySelectorAll(':scope > div');
                        const targetCard = cards[idx];
                        if(!targetCard) return;
                        // observer'ı geçici durdur, scroll sırasında yanlış video çalmasın
                        if(_feedObserver) _feedObserver.disconnect();
                        // Tüm videolar durdurulmuş, scroll et
                        targetCard.scrollIntoView({ behavior: 'instant', block: 'start' });
                        // Scroll sonrası hedef videoyu oynat ve observer'ı yeniden kur
                        requestAnimationFrame(() => {
                            const video = targetCard.querySelector('video');
                            if(video) {
                                video.muted = _reelMuted;
                                video.play().catch(() => { video.muted = true; video.play().catch(() => {}); });
                            }
                            _setupFeedObserver();
                        });
                    }));
                }
            }
            history.pushState({ reelsOpen: true }, '');
        };

        function escapeHtml(str) {
            if(str == null) return '';
            return String(str)
                .replace(/&/g,'&amp;')
                .replace(/</g,'&lt;')
                .replace(/>/g,'&gt;')
                .replace(/"/g,'&quot;')
                .replace(/'/g,'&#39;');
        }

        let _reelMuted = false; // Varsayılan: ses açık

        // Reels'i kapat, önceki sekmeye dön
        function closeReels() {
            stopAllMedia(); // Hayalet ses önleme — tüm medyayı durdur
            const reelsEl = document.getElementById('screen-reels');
            if(reelsEl) {
                reelsEl.style.display = 'none';
                reelsEl.classList.add('hidden');
            }
            const bottomNav = document.getElementById('bottom-nav');
            if(bottomNav) bottomNav.style.display = '';
            const soundBtn = document.getElementById('reel-sound-btn');
            if(soundBtn) soundBtn.style.display = 'none';
            const gridBtn = document.getElementById('grid-view-btn');
            if(gridBtn) gridBtn.style.display = 'none';
            const uploadTopBtnC = document.getElementById('reels-upload-top-btn');
            if(uploadTopBtnC) uploadTopBtnC.style.display = 'none';
            document.querySelectorAll('#reels-feed video').forEach(v => v.pause());
            // Alt nav butonlarını güncelle
            const bnavIds = [0,1,9,3,7];
            bnavIds.forEach(i => {
                const btn = document.getElementById('bnav-' + i);
                if(!btn) return;
                if(i === _prevTab) {
                    btn.classList.add('text-white','bg-zinc-800/80','shadow-inner');
                    btn.classList.remove('text-zinc-500');
                } else {
                    btn.classList.remove('text-white','bg-zinc-800/80','shadow-inner');
                    btn.classList.add('text-zinc-500');
                }
            });
            // Önceki sekmeye geç (reels değilse)
            const target = (_prevTab === 9) ? 0 : _prevTab;
            const tabs = ['screen-map','screen-chat','screen-market','screen-rank','screen-news','screen-missions','screen-premium','screen-profile','screen-referral'];
            tabs.forEach((t, i) => {
                const el = document.getElementById(t);
                if(!el) return;
                if(i === target) {
                    el.style.display = 'flex';
                    el.style.flexDirection = 'column';
                    el.style.zIndex = '20';
                    el.classList.remove('hidden');
                } else {
                    el.style.display = 'none';
                    el.classList.add('hidden');
                }
            });
            if(target === 0 && map) map.invalidateSize();
        }

        function toggleReelSound() {
            _reelMuted = !_reelMuted;
            const btn = document.getElementById('reel-sound-btn');
            if(btn) btn.textContent = _reelMuted ? '🔇' : '🔊';
            document.querySelectorAll('#reels-feed video').forEach(v => { v.muted = _reelMuted; });
        }

        // ── TEK merkezi IntersectionObserver — tüm feed kartları için ──
        // Kart başına değil, feed render bittikten sonra tek seferde kurulur.
        let _feedObserver = null;
        function _setupFeedObserver() {
            if(_feedObserver) { _feedObserver.disconnect(); _feedObserver = null; }
            if(_reelsGridMode) return; // Grid modunda observer gerekmez
            const feed = document.getElementById('reels-feed');
            if(!feed) return;
            _feedObserver = new IntersectionObserver(entries => {
                entries.forEach(entry => {
                    const video = entry.target.querySelector('video');
                    if(!video) return;
                    if(_reelsGridMode) { video.pause(); return; }
                    if(entry.isIntersecting) {
                        // Diğer tüm feed videolarını durdur → sadece görünür kart çalar
                        document.querySelectorAll('#reels-feed video').forEach(v => {
                            if(v !== video) v.pause();
                        });
                        video.muted = _reelMuted;
                        video.play().catch(() => { video.muted = true; video.play().catch(() => {}); });
                    } else {
                        video.pause();
                    }
                });
            }, { threshold: 0.6, rootMargin: '0px' });
            feed.querySelectorAll(':scope > div').forEach(card => _feedObserver.observe(card));
        }

        async function loadReels() {
            // Observer ve medyayı temizle
            if(_feedObserver) { _feedObserver.disconnect(); _feedObserver = null; }
            document.querySelectorAll('#reels-feed video, #reels-feed audio').forEach(el => {
                try { el.pause(); el.removeAttribute('src'); el.load(); } catch(_) {}
            });
            reelsData = [];
            const feed = document.getElementById('reels-feed');
            const emptyEl = document.getElementById('reels-empty');
            const loadingEl = document.getElementById('reels-loading');
            if(!feed) return;

            if(loadingEl) loadingEl.style.display = 'flex';
            if(emptyEl) emptyEl.classList.add('hidden');

            try {
                const res = await sendAction('get_reels', { offset: 0 });
                if(res && res.reels) reelsData = res.reels;
            } catch(e) { console.error('Reel yükleme hatası:', e); }

            if(loadingEl) loadingEl.style.display = 'none';

            const soundBtn = document.getElementById('reel-sound-btn');
            if(soundBtn) { soundBtn.style.display = 'flex'; soundBtn.textContent = _reelMuted ? '🔇' : '🔊'; }

            if(!reelsData.length) {
                if(emptyEl) emptyEl.classList.remove('hidden');
                return;
            }

            // Feed'i temizle ve yeniden render et
            while(feed.firstChild) feed.removeChild(feed.firstChild);
            reelsData.forEach((reel) => {
                try { renderReelCard(reel, feed); }
                catch(e) { console.error('Reel render hatası:', reel?.id, e); }
            });

            // Tek merkezi observer'ı kur (render bittikten sonra)
            requestAnimationFrame(() => _setupFeedObserver());
        }

        function renderReelCard(reel, container) {
            if(!reel) return;
            const user = db.users.find(u => u.username === reel.user) || { username: reel.user, avatar: '' };
            const avatar = user.avatar || 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg';
            const isLiked = currentUser && (reel.likes || []).includes(currentUser.username);
            const likeCount = (reel.likes || []).length;
            const isOwner = currentUser && (currentUser.username === reel.user || currentUser.role === 'Admin' || currentUser.role === 'SubAdmin');

            // Story halkası: db.stories içinde aktif story var mı?
            const now = Math.floor(Date.now() / 1000);
            const hasActiveStory = db.stories && db.stories.some(s => s.user === reel.user && s.expires_at > now);
            const avatarRingClass = hasActiveStory ? 'story-ring' : 'border-2 border-white';
            
            const card = document.createElement('div');
            card.className = 'relative w-full shrink-0 bg-black flex items-center justify-center';
            card.style.cssText = 'height:100dvh;scroll-snap-align:start;scroll-snap-stop:always;';
            
            let mediaHtml = '';
            if(reel.media_type === 'video') {
                mediaHtml = `<video src="${escapeHtml(reel.media_url)}" class="w-full h-full object-contain" playsinline loop autoplay style="max-height:100%;"></video>`;
            } else {
                mediaHtml = `<img src="${escapeHtml(reel.media_url)}" class="w-full h-full object-contain" style="max-height:100%;" loading="lazy">`;
            }
            
            const timeAgo = formatTimeAgo(reel.created_at);
            
            card.innerHTML = `
                ${mediaHtml}
                <!-- Play/Pause flash ikonu -->
                <div class="reel-play-flash" style="pointer-events:none;">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80" width="80" height="80">
                        <circle cx="40" cy="40" r="38" fill="rgba(255,255,255,0.22)" stroke="rgba(255,255,255,0.5)" stroke-width="2"/>
                        <polygon class="flash-play-icon" points="30,22 62,40 30,58" fill="white" style="display:none;"/>
                        <g class="flash-pause-icon" style="display:none;">
                            <rect x="24" y="22" width="10" height="36" rx="3" fill="white"/>
                            <rect x="46" y="22" width="10" height="36" rx="3" fill="white"/>
                        </g>
                    </svg>
                </div>
                <!-- Gradient overlay -->
                <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent pointer-events-none"></div>
                <!-- Sol alt: kullanıcı + açıklama -->
                <div class="absolute bottom-4 left-4 right-16 z-10">
                    <div class="flex items-center gap-2 mb-2 cursor-pointer" onclick="window.openProfileOrStory('${escapeHtml(reel.user)}')">
                        <div class="w-9 h-9 rounded-full overflow-hidden ${avatarRingClass} shrink-0">
                            <img src="${escapeHtml(avatar)}" class="w-full h-full object-cover">
                        </div>
                        <span class="text-white font-black text-sm drop-shadow-md">${escapeHtml(reel.user)}</span>
                        <span class="text-zinc-400 text-xs">${timeAgo}</span>
                    </div>
                    ${reel.caption ? `<p class="text-white text-sm leading-snug drop-shadow-md break-words line-clamp-2">${escapeHtml(reel.caption)}</p>` : ''}
                </div>
                <!-- Sağ: aksiyonlar -->
                <div class="absolute right-3 bottom-8 z-10 flex flex-col items-center gap-5">
                    <button onclick="toggleReelLike('${reel.id}', this)" class="flex flex-col items-center gap-1">
                        <div class="w-10 h-10 rounded-full bg-black/50 backdrop-blur flex items-center justify-center text-xl border border-white/20 ${isLiked ? 'text-sky-400' : 'text-white'}">${isLiked ? '❤️' : '🤍'}</div>
                        <span class="text-white text-xs font-bold drop-shadow-md reel-like-count">${likeCount}</span>
                    </button>
                    <button onclick="openReelComments('${reel.id}')" class="flex flex-col items-center gap-1">
                        <div class="w-10 h-10 rounded-full bg-black/50 backdrop-blur flex items-center justify-center text-xl border border-white/20 text-white">💬</div>
                        <span class="text-white text-xs font-bold drop-shadow-md">${reel.comment_count || 0}</span>
                    </button>
                    ${isOwner ? `<button onclick="deleteReel('${reel.id}')" class="flex flex-col items-center gap-1">
                        <div class="w-10 h-10 rounded-full bg-red-900/60 backdrop-blur flex items-center justify-center text-xl border border-sky-400/30 text-white">🗑️</div>
                    </button>` : ''}
                </div>
            `;
            container.appendChild(card);

            // ── Video tap-to-pause: click → SVG flash ikonu ──
            if(reel.media_type === 'video') {
                const video = card.querySelector('video');
                const flashEl = card.querySelector('.reel-play-flash');
                video.muted = _reelMuted;
                if(video && flashEl) {
                    const playIcon  = flashEl.querySelector('.flash-play-icon');
                    const pauseIcon = flashEl.querySelector('.flash-pause-icon');
                    video.addEventListener('click', function(e) {
                        e.stopPropagation();
                        if(video.paused) {
                            // Diğer tüm feed videolarını önce durdur
                            document.querySelectorAll('#reels-feed video').forEach(v => { if(v !== video) v.pause(); });
                            video.play().catch(()=>{});
                            if(playIcon)  playIcon.style.display = 'none';
                            if(pauseIcon) pauseIcon.style.display = 'block';
                        } else {
                            video.pause();
                            if(playIcon)  playIcon.style.display = 'block';
                            if(pauseIcon) pauseIcon.style.display = 'none';
                        }
                        flashEl.classList.remove('show');
                        void flashEl.offsetWidth;
                        flashEl.classList.add('show');
                    });
                }
            }
            // NOT: IntersectionObserver artık kart başına DEĞİL,
            // loadReels() sonunda _setupFeedObserver() ile tek seferde kurulur.
        }

        async function toggleReelLike(reelId, btn) {
            if(!currentUser) { alert('Beğenmek için giriş yapın!'); return; }
            try {
                const res = await sendAction('like_reel', { reel_id: reelId });
                if(res && res.status === 'ok') {
                    const icon = btn.querySelector('div');
                    const count = btn.querySelector('.reel-like-count');
                    if(icon) { icon.textContent = res.liked ? '❤️' : '🤍'; icon.className = icon.className.replace(/text-(red|white)-\d+/, res.liked ? 'text-sky-400' : 'text-white'); }
                    if(count) count.textContent = res.likes;
                }
            } catch(e) {}
        }

        async function deleteReel(reelId) {
            if(!confirm("Bu Reels'i silmek istediğinize emin misiniz?")) return;
            await sendAction('delete_reel', { reel_id: reelId });
            loadReels();
        }

        async function openReelComments(reelId) {
            currentReelId = reelId;
            const modal = document.getElementById('reel-comment-modal');
            const list = document.getElementById('reel-comments-list');
            modal.classList.remove('hidden');
            list.innerHTML = '<div class="text-zinc-500 text-sm text-center py-4">Yorumlar yükleniyor...</div>';
            try {
                const res = await sendAction('get_comments', { target_id: reelId });
                const comments = res.comments || [];
                if(!comments.length) {
                    list.innerHTML = '<div class="text-zinc-500 text-sm text-center py-4">Henüz yorum yok. İlk yorumu sen yap!</div>';
                    return;
                }
                list.innerHTML = comments.map(c => {
                    const u = db.users.find(x => x.username === c.user) || {};
                    const av = u.avatar || 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg';
                    return `<div class="flex items-start gap-2">
                        <img src="${escapeHtml(av)}" class="w-8 h-8 rounded-full object-cover shrink-0 border border-zinc-700">
                        <div class="bg-zinc-900/80 rounded-xl px-3 py-2 flex-1">
                            <span class="text-pink-400 font-black text-xs">${escapeHtml(c.user)} </span>
                            <span class="text-white text-xs">${escapeHtml(c.text)}</span>
                        </div>
                    </div>`;
                }).join('');
            } catch(e) { list.innerHTML = '<div class="text-zinc-500 text-sm text-center py-4">Yorumlar yüklenemedi.</div>'; }
        }

        async function submitReelComment() {
            if(!currentUser) { alert('Yorum yapmak için giriş yapın!'); return; }
            const inp = document.getElementById('reel-comment-input');
            const text = inp.value.trim();
            if(!text) return;
            inp.value = '';
            await sendAction('comment_reel', { reel_id: currentReelId, text });
            openReelComments(currentReelId);
        }

        function openReelUploadModal() {
            if(!currentUser) { alert('Reel paylaşmak için giriş yapın!'); return; }
            const modal = document.getElementById('reel-upload-modal');
            const infoEl = document.getElementById('reel-limit-info');
            const tier = getMyTier();
            let infoText = '';
            if(tier === 0) infoText = '⚪ Ücretsiz: Günde <b>1 fotoğraf</b> paylaşabilirsiniz. Video için Standart üyelik gerekli.';
            else if(tier === 1) infoText = '⭐ Standart: Günde <b>1 fotoğraf veya video</b> paylaşabilirsiniz.';
            else infoText = '💎 Deluxe/Ultra+: Günde <b>2 Reel</b> paylaşabilirsiniz.';
            if(infoEl) infoEl.innerHTML = infoText;
            // Video butonunu ücretsizler için soluk göster ama tıklanabilir bırak
            const videoLabel = document.getElementById('reel-video-btn');
            if(videoLabel) {
                videoLabel.style.opacity = tier >= 1 ? '1' : '0.5';
                videoLabel.title = tier < 1 ? 'Video için Standart üyelik gerekli' : '';
            }
            clearReelFile();
            modal.classList.remove('hidden');
        }

        function clearReelFile() {
            reelFileData = null;
            reelFileType = null;
            const previewCont = document.getElementById('reel-preview-container');
            const previewImg = document.getElementById('reel-preview-img');
            const previewVid = document.getElementById('reel-preview-video');
            if(previewCont) previewCont.classList.add('hidden');
            if(previewImg) { previewImg.classList.add('hidden'); previewImg.src = ''; }
            if(previewVid) { previewVid.classList.add('hidden'); previewVid.src = ''; }
            const pi = document.getElementById('reel-photo-input');
            const vi = document.getElementById('reel-video-input');
            if(pi) pi.value = '';
            if(vi) vi.value = '';
        }

        function getMyTier() {
            if(!currentUser) return 0;
            if(currentUser.role === 'Admin') return 3;
            let st = currentUser.stats;
            if(typeof st === 'string') { try { st = JSON.parse(st); } catch(e) { st = {}; } }
            return parseInt((st || {}).premium_tier || 0);
        }

        async function handleReelFile(input, type) {
            const tier = getMyTier();
            const file = input.files[0];
            if(!file) return;

            if(type === 'video') {
                if(tier < 1) {
                    input.value = '';
                    if(confirm("Video paylaşmak için Standart üyelik gereklidir. Üyelik almak ister misin?")) {
                        document.getElementById('reel-upload-modal').classList.add('hidden');
                        switchTab(6);
                    }
                    return;
                }
                if(file.size > 50 * 1024 * 1024) {
                    alert('Video boyutu maksimum 50MB olmalıdır!');
                    input.value = '';
                    return;
                }
            }

            const previewCont = document.getElementById('reel-preview-container');
            const previewImg = document.getElementById('reel-preview-img');
            const previewVid = document.getElementById('reel-preview-video');
            const compressInfo = document.getElementById('reel-compress-info');
            previewCont.classList.remove('hidden');

            if(type === 'image') {
                const compressed = await compressImage(file, 960, 0.75);
                reelFileData = compressed;
                reelFileType = 'image';
                previewImg.src = compressed;
                previewImg.classList.remove('hidden');
                previewVid.classList.add('hidden');
                if(compressInfo) compressInfo.classList.remove('hidden');
            } else {
                previewImg.classList.add('hidden');
                previewVid.classList.remove('hidden');
                if(compressInfo) compressInfo.classList.add('hidden');
                const loadDiv = document.createElement('div');
                loadDiv.id = 'reel-vid-loading';
                loadDiv.className = 'absolute inset-0 flex items-center justify-center bg-black/70 text-white text-xs font-bold z-10';
                loadDiv.textContent = 'Video hazırlanıyor...';
                previewCont.style.position = 'relative';
                previewCont.appendChild(loadDiv);
                reelFileData = null; // FileReader bitene kadar null
                reelFileType = 'video';
                previewVid.src = URL.createObjectURL(file);
                const reader = new FileReader();
                reader.onload = e => {
                    reelFileData = e.target.result;
                    const ld = document.getElementById('reel-vid-loading');
                    if(ld) ld.remove();
                };
                reader.onerror = () => {
                    alert('Video okunamadi, lutfen tekrar deneyin.');
                    clearReelFile();
                };
                reader.readAsDataURL(file);
            }
        }

        async function compressImage(file, maxSize, quality) {
            return new Promise(resolve => {
                const img = new Image();
                const url = URL.createObjectURL(file);
                img.onload = () => {
                    let w = img.width, h = img.height;
                    if(w > maxSize || h > maxSize) {
                        if(w > h) { h = Math.round(h * maxSize / w); w = maxSize; }
                        else { w = Math.round(w * maxSize / h); h = maxSize; }
                    }
                    const canvas = document.createElement('canvas');
                    canvas.width = w; canvas.height = h;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(img, 0, 0, w, h);
                    URL.revokeObjectURL(url);
                    resolve(canvas.toDataURL('image/jpeg', quality));
                };
                img.src = url;
            });
        }

        async function submitReel() {
            if(!currentUser) return;

            // Video henüz FileReader ile okunuyorsa bekle
            if(reelFileType === 'video' && !reelFileData) {
                alert('Video hâlâ hazırlanıyor, lütfen birkaç saniye bekleyin.');
                return;
            }
            if(!reelFileData) { alert('Önce bir fotoğraf veya video seçin!'); return; }

            const caption = document.getElementById('reel-caption').value.trim();
            const submitBtn = document.getElementById('reel-submit-btn');
            const progressDiv = document.getElementById('reel-upload-progress');
            const progressBar = document.getElementById('reel-progress-bar');
            const progressLabel = progressDiv ? progressDiv.querySelector('.text-xs') : null;

            submitBtn.disabled = true;
            submitBtn.textContent = 'Yükleniyor...';
            if(progressDiv) progressDiv.classList.remove('hidden');

            function setProgress(pct, label) {
                if(progressBar) progressBar.style.width = pct + '%';
                if(progressLabel) progressLabel.textContent = label;
            }

            try {
                setProgress(15, reelFileType === 'video' ? 'Video sunucuya yükleniyor...' : 'Fotoğraf yükleniyor...');

                // Adım 1: Medyayı R2'ye yükle
                const uploadRes = await fetch('/api/data', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'upload_media', data: { media_data: reelFileData, folder: 'reels' } })
                });

                if(!uploadRes.ok) throw new Error('Sunucu hatası: ' + uploadRes.status);
                const uploadData = await uploadRes.json();
                setProgress(80, 'Reel kaydediliyor...');

                if(!uploadData || !uploadData.url) {
                    // Oturum süresi dolmuşsa yeniden giriş iste
                    if(uploadData?.message === 'Giriş yapmalısınız!') {
                        alert('Oturumun süresi dolmuş, lütfen tekrar giriş yap.');
                        logout();
                        return;
                    }
                    throw new Error(uploadData?.message || 'Medya sunucuya yüklenemedi.');
                }

                // Adım 2: Sadece URL ile add_reel — küçük payload
                const res = await fetch('/api/data', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'add_reel', data: {
                        media_url: uploadData.url,
                        media_type: reelFileType,
                        caption: caption
                    }})
                });

                if(!res.ok) throw new Error('Kayıt hatası: ' + res.status);
                const resData = await res.json();
                setProgress(100, 'Tamamlandı!');

                if(resData && resData.status === 'ok') {
                    setTimeout(() => {
                        document.getElementById('reel-upload-modal').classList.add('hidden');
                        clearReelFile();
                        document.getElementById('reel-caption').value = '';
                        loadReels();
                    }, 400);
                } else {
                    if(resData?.message === 'Giriş yapmalısınız!') { alert('Oturumun süresi dolmuş, lütfen tekrar giriş yap.'); logout(); return; }
                    alert(resData?.message || 'Reel paylaşılamadı, tekrar deneyin.');
                }
            } catch(e) {
                console.error('Reel upload error:', e);
                alert('Yükleme hatası: ' + (e.message || 'Bilinmeyen hata. Lütfen tekrar deneyin.'));
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'PAYLAŞ';
                if(progressDiv) setTimeout(() => progressDiv.classList.add('hidden'), 600);
            }
        }

        function formatTimeAgo(ts) {
            if(!ts) return '';
            const diff = Math.floor(Date.now() / 1000) - ts;
            if(diff < 60) return 'Az önce';
            if(diff < 3600) return Math.floor(diff/60) + 'dk';
            if(diff < 86400) return Math.floor(diff/3600) + 'sa';
            return Math.floor(diff/86400) + 'g';
        }
        // ── Herhangi bir reel objesini direkt tam ekran aç ──
        // Hem profil grid tıklamasından hem de ileride başka yerlerden çağrılabilir.
        window.openReelDirect = function(reel) {
            if(!reel || !reel.media_url) return;
            stopAllMedia(); // Önceki sesleri temizle

            // Önce reels sekmesini arka planda aktif et (butonlar görünsün diye)
            const screenReels = document.getElementById('screen-reels');
            if(screenReels) {
                screenReels.style.display = 'flex';
                screenReels.style.flexDirection = 'column';
                screenReels.style.zIndex = '9990';
                screenReels.classList.remove('hidden');
            }
            const bottomNav = document.getElementById('bottom-nav');
            if(bottomNav) bottomNav.style.display = 'none';
            const soundBtn = document.getElementById('reel-sound-btn');
            if(soundBtn) { soundBtn.style.display = 'flex'; soundBtn.textContent = _reelMuted ? '🔇' : '🔊'; }
            const gridBtn = document.getElementById('grid-view-btn');
            if(gridBtn) gridBtn.style.display = 'flex';
            const uploadTopBtn = document.getElementById('reels-upload-top-btn');
            if(uploadTopBtn) uploadTopBtn.style.display = 'flex';

            // Önceki overlay varsa temizle
            const oldOverlay = document.getElementById('reel-direct-overlay');
            if(oldOverlay) oldOverlay.remove();

            const user = (typeof db !== 'undefined' && db.users)
                ? (db.users.find(u => u.username === reel.user) || { username: reel.user, avatar: '' })
                : { username: reel.user, avatar: '' };
            const avatar = user.avatar || 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg';
            const likeCount = (reel.likes || []).length;
            const timeAgo = typeof formatTimeAgo === 'function' ? formatTimeAgo(reel.created_at) : '';

            const overlay = document.createElement('div');
            overlay.id = 'reel-direct-overlay';
            overlay.style.cssText = 'position:absolute;inset:0;z-index:500;background:#000;display:flex;align-items:center;justify-content:center;';

            // Medya
            let mediaEl;
            if(reel.media_type === 'video') {
                mediaEl = document.createElement('video');
                mediaEl.src = reel.media_url;
                mediaEl.style.cssText = 'width:100%;height:100%;object-fit:contain;max-height:100%;';
                mediaEl.setAttribute('playsinline', '');
                mediaEl.setAttribute('loop', '');
                mediaEl.muted = _reelMuted;
                mediaEl.autoplay = true;
            } else {
                mediaEl = document.createElement('img');
                mediaEl.src = reel.media_url;
                mediaEl.style.cssText = 'width:100%;height:100%;object-fit:contain;max-height:100%;';
            }

            // Gradient overlay
            const grad = document.createElement('div');
            grad.style.cssText = 'position:absolute;inset:0;background:linear-gradient(to top,rgba(0,0,0,0.8) 0%,transparent 50%);pointer-events:none;';

            // Kapat butonu (sağ üst — overlay'e özel)
            const closeBtn = document.createElement('button');
            closeBtn.innerHTML = '✕';
            closeBtn.style.cssText = 'position:absolute;top:calc(env(safe-area-inset-top, 0px) + 72px);right:16px;z-index:10;width:44px;height:44px;border-radius:50%;background:rgba(0,0,0,0.65);color:#fff;font-size:18px;font-weight:bold;border:1px solid rgba(255,255,255,0.25);display:flex;align-items:center;justify-content:center;cursor:pointer;backdrop-filter:blur(4px);';
            closeBtn.onclick = () => {
                if(mediaEl.tagName === 'VIDEO') {
                    mediaEl.pause();
                    mediaEl.removeAttribute('src');
                    mediaEl.load(); // tarayıcıyı tamamen sıfırla, ses kesilir
                }
                overlay.remove();
                closeReels();
            };

            // Sol alt: kullanıcı + açıklama
            const info = document.createElement('div');
            info.style.cssText = 'position:absolute;bottom:16px;left:16px;right:64px;z-index:10;';
            info.innerHTML = `
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;cursor:pointer;" onclick="showOtherProfile('${escapeHtml(reel.user)}')">
                    <div style="width:36px;height:36px;border-radius:50%;overflow:hidden;border:2px solid #fff;flex-shrink:0;">
                        <img src="${escapeHtml(avatar)}" style="width:100%;height:100%;object-fit:cover;">
                    </div>
                    <span style="color:#fff;font-weight:900;font-size:14px;text-shadow:0 1px 4px rgba(0,0,0,0.8);">${escapeHtml(reel.user)}</span>
                    <span style="color:#a1a1aa;font-size:12px;">${timeAgo}</span>
                </div>
                ${reel.caption ? `<p style="color:#fff;font-size:13px;line-height:1.4;word-break:break-word;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">${escapeHtml(reel.caption)}</p>` : ''}
            `;

            // Sağ: beğeni
            const actions = document.createElement('div');
            actions.style.cssText = 'position:absolute;right:12px;bottom:32px;z-index:10;display:flex;flex-direction:column;align-items:center;gap:16px;';
            const isLiked = (typeof currentUser !== 'undefined' && currentUser) && (reel.likes || []).includes(currentUser.username);
            actions.innerHTML = `
                <div style="display:flex;flex-direction:column;align-items:center;gap:4px;">
                    <div style="width:40px;height:40px;border-radius:50%;background:rgba(0,0,0,0.5);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;font-size:20px;border:1px solid rgba(255,255,255,0.2);">${isLiked ? '❤️' : '🤍'}</div>
                    <span style="color:#fff;font-size:12px;font-weight:bold;">${likeCount}</span>
                </div>
            `;

            overlay.appendChild(mediaEl);
            overlay.appendChild(grad);
            overlay.appendChild(closeBtn);
            overlay.appendChild(info);
            overlay.appendChild(actions);

            if(screenReels) screenReels.appendChild(overlay);
            if(mediaEl.tagName === 'VIDEO') mediaEl.play().catch(()=>{});

            history.pushState({ reelDirect: true }, '');
        };

        // ── Merkezi popstate yöneticisi — tüm reel geri tuşu durumları ──
        window.addEventListener('popstate', function _reelDirectPopstate(e) {
            const state = e.state || {};
            if(state.reelDirect) {
                stopAllMedia();
                const ov = document.getElementById('reel-direct-overlay');
                if(ov) ov.remove();
                closeReels();
            }
            if(state.reelsOpen) {
                stopAllMedia();
                closeReels();
            }
            // reelFullscreen: yukarıdaki ayrı listener zaten handle ediyor
        });

        // ================================================================
        // REELS — YENİ GLOBAL FONKSİYONLAR
        // ================================================================

        // 1. Story varsa story görüntüleyiciyi aç, yoksa profile git
        window.openProfileOrStory = async function(username) {
            if(!username) return;
            const now = Math.floor(Date.now() / 1000);
            const activeStories = (db.stories || []).filter(s => s.user === username && s.expires_at > now);
            if(activeStories.length > 0) {
                // Story viewer'ı o kullanıcının story'siyle aç
                _storyList = activeStories;
                _storyIndex = 0;
                showCurrentStory();
                const modal = document.getElementById('story-view-modal');
                if(modal) modal.classList.remove('hidden');
            } else {
                showOtherProfile(username);
            }
        };

        // 2. Grid ↔ Feed geçiş
        let _reelsGridMode = false;
        let _reelFullscreenIdx = -1;
        let _reelFullscreenOverlay = null;

        window.toggleReelsGridView = function() {
            const feed = document.getElementById('reels-feed');
            const gridBtn = document.getElementById('grid-view-btn');
            const soundBtn = document.getElementById('reel-sound-btn');
            if(!feed) return;

            _reelsGridMode = !_reelsGridMode;

            if(_reelsGridMode) {
                // Grid moda geç
                // Observer'ı durdur — grid'de video otomatik çalmasın
                if(_feedObserver) { _feedObserver.disconnect(); _feedObserver = null; }
                feed.classList.add('grid-mode');
                if(soundBtn) soundBtn.style.display = 'none';
                // Tüm videoları durdur ve sessize al
                feed.querySelectorAll('video').forEach(v => { v.pause(); v.muted = true; });
                // Grid kartlarına click ekle (duplicate önleme: data flag ile)
                feed.querySelectorAll(':scope > div').forEach((card, idx) => {
                    card.dataset.reelIdx = idx;
                    if(!card.dataset.gridClickBound) {
                        card.dataset.gridClickBound = '1';
                        card.addEventListener('click', _onGridCardClick);
                    }
                    card.style.cursor = 'pointer';
                });
                if(gridBtn) gridBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:18px;height:18px;"><rect x="2" y="3" width="20" height="18" rx="2"/><line x1="2" y1="9" x2="22" y2="9"/><line x1="2" y1="15" x2="22" y2="15"/></svg>`;
            } else {
                // Feed moduna dön
                feed.classList.remove('grid-mode');
                if(soundBtn && reelsData.length) soundBtn.style.display = 'flex';
                // Grid click listener'larını kaldır ve flag'i temizle
                feed.querySelectorAll(':scope > div').forEach(card => {
                    card.removeEventListener('click', _onGridCardClick);
                    delete card.dataset.gridClickBound;
                });
                // Observer'ı yeniden kur, mevcut scroll pozisyonunda oynayan videoyu başlat
                _setupFeedObserver();
                if(gridBtn) gridBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:18px;height:18px;"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`;
            }
        };

        // Grid kart click handler (ayrı referans olmalı ki removeEventListener çalışsın)
        function _onGridCardClick(e) {
            const idx = parseInt(this.dataset.reelIdx);
            if(!isNaN(idx)) window.openReelsGridItem(idx);
        }

        // 3. Izgaradan bir video → tam ekran
        // 3. Izgaradan bir video/fotoğraf → tam ekran (body'e ekle → fixed parent sorunu yok)
        window.openReelsGridItem = function(idx) {
            if(!reelsData[idx]) return;
            const reel = reelsData[idx];

            // Önceki overlay varsa sessizce temizle
            window.exitReelFullscreen(true);

            _reelFullscreenIdx = idx;

            const overlay = document.createElement('div');
            overlay.id = 'reel-fs-overlay';
            // body'e fixed ekliyoruz — screenReels'e değil (fixed-in-fixed sorunu çözüldü)
            overlay.style.cssText = 'position:fixed;inset:0;z-index:999999;background:#000;display:flex;align-items:center;justify-content:center;overflow:hidden;';

            // Kapatma butonu
            const closeBtn = document.createElement('button');
            closeBtn.innerHTML = '✕';
            closeBtn.style.cssText = 'position:absolute;top:calc(env(safe-area-inset-top,0px) + 72px);right:16px;z-index:10;width:44px;height:44px;border-radius:50%;background:rgba(0,0,0,0.7);color:#fff;font-size:18px;font-weight:bold;border:1.5px solid rgba(255,255,255,0.35);display:flex;align-items:center;justify-content:center;cursor:pointer;backdrop-filter:blur(4px);box-shadow:0 2px 12px rgba(0,0,0,0.6);';
            closeBtn.onclick = (e) => { e.stopPropagation(); window.exitReelFullscreen(false); };

            if(reel.media_type === 'video') {
                const video = document.createElement('video');
                video.src = reel.media_url;
                video.style.cssText = 'width:100%;height:100%;object-fit:contain;max-height:100%;display:block;';
                video.setAttribute('playsinline', '');
                video.setAttribute('loop', '');
                video.muted = false;
                video.autoplay = true;
                video.addEventListener('click', () => {
                    if(video.paused) video.play().catch(()=>{});
                    else video.pause();
                });
                overlay.appendChild(video);
                video.play().catch(() => { video.muted = true; video.play().catch(() => {}); });
            } else {
                const img = document.createElement('img');
                img.src = reel.media_url;
                img.style.cssText = 'width:100%;height:100%;object-fit:contain;max-height:100%;display:block;';
                overlay.appendChild(img);
            }

            overlay.appendChild(closeBtn);
            document.body.appendChild(overlay);  // ← body'e ekle
            _reelFullscreenOverlay = overlay;

            // Geri tuşu desteği
            history.pushState({ reelFullscreen: true, reelIdx: idx }, '');
        };

        // 4. Tam ekranı kapat → grid görünümüne geri dön
        window.exitReelFullscreen = function(silent) {
            const ov = document.getElementById('reel-fs-overlay');
            if(ov) {
                const v = ov.querySelector('video');
                if(v) { try { v.pause(); v.removeAttribute('src'); v.load(); } catch(_){} }
                ov.remove();
            }
            _reelFullscreenOverlay = null;
            _reelFullscreenIdx = -1;
            // Grid modundaysa ses butonunu gizli tut
            if(_reelsGridMode) {
                const soundBtn = document.getElementById('reel-sound-btn');
                if(soundBtn) soundBtn.style.display = 'none';
            }
        };

        // 5. Geri tuşu / popstate → tam ekranı kapat, grid'e dön
        window.addEventListener('popstate', function(e) {
            if(e.state && e.state.reelFullscreen) {
                window.exitReelFullscreen(false);
                e.preventDefault && e.preventDefault();
            }
        });

        // ================================================================
        // REELS SİSTEMİ JS SONU
        // ================================================================

        async function toggleRidingMode() {
            if(!currentUser) return;
            
            let stats = currentUser.stats || {};
            const isCurrentlyRiding = stats.riding_until && stats.riding_until > Date.now();
            
            if(isCurrentlyRiding) {
                if(confirm("Sürüş modunu kapatmak istiyor musun? Haritadan gizleneceksin.")) {
                    stats.riding_until = 0;
                    await sendAction('update_user', currentUser);
                    
                    document.getElementById("radar-info").classList.add("hidden");
                    document.getElementById("btn-riding-mode").innerHTML = "📡 RADAR (SÜRÜŞTEYİM)";
                    document.getElementById("btn-riding-mode").className = "bg-green-600/90 backdrop-blur hover:bg-green-500 btn-premium-hover px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(34,197,94,0.4)] flex items-center justify-center text-[10px] uppercase tracking-widest font-bold text-white border border-green-400/50 pointer-events-auto";
                    
                    syncMap();
                    alert("Sürüş modu kapatıldı.");
                }
            } else {
                if(!userLat || !userLng) return alert("Konumunuz henüz bulunamadı. Lütfen önce 🎯 butonuna basarak konum izni verin.");
                
                if(confirm("Konumun 3 saat boyunca haritada diğer sürücülere canlı olarak gösterilecek. Onaylıyor musun?")) {
                    stats.riding_until = Date.now() + (3 * 60 * 60 * 1000); 
                    stats.riding_lat = userLat;
                    stats.riding_lng = userLng;
                    
                    await sendAction('update_user', currentUser);
                    
                    document.getElementById("radar-info").classList.remove("hidden");
                    document.getElementById("btn-riding-mode").innerHTML = "🛑 SÜRÜŞÜ BİTİR";
                    document.getElementById("btn-riding-mode").className = "bg-sky-600/90 backdrop-blur hover:bg-red-500 btn-premium-hover px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(14,165,233,0.4)] flex items-center justify-center text-[10px] uppercase tracking-widest font-bold text-white border border-red-400/50 pointer-events-auto";
                    
                    syncMap();
                    alert("Sürüş modu aktif! Artık haritada radar olarak parlıyorsun.");
                }
            }
        }

        // ==============================================================
        // BİSİKLET DÜZENLEME VE SİLME FONKSİYONLARI 
        // ==============================================================
        async function deleteBike(index) {
            if(!confirm("Bu bisikleti garajından kalıcı olarak silmek istediğine emin misin?")) return;
            
            currentUser.stats.garage.splice(index, 1); 
            await sendAction('update_user', currentUser);
            const meIdx2 = db.users.findIndex(u => u.username === currentUser.username);
            if(meIdx2 !== -1) db.users[meIdx2] = {...db.users[meIdx2], stats: currentUser.stats};
            renderGarage(currentUser.username, 'self'); 
            document.getElementById("bike-detail-modal").classList.add("hidden"); 
        }

        function editBike(index) {
            document.getElementById("bike-detail-modal").classList.add("hidden");
            editingBikeIndex = index;
            const b = currentUser.stats.garage[index];
            if(!b) return;

            // Fill all fields safely
            const sf = (id, val) => { const el=document.getElementById(id); if(el) el.value=val||""; };
            sf("bike-model",    b.model);
            sf("bike-type",     b.type);
            sf("bike-fork",     b.fork);
            sf("bike-shock",    b.shock);
            sf("bike-brakes",   b.brakes);
            sf("bike-rotor",    b.rotor);
            sf("bike-drivetrain",b.drivetrain);
            sf("bike-chain",    b.chain);
            sf("bike-crankset", b.crankset);
            sf("bike-cassette", b.cassette);
            sf("bike-wheelset", b.wheelset);
            sf("bike-tires",    b.tires);
            sf("bike-tire-size",b.tire_size);
            sf("bike-handlebar",b.handlebar);
            sf("bike-stem",     b.stem);
            sf("bike-grips",    b.grips);
            sf("bike-seatpost", b.seatpost);
            sf("bike-saddle",   b.saddle);
            sf("bike-pedals",   b.pedals);
            sf("bike-weight",   b.weight);
            sf("bike-desc",     b.desc);
            sf("bike-photo",    "");

            const premTier = getUserPremiumTier(currentUser.username);
            let maxPhotos = premTier>=3?10:premTier>=2?4:premTier>=1?2:1;
            const lbl = document.getElementById("bike-photo-label");
            if(lbl) lbl.textContent = `Yeni Fotograf (Maks ${maxPhotos}) - Bos birakırsan eskileri kalır`;

            document.getElementById("add-bike-modal").classList.remove("hidden");
        }

        function openAddBikeModal() {
            if(!currentUser) return;
            editingBikeIndex = null; 
            
            const premTier = getUserPremiumTier(currentUser.username); 
            const garage = currentUser.stats.garage || [];
            
            let maxBikes = 0; 
            let maxPhotos = 1;
            
            if(premTier === 1) { maxBikes = 1; maxPhotos = 2; }
            if(premTier === 2) { maxBikes = 2; maxPhotos = 4; }
            if(premTier === 3) { maxBikes = 4; maxPhotos = 10; }
            
            if(premTier === 0) {
                alert("Plus üyeliği olmayan kullanıcılar garaja bisiklet ekleyemez! Pazar veya Plus menüsünden üyeliğini yükselt.");
                switchTab(6);
                return;
            }
            if(garage.length >= maxBikes) {
                return alert(`Mevcut paketiniz garajınıza en fazla ${maxBikes} bisiklet eklemenize izin veriyor! Plus menüsünden paketinizi yükseltin.`);
            }

            document.getElementById("bike-model").value = ""; 
            document.getElementById("bike-fork").value = ""; 
            document.getElementById("bike-shock").value = ""; 
            document.getElementById("bike-brakes").value = ""; 
            document.getElementById("bike-desc").value = ""; 
            document.getElementById("bike-photo").value = "";
            document.getElementById("bike-photo-label").textContent = `Bisiklet Fotoğrafları (Maksimum ${maxPhotos} adet)`;
            document.getElementById("add-bike-modal").classList.remove("hidden");
        }
        
        async function saveBike() {
            const premTier = getUserPremiumTier(currentUser.username);
            const model = document.getElementById("bike-model").value.trim();
            const type = document.getElementById("bike-type").value;
            const files = document.getElementById("bike-photo").files;

            if(!model) return alert("Bisiklet marka/modelini giriniz!");

            for(let i=0; i<files.length; i++) {
                if(!checkFileSize(files[i], 10)) return;
            }
            let maxPhotos = premTier >= 3 ? 10 : premTier >= 2 ? 4 : premTier >= 1 ? 2 : 1;
            if(files.length > maxPhotos) return alert(`En fazla ${maxPhotos} fotograf ekleyebilirsiniz.`);

            const g = id => { const el=document.getElementById(id); return el?el.value.trim():""; };
            const bikeData = {
                model, type,
                fork:        g("bike-fork"),
                shock:       g("bike-shock"),
                brakes:      g("bike-brakes"),
                rotor:       g("bike-rotor"),
                drivetrain:  g("bike-drivetrain"),
                chain:       g("bike-chain"),
                crankset:    g("bike-crankset"),
                cassette:    g("bike-cassette"),
                wheelset:    g("bike-wheelset"),
                tires:       g("bike-tires"),
                tire_size:   g("bike-tire-size"),
                handlebar:   g("bike-handlebar"),
                stem:        g("bike-stem"),
                grips:       g("bike-grips"),
                seatpost:    g("bike-seatpost"),
                saddle:      g("bike-saddle"),
                pedals:      g("bike-pedals"),
                weight:      g("bike-weight"),
                desc:        g("bike-desc"),
            };

            document.getElementById("add-bike-modal").classList.add("hidden");

            let photoDataArray = [];
            for(let i=0; i<Math.min(files.length, maxPhotos); i++) {
                let b64 = await resizeImage(files[i], 800);
                if(b64) photoDataArray.push(b64);
            }

            if(editingBikeIndex !== null) {
                const existing = currentUser.stats.garage[editingBikeIndex];
                Object.assign(existing, bikeData);
                if(photoDataArray.length > 0) existing.image = photoDataArray;
                alert("Bisiklet guncellendi!");
            } else {
                if(photoDataArray.length === 0) photoDataArray = ["https://placehold.co/400x300/121214/FFF?text=FOTO+YOK"];
                if(!currentUser.stats) currentUser.stats = {};
                if(!currentUser.stats.garage) currentUser.stats.garage = [];
                bikeData.id = Date.now();
                bikeData.image = photoDataArray;
                currentUser.stats.garage.push(bikeData);
                alert("Bisiklet garaja eklendi!");
            }
            await sendAction('update_user', currentUser);
            // Lokal db'yi güncelle
            const meIdx = db.users.findIndex(u => u.username === currentUser.username);
            if(meIdx !== -1) db.users[meIdx] = {...db.users[meIdx], stats: currentUser.stats};
            renderGarage(currentUser.username, 'self');
            editingBikeIndex = null;
        }
        function viewBikeDetail(username, index) {
            const u = db.users.find(x => x.username === username);
            if(!u || !u.stats || !u.stats.garage || !u.stats.garage[index]) return;
            const b = u.stats.garage[index];

            const imgContainer = document.getElementById("bd-image-container");
            imgContainer.innerHTML = "";
            let images = Array.isArray(b.image) ? b.image : [b.image||"https://placehold.co/400x300/121214/FFF?text=FOTO+YOK"];
            images.forEach(img => {
                imgContainer.innerHTML += `<img src="${img}" onclick="openFullscreen(images,${imgContainer.children.length})" class="h-full w-auto object-contain shrink-0 rounded-xl scroll-snap-align-center cursor-pointer hover:opacity-90 transition-opacity">`;
            });

            // Basic
            document.getElementById("bd-model").textContent  = b.model || "-";
            document.getElementById("bd-type").textContent   = b.type  || "-";
            document.getElementById("bd-fork").textContent   = b.fork  || "Belirtilmemis";
            document.getElementById("bd-shock").textContent  = b.shock || "Belirtilmemis";
            document.getElementById("bd-brakes").textContent = b.brakes|| "Belirtilmemis";
            document.getElementById("bd-desc").textContent   = b.desc  || "Belirtilmemis";

            // Extended fields - add dynamically if container exists
            const extra = document.getElementById("bd-extra-specs");
            if(extra) {
                const fields = [
                    ["Disk Caplaari", b.rotor],
                    ["Vites Sistemi", b.drivetrain],
                    ["Zincir", b.chain],
                    ["Krank / BB", b.crankset],
                    ["Kasnak", b.cassette],
                    ["Jantlar", b.wheelset],
                    ["Lastikler", b.tires],
                    ["Lastik Boyutu", b.tire_size],
                    ["Gidon", b.handlebar],
                    ["Stem", b.stem],
                    ["Tutus", b.grips],
                    ["Seatpost", b.seatpost],
                    ["Sele", b.saddle],
                    ["Pedallar", b.pedals],
                    ["Agirlik", b.weight],
                ];
                let extraHtml = "";
                fields.forEach(([label, val]) => {
                    if(val) extraHtml += `<div class="flex justify-between py-2 border-b border-zinc-800/50">
                        <span class="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">${label}</span>
                        <span class="text-xs text-zinc-200 font-medium text-right max-w-[55%]">${val}</span>
                    </div>`;
                });
                extra.innerHTML = extraHtml || "<div class='text-zinc-600 text-xs italic'>Ek detay girilmemis.</div>";
            }

            const actionsArea = document.getElementById("bd-actions-area");
            if(actionsArea) {
                if(username === currentUser.username) {
                    actionsArea.innerHTML = `
                        <button onclick="editBike(${index})" class="flex-1 bg-blue-900/50 hover:bg-blue-800 btn-premium-hover transition text-blue-400 border border-blue-500/50 py-3 rounded-xl font-bold text-xs uppercase tracking-widest shadow-lg">DUZENLE</button>
                        <button onclick="deleteBike(${index})" class="flex-1 bg-red-950/50 hover:bg-sky-900/80 btn-premium-hover transition text-sky-400 border border-sky-900/50 py-3 rounded-xl font-bold text-xs uppercase tracking-widest">SIL</button>`;
                } else {
                    actionsArea.innerHTML = "";
                }
            }
            document.getElementById("bike-detail-modal").classList.remove("hidden");
        }

        function renderGarage(username, targetDivId = 'self') {
            const isSelf = targetDivId === 'self'; 
            const container = document.getElementById(isSelf ? "garage-list" : "op-garage"); 
            
            if(!container) return;
            
            let u = isSelf ? currentUser : db.users.find(x => x.username === username);
            
            if(!u || !u.stats || !u.stats.garage || u.stats.garage.length === 0) { 
                container.innerHTML = "<div class='col-span-2 text-center text-xs text-zinc-500 italic py-4'>Garaj boş.</div>"; 
                return; 
            }
            
            container.innerHTML = "";
            
            u.stats.garage.forEach((b, index) => {
                let delBtn = isSelf 
                    ? `<button onclick="event.stopPropagation(); deleteBike(${index})" class="absolute top-1 right-1 bg-red-600 hover:bg-red-500 transition w-6 h-6 rounded-full flex items-center justify-center text-white text-xs shadow-md z-20 btn-premium-hover">✕</button>` 
                    : '';
                
                let mainImg = Array.isArray(b.image) ? b.image[0] : (b.image || "https://placehold.co/400x300/121214/FFF?text=FOTO+YOK");
                
                container.innerHTML += `
                <div onclick="viewBikeDetail('${u.username}', ${index})" class="bg-black/50 rounded-xl overflow-hidden border border-zinc-800 shadow-md relative group cursor-pointer hover:border-zinc-500 transition btn-premium-hover">
                    ${delBtn}
                    <img src="${mainImg}" class="w-full h-24 object-cover">
                    <div class="p-2">
                        <div class="font-bold text-white text-[11px] truncate tracking-wide">${b.model}</div>
                        <div class="text-zinc-500 text-[9px] mt-0.5 truncate uppercase font-bold tracking-widest">${b.type}</div>
                    </div>
                </div>`;
            });
        }

        async function logout() {
            if(confirm("Sistemden çıkış yapmak istediğine emin misin?")) {
                try {
                    await sendAction('logout', {});
                } catch(e) {
                    console.log("Sunucu çıkış hatası, yerel veriler temizleniyor...");
                }
                
                localStorage.removeItem("fr_user");
                currentUser = null;
                
                window.location.reload();
            }
        }
        
        function loginSuccess() { 
            document.getElementById("login-screen").classList.add("hidden"); 
            document.getElementById("main-app").classList.remove("hidden");
            const _bnav = document.getElementById("bottom-nav");
            if(_bnav) _bnav.style.display = '';
            // Önceki oturumdan mesaj cache'i yükle (anlık görünsün)
            try {
                const cached = localStorage.getItem('fr_msg_cache');
                if(cached) {
                    const msgs = JSON.parse(cached);
                    if(msgs && msgs.length > 0 && db.messages.length === 0) {
                        db.messages = msgs;
                    }
                }
            } catch(e) {}
            
            // Trial bitti mi kontrol
            if(currentUser.stats && currentUser.stats.trial_expired) {
                setTimeout(() => showTrialExpiredModal(), 2000);
            }
            // Trial aktif - banner goster
            if(currentUser.stats && currentUser.stats.is_trial && currentUser.stats.premium_tier === 3) {
                setTimeout(() => showTrialBanner(), 800);
            } 
            
            updateProfileUI(); 
            initMap(); 
            switchTab(0); 
            renderChat(true);
            // Çarkı önceden çiz — sekmede açılınca zaten hazır olsun
            setTimeout(initWheel3D, 500); 

            // ── Premium Reklam: Giriş sonrası 30 saniyede bir kez %100 göster ──
            // SessionStorage sayesinde sekme kapatılınca sıfırlanır, sayfa yenilemede tekrar çalışır
            if (!sessionStorage.getItem('fr_premium_shown')) {
                setTimeout(() => {
                    // Kullanıcı zaten premium sekmesindeyse tekrar yönlendirme
                    const premiumEl = document.getElementById('screen-premium');
                    if (premiumEl && premiumEl.style.display !== 'none' && !premiumEl.classList.contains('hidden')) return;
                    // Premium üye ise (tier >= 2) reklam gösterme
                    if (getUserPremiumTier && typeof getUserPremiumTier === 'function' && getUserPremiumTier(currentUser.username) >= 2) return;
                    sessionStorage.setItem('fr_premium_shown', '1');
                    switchTab(6);
                }, 30000); // 30 saniye
            }
            
            currentMessageCount = db.messages.length; 
            
            if(currentUser.stats && currentUser.stats.riding_until > Date.now()) {
                document.getElementById("radar-info").classList.remove("hidden");
                document.getElementById("btn-riding-mode").innerHTML = "🛑 SÜRÜŞÜ BİTİR";
                document.getElementById("btn-riding-mode").className = "bg-sky-600/90 backdrop-blur hover:bg-red-500 btn-premium-hover transition px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(14,165,233,0.4)] flex items-center justify-center text-[10px] uppercase tracking-widest font-bold text-white border border-red-400/50 pointer-events-auto";
            }
            
            if (currentUser.stats && currentUser.stats.onboarding === false) {
                // Deneme bitiş tarihini doldur
                const expDate = currentUser.stats.premium_expire_date || '';
                const trialDateEl = document.getElementById('onboarding-trial-date');
                if(trialDateEl && expDate) {
                    trialDateEl.textContent = '⏰ Deneme Bitiş Tarihi: ' + expDate;
                }
                document.getElementById("onboarding-modal").classList.remove("hidden");
            }

            updateMyLocation();
            sendHeartbeat();
            // Heartbeat: her 30 sn (çevrim içi doğruluk için)
            setInterval(sendHeartbeat, 60000);
            // Konum + radar: her 60 sn
            setInterval(() => {
                updateMyLocation();
                refreshRadars();
            }, 60000);
            // Push bildirim: Profil sayfasındaki butondan açılıyor
            updateNotifBtnState();
            loadSavedTheme();
            _lastTitleName = getTitle(currentUser.xp).name;
            // OneSignal: kullanıcı kimliğini set et (bildirim hedefleme için)
            // setTimeout yerine doğrudan çağır — setOneSignalUser içinde Deferred kuyruğu kullanılıyor
            setOneSignalUser();
        }

        async function refreshRadars() {
            try {
                const now = Date.now();
                // stats bir JSONB kolon - nested select sözdizimi yanlış, direkt stats seç
                const { data, error } = await supaClient.from('users')
                    .select('username, stats');
                        
                if (data && !error) {
                    data.forEach(fetchedUser => {
                        const s = fetchedUser.stats;
                        if (!s) return;
                        let existingUser = db.users.find(u => u.username === fetchedUser.username);
                        if (existingUser) {
                            if(!existingUser.stats) existingUser.stats = {};
                            // Radar güncelle
                            existingUser.stats.riding_lat = s.riding_lat;
                            existingUser.stats.riding_lng = s.riding_lng;
                            existingUser.stats.riding_until = s.riding_until;
                            // ÇEVRİM İÇİ: last_seen_ts güncelle (kritik!)
                            if (s.last_seen_ts) existingUser.stats.last_seen_ts = s.last_seen_ts;
                        }
                    });
                    if (map) syncMap();
                }
            } catch(e) { console.error("Radar hatası:", e); }
        }

        function updateProfileUI() {
            if(!currentUser) return;
            checkLevelUp();
            
            const stats = currentUser.stats || { markers: 0, events: 0, market: 0, profile_views: 0 };
            const premTier = parseInt(stats.premium_tier) || 0; 
            const premColor = stats.premium_color || 'std-blue';
            
            const textCls = (premTier > 0) ? getPremiumTextClass(premColor) : ''; 
            const inlineStyle = (premTier > 0) ? getPremiumInlineStyle(premColor) : '';
            const borderCls = (premTier > 0) ? getPremiumBorderClass(currentUser.username) : 'border-zinc-700';
            
            let tick = (premTier === 3) ? verifiedTick : ''; 
            let adminTag = (currentUser.role === 'Admin') ? '<span class="ml-2 bg-red-600 text-white px-2 py-0.5 rounded text-[9px] tracking-widest uppercase shadow-[0_0_10px_red] relative z-50">👑 Yönetici</span>' : (currentUser.role === 'SubAdmin' ? '<span class="ml-2 bg-orange-800 text-orange-200 px-2 py-0.5 rounded text-[9px] uppercase font-bold tracking-widest">🛡️ Yrd. Admin</span>' : '');
            
            const topUserEl = document.getElementById("top-username");
            topUserEl.innerHTML = `${currentUser.username} ${tick} ${adminTag}`; 
            topUserEl.className = `font-bold text-sm flex items-center transition-all ${textCls ? textCls : 'text-white'}`;
            topUserEl.setAttribute("style", inlineStyle);

            document.getElementById("top-avatar").src = currentUser.avatar || `https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg`; 
            document.getElementById("top-avatar").className = `w-10 h-10 rounded-full object-cover border transition-all ${borderCls}`;
            
            const title = getTitle(currentUser.xp); 
            document.getElementById("top-title").textContent = title.name;
            
            const profileNameEl = document.getElementById("profile-name");
            profileNameEl.innerHTML = `${currentUser.username} ${tick} ${adminTag}`; 
            profileNameEl.className = `text-4xl font-bold break-all teko-font tracking-wide flex justify-center items-center gap-2 drop-shadow-md transition-all ${textCls ? textCls : 'text-white'}`;
            profileNameEl.setAttribute("style", inlineStyle);

            document.getElementById("profile-bio").textContent = currentUser.bio || "Biyografi eklenmemiş."; 
            document.getElementById("profile-xp").textContent = currentUser.xp;
            
            document.getElementById("profile-avatar").src = currentUser.avatar || `https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg`; 
            document.getElementById("profile-avatar").className = `w-32 h-32 mx-auto rounded-full object-cover cursor-pointer bg-zinc-900 border-4 transition-all duration-300 group-hover:scale-105 ${borderCls}`;
            // Parcacik efektini uygula
            const myEffect = (currentUser.stats && currentUser.stats.avatar_effect) || 'none';
            applyAvatarEffect(myEffect);

            // Streak freeze badge
            const freezeBadge = document.getElementById('streak-freeze-badge');
            const freezeCount = document.getElementById('streak-freeze-count');
            const freezeAmt = parseInt(stats.streak_freeze||0);
            if(freezeBadge) {
                if(freezeAmt > 0) {
                    freezeBadge.classList.remove('hidden');
                    if(freezeCount) freezeCount.textContent = freezeAmt + ' adet kalkaning var';
                } else {
                    freezeBadge.classList.add('hidden');
                }
            }

            // Profil goruntuleme butonu guncelle
            const viewerBtn = document.getElementById('profile-viewer-btn-text');
            if(viewerBtn) {
                const viewCount = stats.profile_views || 0;
                const viewers = stats.profile_viewer_log || [];
                viewerBtn.textContent = viewCount + ' Profil Goruntulemesi - Kimlerin Gordu?';
            }
            document.getElementById("profile-title").textContent = title.icon + " " + title.name;
            document.getElementById("profile-title").className = `text-lg font-bold mt-2 drop-shadow-sm transition-colors ${title.color}`;

            // XP ilerleme cubugu
            const prog = getTitleProgress(currentUser.xp);
            const xpBarEl = document.getElementById("profile-xp-progress");
            if(xpBarEl) {
                if(prog.nextName) {
                    xpBarEl.innerHTML = `
                    <div class="mt-3 px-2">
                        <div class="flex justify-between text-[10px] font-bold uppercase tracking-widest mb-1">
                            <span class="${title.color}">${title.icon} ${title.name}</span>
                            <span class="text-zinc-400">${prog.xpLeft} XP sonra ${prog.nextIcon} ${prog.nextName}</span>
                        </div>
                        <div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden border border-zinc-700">
                            <div class="h-full rounded-full transition-all duration-700" style="width:${prog.percent}%;background:linear-gradient(90deg,#0ea5e9,#f59e0b);box-shadow:0 0 8px rgba(14,165,233,0.5);"></div>
                        </div>
                        <div class="text-center text-[10px] text-zinc-500 mt-1 font-bold">${prog.percent}% tamamlandi</div>
                    </div>`;
                } else {
                    xpBarEl.innerHTML = `<div class="mt-2 text-center text-xs font-bold text-prem-rainbow">MAX SEVIYE 🌟</div>`;
                }
            }

            let badges = "";
            // Premium badges - all with explicit blocks to avoid else-if chain issues
            if(stats.is_trial) { badges += `<span class="bg-gradient-to-r from-yellow-500 to-amber-400 text-black px-3 py-1.5 rounded-lg text-[10px] font-black shadow-[0_0_15px_rgba(234,179,8,0.6)] uppercase tracking-widest scale-in-anim animate-pulse">🎁 3 Gun Deneme</span> `; }
            if(premTier === 3) { badges += `<span class="bg-yellow-500 text-black px-3 py-1.5 rounded-lg text-[10px] font-black shadow-[0_0_15px_rgba(234,179,8,0.5)] uppercase tracking-widest scale-in-anim">👑 Ultra+</span> `; }
            else if(premTier === 2) { badges += `<span class="bg-purple-600 text-white px-3 py-1.5 rounded-lg text-[10px] font-bold shadow-[0_0_15px_rgba(168,85,247,0.5)] uppercase tracking-widest scale-in-anim">🌟 Deluxe</span> `; }
            else if(premTier === 1) { badges += `<span class="bg-gradient-to-r from-blue-600 to-purple-600 text-white px-3 py-1.5 rounded-lg text-[10px] font-bold shadow-lg uppercase tracking-widest scale-in-anim">⭐ Standart</span> `; }
            // Activity badges
            if(stats.markers >= 10){ badges += `<span class="bg-emerald-900/50 text-emerald-300 border border-emerald-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">🗺️ Haritaci</span> `; }
            else if(stats.markers >= 1){ badges += `<span class="bg-zinc-800 text-zinc-300 border border-zinc-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">📍 Kasif</span> `; }
            if(stats.events >= 5){ badges += `<span class="bg-blue-900/50 text-blue-300 border border-blue-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">🏆 Topluluk Lideri</span> `; }
            else if(stats.events >= 1){ badges += `<span class="bg-zinc-800 text-zinc-300 border border-zinc-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">📅 Organizator</span> `; }
            if(stats.market >= 5){ badges += `<span class="bg-amber-900/50 text-amber-300 border border-amber-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">💰 Pazar Ustasi</span> `; }
            else if(stats.market >= 1){ badges += `<span class="bg-zinc-800 text-zinc-300 border border-zinc-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">🤝 Esnaf</span> `; }
            if(stats.login_streak >= 100){ badges += `<span class="bg-violet-900/50 text-violet-300 border border-violet-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">⚡ 100 Gun</span> `; }
            else if(stats.login_streak >= 30){ badges += `<span class="bg-indigo-900/50 text-indigo-300 border border-indigo-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">💎 Demir Uye</span> `; }
            else if(stats.login_streak >= 7){ badges += `<span class="bg-orange-900/50 text-orange-300 border border-orange-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">🔥 Seri Girisci</span> `; }
            if(stats.total_messages >= 200){ badges += `<span class="bg-cyan-900/50 text-cyan-300 border border-cyan-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">👑 Chat Efsanesi</span> `; }
            else if(stats.total_messages >= 50){ badges += `<span class="bg-zinc-800 text-zinc-300 border border-zinc-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">🗣️ Sohbet Tutkunu</span> `; }
            // XP level badges
            if(currentUser.xp >= 50000){ badges += `<span class="bg-gradient-to-r from-red-700 to-purple-700 text-white px-2 py-1 rounded-lg text-[10px] font-black scale-in-anim text-prem-rainbow">🌟 Downhill Efsanesi</span> `; }
            else if(currentUser.xp >= 20000){ badges += `<span class="bg-red-900/50 text-red-300 border border-sky-600 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">👑 Efsane</span> `; }
            else if(currentUser.xp >= 10000){ badges += `<span class="bg-yellow-900/50 text-yellow-300 border border-yellow-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">🏆 Sampiyon</span> `; }
            else if(currentUser.xp >= 7000){ badges += `<span class="bg-rose-900/50 text-rose-300 border border-rose-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">💥 Elite</span> `; }
            else if(currentUser.xp >= 4000){ badges += `<span class="bg-orange-900/50 text-orange-300 border border-orange-700 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">🔥 Usta</span> `; }
            // Earned mission badges
            const eb = stats.earned_badges || [];
            eb.forEach(b => { badges += `<span class="bg-zinc-800 text-zinc-200 border border-zinc-600 px-2 py-1 rounded-lg text-[10px] font-bold scale-in-anim">🏅 ${b}</span> `; });

            if(!badges.trim()) {
                badges = "<span class='text-zinc-600 text-xs italic font-medium'>Henuz kazanilmis bir rozet yok.</span>";
            }
            document.getElementById("profile-badges").innerHTML = badges;
            
            if (currentUser.role === 'Admin' || currentUser.role === 'SubAdmin') {
                document.getElementById("admin-btn").classList.remove("hidden");
            } else {
                document.getElementById("admin-btn").classList.add("hidden");
            }
            
            if(premTier > 0) {
                document.getElementById("premium-buy-section").classList.add("hidden");
                document.getElementById("premium-settings-section").classList.remove("hidden");

                // Paket kartlarını gizle (zaten üye, tekrar satın alma görseli gösterme)
                const packageCardsWrap = document.querySelector('#screen-premium .space-y-4');
                if (packageCardsWrap) packageCardsWrap.classList.add('hidden');

                // Aktif plan kartını doldur
                const planNames = { 1: '⭐ Standart Paket', 2: '🌟 Deluxe Paket', 3: '👑 Ultra+ Paket' };
                const planColors = { 1: 'bg-blue-900/60 text-blue-300 border border-blue-700/50', 2: 'bg-purple-900/60 text-purple-300 border border-purple-700/50', 3: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50' };
                const planNameEl = document.getElementById('current-plan-name');
                const planBadgeEl = document.getElementById('current-plan-badge');
                const planExpiryEl = document.getElementById('current-plan-expiry');
                if (planNameEl) planNameEl.textContent = planNames[premTier] || 'Plus Üye';
                if (planBadgeEl) { planBadgeEl.textContent = 'AKTİF'; planBadgeEl.className = 'text-xs font-black px-3 py-1 rounded-lg ' + (planColors[premTier] || ''); }
                if (planExpiryEl) {
                    const expDate = stats.premium_expire_date;
                    planExpiryEl.textContent = expDate ? '📅 Bitiş tarihi: ' + expDate : '♾️ Süresiz aktif';
                }

                // Yükselt butonu: Standart (1) veya Deluxe (2) kullanıcısına göster, Ultra+ (3) için gizle
                const upgradeSec = document.getElementById('upgrade-plan-section');
                const upgradeSelect = document.getElementById('upgrade-tier-select');
                const upgradeHint = document.getElementById('upgrade-hint-text');
                if (premTier < 3 && upgradeSec && upgradeSelect) {
                    upgradeSec.classList.remove('hidden');
                    upgradeSelect.innerHTML = '';
                    if (premTier === 1) {
                        upgradeSelect.innerHTML += '<option value="freeridertr_deluxe_pack_monthly">🌟 Deluxe Paket — 50 TL/Ay</option>';
                        upgradeSelect.innerHTML += '<option value="freeridertr_ultra_pack_monthly">👑 Ultra+ Paket — 75 TL/Ay</option>';
                        if (upgradeHint) upgradeHint.textContent = 'Deluxe veya Ultra+ a gecerek daha fazla ozellik ac.';
                    } else if (premTier === 2) {
                        upgradeSelect.innerHTML += '<option value="freeridertr_ultra_pack_monthly">👑 Ultra+ Paket — 75 TL/Ay</option>';
                        if (upgradeHint) upgradeHint.textContent = 'Ultra+ a gecerek tum ozelliklerin kilidini ac.';
                    }
                } else if (upgradeSec) {
                    upgradeSec.classList.add('hidden');
                }

                const colorContainer = document.getElementById("color-options");
                if(colorContainer) {
                    let html = "";
                    if (premTier >= 1) {
                        html += `<div class="w-full text-[10px] text-zinc-500 uppercase tracking-widest font-bold mb-1 mt-2">Standart Renkler:</div>`;
                        html += createColorBtn('std-blue', 'Mavi', premColor);
                        html += createColorBtn('std-yellow', 'Sarı', premColor);
                        html += createColorBtn('std-pink', 'Pembe', premColor);
                        html += createColorBtn('std-green', 'Yeşil', premColor);
                    }
                    if (premTier >= 2) {
                        html += `<div class="w-full text-[10px] text-yellow-500 uppercase tracking-widest font-bold mb-1 mt-3 border-t border-zinc-800 pt-3">Deluxe Renkler:</div>`;
                        html += createColorBtn('ult-gold', 'Altın', premColor);
                        html += createColorBtn('ult-rainbow', 'Gökkuşağı', premColor);
                        html += createColorBtn('dlx-blue', 'Simli Mavi', premColor);
                        html += createColorBtn('dlx-pink', 'Simli Pembe', premColor);
                        html += createColorBtn('dlx-green', 'Simli Yeşil', premColor);
                    }
                    if (premTier >= 3) {
                        html += `<div class="w-full text-[10px] text-sky-400 uppercase tracking-widest font-bold mb-1 mt-3 border-t border-zinc-800 pt-3">Ultra+ Özel Renk (Hex):</div>`;
                        html += `<div class="w-full flex gap-2 mb-2 items-center">
                                    <input type="color" id="custom-hex-color" class="w-12 h-10 rounded cursor-pointer bg-zinc-900 border border-zinc-700 shadow-inner" value="${premColor.startsWith('#') ? premColor : '#ff0000'}">
                                    <button onclick="applyCustomHex()" class="bg-white text-black px-4 py-2 rounded-lg text-xs font-bold shadow-lg hover:bg-gray-200 transition btn-premium-hover">Uygula</button>
                                 </div>`;
                        
                        html += `<div class="w-full text-[10px] text-sky-400 uppercase tracking-widest font-bold mb-1 mt-2">Ultra+ Profil Efekti:</div>`;
                        const currentEffect = stats.avatar_effect || 'none';
                        html += createEffectBtn('none', 'Efekt Yok', currentEffect);
                        html += createEffectBtn('fire', '🔥 Alev', currentEffect);
                        html += createEffectBtn('ice', '❄️ Buz', currentEffect);
                    }
                    colorContainer.innerHTML = html;
                }
            } else {
                document.getElementById("premium-buy-section").classList.remove("hidden");
                document.getElementById("premium-settings-section").classList.add("hidden");
                // Üye değilse paket kartlarını tekrar göster
                const packageCardsWrap = document.querySelector('#screen-premium .space-y-4');
                if (packageCardsWrap) packageCardsWrap.classList.remove('hidden');
            }
            
            renderGarage(currentUser.username, 'self');
        }

        // ── Google Play IAP Satın Alma Akışı ──────────────────────────────────────
        // requestPremium() fonksiyonu artık Google Play Billing Library'yi tetikler.
        // Mobil uygulama (WebView içinde), bu fonksiyonu çağıran JS Bridge üzerinden
        // Android uygulamasına productId'yi iletir ve satın alım akışını başlatır.
        // Satın alım tamamlandığında Android, verifyGooglePurchase() fonksiyonunu
        // çağırarak purchaseToken'ı backend'e doğrulama için gönderir.
        async function requestPremium() {
            const sel = document.getElementById("premium-tier-select");
            if (!sel) { showToast('⚠️ Ürün seçici bulunamadı.'); return; }
            const productId = sel.value;
            if (!productId) { showToast('⚠️ Lütfen bir paket seçin.'); return; }

            // ── Android WebView JS Bridge kontrolü ──────────────────────────────
            // window.Android nesnesi yoksa veya launchBilling metodu tanımlı değilse
            // uyarı göster; uygulamayı çökertme.
            if (typeof window.Android !== 'undefined' && window.Android !== null) {
                if (typeof window.Android.launchBilling === 'function') {
                    try {
                        window.Android.launchBilling(productId);
                    } catch(e) {
                        showToast('Google Play başlatılamadı. Lütfen tekrar deneyin.');
                        console.error('[IAP] launchBilling hatası:', e);
                    }
                    return;
                } else {
                    // window.Android var ama launchBilling metodu yok → eski uygulama sürümü
                    showToast("⚠️ Uygulama güncel değil. Lütfen Google Play'den güncelleyin.");
                    console.warn('[IAP] window.Android mevcut ama launchBilling metodu yok.');
                    return;
                }
            }

            // iOS WKWebView köprüsü (gelecekteki iOS desteği için)
            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.billing) {
                try {
                    window.webkit.messageHandlers.billing.postMessage({ productId });
                } catch(e) {
                    showToast('In-app satın alım başlatılamadı.');
                }
                return;
            }

            // Tarayıcı ortamı (test/geliştirme) — satın alım başlatılamaz
            showToast("Bu özellik yalnızca mobil uygulama üzerinden kullanılabilir. Lütfen Google Play'den FreeriderTR uygulamasını açın.");
        }

        // ── Üyelik Yükseltme ─────────────────────────────────────────────────────
        async function requestUpgrade() {
            const sel = document.getElementById("upgrade-tier-select");
            if (!sel) { showToast('⚠️ Yükseltme seçici bulunamadı.'); return; }
            const productId = sel.value;
            if (!productId) { showToast('⚠️ Lütfen bir paket seçin.'); return; }

            if (typeof window.Android !== 'undefined' && window.Android !== null) {
                if (typeof window.Android.launchBilling === 'function') {
                    try {
                        window.Android.launchBilling(productId);
                    } catch(e) {
                        showToast('Google Play başlatılamadı. Lütfen tekrar deneyin.');
                        console.error('[IAP] launchBilling hatası:', e);
                    }
                    return;
                } else {
                    showToast("⚠️ Uygulama güncel değil. Lütfen Google Play'den güncelleyin.");
                    return;
                }
            }
            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.billing) {
                try { window.webkit.messageHandlers.billing.postMessage({ productId }); } catch(e) { showToast('In-app satın alım başlatılamadı.'); }
                return;
            }
            showToast("Bu özellik yalnızca mobil uygulama üzerinden kullanılabilir. Lütfen Google Play'den FreeriderTR uygulamasını açın.");
        }

        // Android uygulaması satın alım tamamlandığında bu fonksiyonu çağırır.
        // Android kodu: webView.evaluateJavascript("verifyGooglePurchase(...)", null);
        async function verifyGooglePurchase(purchaseToken, productId, purchaseType) {
            try {
                showToast('Ödeme doğrulanıyor...');
                const res = await fetch('/api/verify_google_purchase', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        purchaseToken: purchaseToken,
                        productId:     productId,
                        purchaseType:  purchaseType || 'subscription'
                    })
                });
                const json = await res.json();
                if (json.status === 'ok') {
                    showToast('✅ Aboneliğin aktive edildi! Hoş geldin.');
                    // Kullanıcı verilerini yenile
                    await loadMyData();
                    renderProfile();
                } else {
                    showToast('⚠️ Doğrulama hatası: ' + (json.message || 'Bilinmeyen hata'));
                }
            } catch(e) {
                showToast('Ağ hatası oluştu, lütfen tekrar deneyin.');
            }
        }

        async function showOtherProfile(targetUsername) {
            if(targetUsername === currentUser.username) { 
                switchTab(7); 
                document.getElementById('market-detail-modal').classList.add('hidden'); 
                return; 
            }
            
            let u = db.users.find(x => x.username === targetUsername); 
            if(!u) {
                try {
                    const { data, error } = await supaClient.from('users').select('*').eq('username', targetUsername).single();
                    if(data) {
                        u = data;
                        db.users.push(u);
                    } else {
                        return;
                    }
                } catch(e) { return; }
            }

            sendAction('increment_profile_view', { username: targetUsername }).catch(e => {});

            const stats = u.stats || { markers: 0, events: 0, market: 0, profile_views: 0 };
            const premTier = parseInt(stats.premium_tier) || 0; 
            const premColor = stats.premium_color || 'std-blue';
            
            const textCls = (premTier > 0) ? getPremiumTextClass(premColor) : ''; 
            const inlineStyle = (premTier > 0) ? getPremiumInlineStyle(premColor) : '';
            const borderCls = (premTier > 0) ? getPremiumBorderClass(u.username) : 'border-zinc-700';
            
            let tick = (premTier === 3) ? verifiedTick : ''; 
            let adminTag = (u.role === 'Admin') ? '<span class="ml-2 bg-red-600 text-white px-2 py-0.5 rounded text-[9px] uppercase font-bold tracking-widest shadow-[0_0_10px_red]">👑 Yönetici</span>' : (u.role === 'SubAdmin' ? '<span class="ml-2 bg-orange-800 text-orange-200 px-2 py-0.5 rounded text-[9px] uppercase font-bold tracking-widest">🛡️ Yrd. Admin</span>' : '');

            document.getElementById("op-avatar").src = u.avatar || `https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg`; 
            document.getElementById("op-avatar").className = `w-28 h-28 mx-auto rounded-full object-cover mt-6 bg-zinc-950 shadow-xl border-4 transition-all duration-300 ${borderCls}`;
            
            const badge = document.getElementById("op-premium-badge");
            if(premTier === 3) { 
                badge.classList.remove("hidden"); 
                badge.className = `mt-3 text-[10px] font-black uppercase tracking-widest text-yellow-500 drop-shadow-sm`; 
                badge.textContent = "👑 Ultra+"; 
            } else if (premTier === 2) { 
                badge.classList.remove("hidden"); 
                badge.className = `mt-3 text-[10px] font-bold uppercase tracking-widest text-purple-400 drop-shadow-sm`; 
                badge.textContent = "🌟 Deluxe"; 
            } else if (premTier === 1) { 
                badge.classList.remove("hidden"); 
                badge.className = `mt-3 text-[10px] font-bold uppercase tracking-widest drop-shadow-sm ${textCls}`; 
                badge.textContent = "⭐ Standart"; 
            } else { 
                badge.classList.add("hidden"); 
            }

            const opNameEl = document.getElementById("op-username");
            opNameEl.innerHTML = `${u.username} ${tick} ${adminTag}`; 
            opNameEl.className = `text-4xl font-bold break-all teko-font tracking-wide flex items-center justify-center drop-shadow-md transition-all ${textCls ? textCls : 'text-white'}`;
            opNameEl.setAttribute("style", inlineStyle);
            
            const tickBox = document.getElementById("op-verified-badge");
            if (premTier === 3) { 
                tickBox.innerHTML = verifiedTick; 
                tickBox.classList.remove("hidden"); 
            } else { 
                tickBox.classList.add("hidden"); 
            }
            
            document.getElementById("op-bio").textContent = u.bio || "Kullanıcı biyo girmemiş."; 
            document.getElementById("op-xp").textContent = u.xp;
            
            const title = getTitle(u.xp); 
            document.getElementById("op-title").textContent = title.name; 
            document.getElementById("op-title").className = `text-sm font-bold truncate uppercase mt-1 drop-shadow-sm ${title.color}`;
            
            const opOnlineEl = document.getElementById("op-online-status");
            if(opOnlineEl) {
                const s = getOnlineStatus(u);
                if(s.status === 'online') {
                    opOnlineEl.innerHTML = `<span class="online-dot-sm"></span><span class="online-label">${s.label}</span>`;
                    opOnlineEl.className = "flex items-center gap-2 justify-center mt-2";
                } else if(s.status === 'recent') {
                    opOnlineEl.innerHTML = `<span class="recent-dot"></span><span class="recent-label">${s.label}</span>`;
                    opOnlineEl.className = "flex items-center gap-2 justify-center mt-2";
                } else {
                    opOnlineEl.innerHTML = '';
                    opOnlineEl.className = "hidden";
                }
            }

            
            let badges = "";
            if(stats.markers >= 1){ badges += `<span class="bg-zinc-800 text-zinc-300 border border-zinc-700 px-3 py-1 rounded-lg text-[10px] font-bold shadow-sm">📍 Kâşif</span>`; }
            if(stats.events >= 1){ badges += `<span class="bg-zinc-800 text-zinc-300 border border-zinc-700 px-3 py-1 rounded-lg text-[10px] font-bold shadow-sm">📅 Organizatör</span>`; }
            if(stats.market >= 1){ badges += `<span class="bg-zinc-800 text-zinc-300 border border-zinc-700 px-3 py-1 rounded-lg text-[10px] font-bold shadow-sm">🤝 Esnaf</span>`; }
            if(u.xp > 1000){ badges += `<span class="bg-orange-900/50 text-orange-300 border border-orange-700 px-3 py-1 rounded-lg text-[10px] font-bold shadow-sm">🔥 Kıdemli</span>`; }
            
            if(badges === "") {
                badges = "<span class='text-zinc-500 text-xs italic font-medium'>Rozet yok.</span>";
            }
            document.getElementById("op-badges").innerHTML = badges;

            renderGarage(u.username, 'other');

            let actionsHtml = `<button onclick="startDm('${u.username}')" class="bg-white hover:bg-gray-200 transition text-black py-4 rounded-xl text-sm font-bold w-full shadow-[0_0_15px_rgba(255,255,255,0.3)] mb-3 btn-premium-hover">💬 ÖZEL MESAJ</button>`;
            
            // Engel durumunu kontrol et
            const myBlockedList = (currentUser.stats && currentUser.stats.blocked_users) ? currentUser.stats.blocked_users : [];
            const isBlocked = myBlockedList.includes(u.username);
            if(isBlocked) {
                actionsHtml += `<button onclick="unblockUser('${u.username}')" class="w-full bg-zinc-900 border border-zinc-700 hover:bg-zinc-800 transition text-zinc-400 py-3 rounded-xl font-bold text-xs uppercase tracking-widest mb-3 btn-premium-hover">✅ ENGELİ KALDIR</button>`;
            } else {
                actionsHtml += `<button onclick="blockUser('${u.username}')" class="w-full bg-black border border-sky-900/50 hover:bg-red-950/30 transition text-sky-400 py-3 rounded-xl font-bold text-xs uppercase tracking-widest mb-2 btn-premium-hover">🚫 ENGELLE</button>`;
            }
            actionsHtml += `<button onclick="openReportUserModal('${u.username}')" class="w-full bg-black border border-orange-900/50 hover:bg-orange-950/20 transition text-orange-400 py-3 rounded-xl font-bold text-xs uppercase tracking-widest mb-3 btn-premium-hover">🚨 ŞİKAYET ET</button>`;
            
            if(currentUser.role === 'Admin') {
                actionsHtml += `
                <div class="rounded-2xl p-4 border border-zinc-700/60 mb-3" style="background:rgba(0,0,0,0.5)">
                    <div class="text-[10px] text-zinc-400 uppercase font-bold tracking-widest mb-3">👑 Ana Admin — Yönetim</div>
                    <div class="flex gap-2 mb-3">
                        <select id="admin-tier-select" class="flex-1 bg-zinc-900 border border-zinc-600 rounded-lg px-3 py-2 text-white text-xs outline-none cursor-pointer font-bold">
                            <option value="0" ${stats.premium_tier == 0 ? 'selected' : ''}>Ücretsiz (İptal)</option>
                            <option value="1" ${stats.premium_tier == 1 ? 'selected' : ''}>⭐ Standart</option>
                            <option value="2" ${stats.premium_tier == 2 ? 'selected' : ''}>🌟 Deluxe</option>
                            <option value="3" ${stats.premium_tier == 3 ? 'selected' : ''}>👑 Ultra+</option>
                        </select>
                        <button onclick="adminSetPremium('${u.username}')" class="bg-gradient-to-r from-purple-700 to-pink-700 hover:opacity-90 text-white py-2 px-4 rounded-lg text-[10px] font-bold transition uppercase tracking-widest btn-premium-hover">KAYDET</button>
                    </div>
                    <div class="flex gap-2 mb-3">
                        <input id="admin-xp-amount" type="number" placeholder="XP miktarı" class="w-1/2 bg-black/60 text-white rounded-xl px-4 py-3 text-sm border border-zinc-700 outline-none focus:border-white transition font-bold">
                        <button onclick="giveXP('${u.username}')" class="w-1/2 bg-zinc-800 hover:bg-zinc-700 transition text-white py-3 rounded-xl text-xs font-bold uppercase tracking-widest btn-premium-hover">XP VER</button>
                    </div>
                    <div class="grid grid-cols-2 gap-2">
                        <button onclick="openUserActivity('${u.username}')" class="bg-blue-950/50 hover:bg-blue-900/60 transition text-blue-400 py-3 rounded-xl text-xs font-bold uppercase tracking-widest border border-blue-800/50 btn-premium-hover">🔍 Aktivite</button>
                        <button onclick="banUser('${u.username}')" class="bg-red-950/50 hover:bg-sky-900/80 transition text-sky-400 py-3 rounded-xl text-xs font-bold uppercase tracking-widest border border-sky-800/50 btn-premium-hover">🚨 Banla</button>
                    </div>
                </div>`;
            } else if(currentUser.role === 'SubAdmin') {
                actionsHtml += `
                <div class="rounded-2xl p-4 border border-orange-900/40 mb-3" style="background:rgba(120,53,15,0.12)">
                    <div class="text-[10px] text-orange-400 uppercase font-bold tracking-widest mb-3">🛡️ Yrd. Admin İşlemleri</div>
                    <div class="grid grid-cols-2 gap-2">
                        <button onclick="openUserActivity('${u.username}')" class="bg-blue-950/50 hover:bg-blue-900/60 transition text-blue-400 py-3 rounded-xl text-xs font-bold uppercase tracking-widest border border-blue-800/50 btn-premium-hover">🔍 Aktivite</button>
                        <button onclick="banUser('${u.username}')" class="bg-red-950/50 hover:bg-sky-900/80 transition text-sky-400 py-3 rounded-xl text-xs font-bold uppercase tracking-widest border border-sky-800/50 btn-premium-hover">🚨 Banla</button>
                    </div>
                </div>`;
            }
            
            document.getElementById("op-actions").innerHTML = actionsHtml;

            // ── Profil Reels Sekmesi ──
            // op-actions altına reels tab ekle (varsa önce temizle)
            const existingReelsTab = document.getElementById('op-reels-section');
            if(existingReelsTab) existingReelsTab.remove();
            const reelsSection = document.createElement('div');
            reelsSection.id = 'op-reels-section';
            reelsSection.className = 'mt-4';
            reelsSection.innerHTML = `
                <div class="flex items-center gap-2 mb-3">
                    <button id="op-reels-tab-btn" onclick="window.loadOtherProfileReels('${escapeHtml(u.username)}')"
                        class="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-pink-900/60 to-sky-900/40 border border-pink-700/40 text-white text-xs font-black uppercase tracking-widest hover:opacity-90 transition btn-premium-hover">
                        🎬 Reels'leri Gör
                    </button>
                </div>
                <div id="op-reels-grid" class="hidden grid grid-cols-3 gap-1 rounded-xl overflow-hidden"></div>
                <div id="op-reels-loading" class="hidden flex items-center justify-center py-6">
                    <div class="w-6 h-6 rounded-full border-2 border-pink-500 border-t-transparent animate-spin"></div>
                </div>
                <div id="op-reels-empty" class="hidden text-center text-zinc-500 text-xs py-4">Bu kullanıcının henüz Reels paylaşımı yok.</div>
            `;
            const opActionsEl = document.getElementById('op-actions');
            if(opActionsEl && opActionsEl.parentNode) {
                opActionsEl.parentNode.insertBefore(reelsSection, opActionsEl.nextSibling);
            }

            document.getElementById("other-profile-modal").classList.remove("hidden");
        }

        // ── Diğer Kullanıcının Reels'lerini Yükle ──
        window.loadOtherProfileReels = async function(profileUsername) {
            const grid    = document.getElementById('op-reels-grid');
            const loading = document.getElementById('op-reels-loading');
            const empty   = document.getElementById('op-reels-empty');
            const tabBtn  = document.getElementById('op-reels-tab-btn');
            if(!grid) return;

            // Butonu gizle, loading göster
            if(tabBtn) tabBtn.style.display = 'none';
            if(loading) { loading.classList.remove('hidden'); loading.style.display = 'flex'; }
            if(empty) empty.classList.add('hidden');
            grid.classList.add('hidden');
            grid.innerHTML = '';

            try {
                // Supabase'den doğrudan sorgula
                const { data, error } = await supaClient
                    .from('reels')
                    .select('id, media_url, media_type, caption, likes, created_at')
                    .eq('user', profileUsername)
                    .order('created_at', { ascending: false })
                    .limit(12);

                if(loading) { loading.classList.add('hidden'); loading.style.display = 'none'; }

                const reels = data || [];
                if(reels.length === 0) {
                    if(empty) empty.classList.remove('hidden');
                    return;
                }

                reels.forEach((r, idx) => {
                    const item = document.createElement('div');
                    item.className = 'relative aspect-square bg-zinc-900 overflow-hidden cursor-pointer';
                    item.style.cssText = 'border-radius:4px;';

                    if(r.media_type === 'video') {
                        item.innerHTML = `
                            <video src="${escapeHtml(r.media_url)}" class="w-full h-full object-cover" muted playsinline preload="metadata" style="pointer-events:none;"></video>
                            <div style="position:absolute;top:4px;right:4px;background:rgba(0,0,0,0.6);border-radius:6px;padding:2px 5px;">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="12" height="12" fill="white"><path d="M3 2l10 6-10 6V2z"/></svg>
                            </div>
                            <div style="position:absolute;bottom:4px;left:4px;font-size:10px;color:rgba(255,255,255,0.8);font-weight:bold;">❤ ${(r.likes||[]).length}</div>`;
                    } else {
                        item.innerHTML = `
                            <img src="${escapeHtml(r.media_url)}" class="w-full h-full object-cover" loading="lazy" onerror="this.parentElement.innerHTML='<div style=\\'width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:24px;color:#555\\'>📸</div>'">
                            <div style="position:absolute;bottom:4px;left:4px;font-size:10px;color:rgba(255,255,255,0.8);font-weight:bold;">❤ ${(r.likes||[]).length}</div>`;
                    }

                    // Tıklayınca Reels sayfasına ışın — direkt o videodan başlat
                    item.addEventListener('click', () => {
                        document.getElementById('other-profile-modal').classList.add('hidden');
                        window.openReels(r.id);
                    });

                    grid.appendChild(item);
                });

                grid.classList.remove('hidden');
                grid.style.display = 'grid';
            } catch(err) {
                if(loading) { loading.classList.add('hidden'); loading.style.display = 'none'; }
                if(empty) empty.classList.remove('hidden');
                console.error('Profil reels yükleme hatası:', err);
            }
        };

        async function adminSetPremium(target) {
            const tier = document.getElementById("admin-tier-select").value;
            await sendAction('admin_toggle_premium', { username: target, tier: tier });
            alert("Abonelik başarıyla güncellendi!");
            document.getElementById("other-profile-modal").classList.add("hidden");
        }

        async function giveXP(u) { 
            const a = document.getElementById("admin-xp-amount").value; 
            if(!a) return; 
            
            await sendAction('give_xp', { username: u, amount: a }); 
            alert("XP Başarıyla Eklendi!"); 
            document.getElementById("other-profile-modal").classList.add("hidden"); 
        }
        
        async function banUser(u) { 
            if(confirm("Bu kullanıcıyı kalıcı olarak banlamak istediğinize emin misiniz?")) { 
                await sendAction('add_ban', { username: u });
                db.banned.push(u);
            } 
        }

        async function blockUser(target) {
            if(!confirm(`${target} adlı kullanıcıyı engellemek istediğine emin misin? Engellenince seni göremez ve sana mesaj gönderemez.`)) return;
            const res = await sendAction('block_user', { target });
            if(res && res.status === 'ok') {
                if(!currentUser.stats) currentUser.stats = {};
                if(!currentUser.stats.blocked_users) currentUser.stats.blocked_users = [];
                if(!currentUser.stats.blocked_users.includes(target)) currentUser.stats.blocked_users.push(target);
                document.getElementById('other-profile-modal').classList.add('hidden');
                showToast(`🚫 ${target} engellendi.`);
            } else {
                alert(res?.message || 'Bir hata oluştu.');
            }
        }

        async function unblockUser(target) {
            const res = await sendAction('unblock_user', { target });
            if(res && res.status === 'ok') {
                if(currentUser.stats && currentUser.stats.blocked_users) {
                    currentUser.stats.blocked_users = currentUser.stats.blocked_users.filter(u => u !== target);
                }
                document.getElementById('other-profile-modal').classList.add('hidden');
                showToast(`✅ ${target} engeli kaldırıldı.`);
            } else {
                alert(res?.message || 'Bir hata oluştu.');
            }
        }

        function openDeleteAccountModal() {
            document.getElementById('settings-modal').classList.add('hidden');
            document.getElementById('delete-account-password').value = '';
            document.getElementById('delete-account-modal').classList.remove('hidden');
        }

        async function confirmDeleteAccount() {
            const pw = document.getElementById('delete-account-password').value.trim();
            if(!pw) { alert('Lütfen şifreni gir.'); return; }
            if(!confirm('Son onay: Hesabın ve TÜM verilerin kalıcı olarak silinecek. Devam etmek istiyor musun?')) return;
            const res = await sendAction('delete_account', { password: pw });
            if(res && res.status === 'ok') {
                alert('Hesabın başarıyla silindi. Görüşmek üzere! 🏔️');
                window.location.reload();
            } else {
                alert(res?.message || 'Bir hata oluştu.');
            }
        }

        // ---- KULLANICI RAPORLAMA ----
        let _reportUserTarget = '';
        let _reportUserReason = '';
        let _reportMsgId = '';
        let _reportMsgUser = '';
        let _reportMsgText = '';
        let _reportMsgReason = '';

        function openReportUserModal(username) {
            _reportUserTarget = username;
            _reportUserReason = '';
            document.getElementById('report-user-target-label').textContent = username;
            document.getElementById('report-user-detail').value = '';
            document.getElementById('other-profile-modal').classList.add('hidden');
            document.getElementById('report-user-modal').classList.remove('hidden');
        }

        function setReportReason(reason) {
            _reportUserReason = reason;
            document.querySelectorAll('#report-user-modal .grid button').forEach(b => {
                b.classList.toggle('border-orange-500', b.textContent.trim().includes(reason.split('/')[0].trim()));
            });
        }

        async function submitReportUser() {
            const detail = document.getElementById('report-user-detail').value.trim();
            const reason = _reportUserReason ? _reportUserReason + (detail ? ': ' + detail : '') : detail;
            if(!reason) { alert('Lütfen bir şikayet sebebi seçin.'); return; }
            const res = await sendAction('report_user', { target: _reportUserTarget, reason });
            document.getElementById('report-user-modal').classList.add('hidden');
            if(res && res.status === 'ok') {
                showToast('Şikayetiniz admin ekibine iletildi. Teşekkürler!');
            } else {
                alert(res?.message || 'Bir hata oluştu.');
            }
        }

        function openReportMsgModal(msgId, msgUser, msgText) {
            _reportMsgId = msgId;
            _reportMsgUser = msgUser;
            _reportMsgText = msgText;
            _reportMsgReason = '';
            document.getElementById('report-msg-preview').textContent = msgText || '(Mesaj içeriği)';
            document.getElementById('report-msg-modal').classList.remove('hidden');
        }

        function setMsgReportReason(reason) {
            _reportMsgReason = reason;
            document.querySelectorAll('#report-msg-modal .grid button').forEach(b => {
                b.classList.toggle('border-orange-500', b.textContent.trim().includes(reason.split('/')[0].trim()));
            });
        }

        async function submitReportMsg() {
            if(!_reportMsgReason) { alert('Lütfen bir şikayet sebebi seçin.'); return; }
            const res = await sendAction('report_message', {
                msg_id: _reportMsgId,
                msg_user: _reportMsgUser,
                msg_text: _reportMsgText,
                reason: _reportMsgReason
            });
            document.getElementById('report-msg-modal').classList.add('hidden');
            if(res && res.status === 'ok') {
                showToast('Mesaj şikayetiniz admin ekibine iletildi. Teşekkürler!');
            } else {
                alert(res?.message || 'Bir hata oluştu.');
            }
        }

        function toggleAddMarkerMode() { 
            if(isAddingEventMode) toggleAddEventMode(); 
            isAddingMarkerMode = !isAddingMarkerMode; 
            
            const btn = document.getElementById("btn-add-marker-mode"); 
            const mapContainer = document.getElementById("map"); 
            
            if(isAddingMarkerMode) { 
                btn.className = "bg-green-600 px-3 py-2 rounded-xl shadow-xl font-bold text-white animate-pulse text-[10px] uppercase tracking-widest pointer-events-auto shadow-[0_0_15px_rgba(34,197,94,0.6)]"; 
                btn.innerHTML = "❌ Haritadan Seç"; 
                mapContainer.classList.add("map-add-mode"); 
            } else { 
                btn.className = "bg-sky-600/90 backdrop-blur hover:bg-red-500 btn-premium-hover transition px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(14,165,233,0.4)] font-bold text-white text-[10px] uppercase tracking-widest border border-red-400/50 pointer-events-auto"; 
                btn.innerHTML = "📍 RAMPA EKLE"; 
                mapContainer.classList.remove("map-add-mode"); 
            } 
        }
        
        function toggleAddEventMode() { 
            if(isAddingMarkerMode) toggleAddMarkerMode();
            isAddingEventMode = !isAddingEventMode; 
            
            const btn = document.getElementById("btn-add-event-mode"); 
            const mapContainer = document.getElementById("map"); 
            
            if(isAddingEventMode) { 
                btn.className = "bg-green-600 px-3 py-2 rounded-xl shadow-xl font-bold text-white animate-pulse text-[10px] uppercase tracking-widest pointer-events-auto shadow-[0_0_15px_rgba(34,197,94,0.6)]"; 
                btn.innerHTML = "❌ Haritadan Seç"; 
                mapContainer.classList.add("map-add-mode"); 
            } else { 
                btn.className = "bg-blue-600/90 backdrop-blur hover:bg-blue-500 btn-premium-hover transition px-3 py-2 rounded-xl shadow-[0_0_15px_rgba(59,130,246,0.4)] flex items-center justify-center text-[10px] uppercase tracking-widest font-bold text-white border border-blue-400/50 pointer-events-auto"; 
                btn.innerHTML = "📅 BULUŞMA EKLE"; 
                mapContainer.classList.remove("map-add-mode"); 
            } 
        }

        function useCurrentLocationForMarker() {
            if(!userLat || !userLng) {
                return alert("Konumunuz bulunamadı! Lütfen haritadaki GPS (🎯) butonuna tıklayıp konum izni verin.");
            }
            tempLat = userLat;
            tempLng = userLng;
            editingMarkerId = null;
            document.getElementById("modal-marker-title").textContent = "📍 RAMPA EKLE (Şu Anki Konum)";
            alert("Şu anki konumunuz başarıyla alındı! Rampa detaylarını girip kaydedebilirsiniz.");
        }

        function quickAddMarkerCurrentLocation() {
            if(!userLat || !userLng) {
                return alert("Konumunuz bulunamadı! Lütfen haritadaki GPS (🎯) butonuna tıklayıp konum izni verin.");
            }
            tempLat = userLat;
            tempLng = userLng;
            editingMarkerId = null;
            document.getElementById("modal-marker-title").textContent = "📍 RAMPA EKLE (Şu Anki Konum)";
            document.getElementById("new-marker-name").value = "";
            document.getElementById("new-marker-desc").value = "";
            document.getElementById("add-marker-modal").classList.remove("hidden");
        }
        
        function openAddMarkerModal() { 
            if(!tempLat && !editingMarkerId) { 
                if(userLat && userLng) {
                    if(confirm("Haritadan bir yer seçmediniz. Şu anki bulunduğunuz konum rampa olarak eklensin mi?")) {
                        tempLat = userLat;
                        tempLng = userLng;
                        document.getElementById("modal-marker-title").textContent = "📍 RAMPA EKLE (Şu Anki Konum)";
                    } else {
                        toggleAddMarkerMode();
                        return;
                    }
                } else {
                    alert("Lütfen önce harita üzerinden bir noktaya dokunarak yer seçin veya GPS izni verin!"); 
                    toggleAddMarkerMode(); 
                    return; 
                }
            } 
            
            if (!editingMarkerId && (!userLat || tempLat !== userLat)) {
                document.getElementById("modal-marker-title").textContent = "📍 RAMPA EKLE";
                document.getElementById("new-marker-name").value = "";
                document.getElementById("new-marker-desc").value = "";
                document.getElementById("new-marker-difficulty").value = "Orta";
                document.getElementById("new-marker-photo").value = "";
            }
            
            if(getUserPremiumTier(currentUser.username) >= 2 || currentUser.role === 'Admin') { 
                document.getElementById("new-marker-icon").classList.remove("hidden"); 
                document.getElementById("new-marker-icon").classList.add("block"); 
            } else { 
                document.getElementById("new-marker-icon").classList.add("hidden"); 
            }
            
            document.getElementById("add-marker-modal").classList.remove("hidden"); 
        }

        function editMarker(id) {
            const m = db.markers.find(x => x.id === id);
            if(!m) return;
            
            editingMarkerId = m.id;
            editingMarkerLat = m.lat;
            editingMarkerLng = m.lng;
            
            document.getElementById("modal-marker-title").textContent = "✏️ RAMPA DÜZENLE";
            document.getElementById("new-marker-name").value = m.name || "";
            document.getElementById("new-marker-desc").value = m.desc || "";
            document.getElementById("new-marker-difficulty").value = m.difficulty || "Orta";
            document.getElementById("new-marker-photo").value = ""; 
            
            if(getUserPremiumTier(currentUser.username) >= 2 || currentUser.role === 'Admin') {
                document.getElementById("new-marker-icon").classList.remove("hidden");
                document.getElementById("new-marker-icon").value = m.icon_type || "🚴";
            }
            
            closeMarkerSheet();
            document.getElementById("add-marker-modal").classList.remove("hidden");
        }
        
        async function deleteMarker(id) {
            if(confirm("Bu noktayı haritadan kalıcı olarak silmek istediğine emin misin?")) {
                closeMarkerSheet();
                await sendAction('delete_marker', {id: id});
                db.markers = db.markers.filter(m => m.id !== id);
                if(map) syncMap();
            }
        }

        function showMarkerSheet(m, updateOnly = false) {
            currentMarkerId = m.id;
            const sheet = document.getElementById("marker-sheet");
            
            if(!updateOnly) sheet.classList.remove("hidden");
            
            document.getElementById("ms-title").textContent = m.name;
            document.getElementById("ms-difficulty").textContent = m.difficulty;
            document.getElementById("ms-desc").textContent = m.desc || "Açıklama yok.";
            
            const imgContainer = document.getElementById("ms-image-container");
            if(m.image) {
                imgContainer.innerHTML = `<img src="${m.image}" onclick="openFullscreen(['${m.image}'],0)" class="w-full h-48 object-cover rounded-xl border border-zinc-800 shadow-md cursor-pointer hover:opacity-90 transition-opacity">`;
            } else {
                imgContainer.innerHTML = "";
            }
            
            let likesCount = m.likes ? m.likes.length : 0; 
            let dislikesCount = m.dislikes ? m.dislikes.length : 0;
            let isLiked = m.likes && m.likes.includes(currentUser.username);
            let isDisliked = m.dislikes && m.dislikes.includes(currentUser.username);
            
            document.getElementById("ms-likes-count").textContent = likesCount;
            document.getElementById("ms-dislikes-count").textContent = dislikesCount;
            
            const likeBtn = document.getElementById("ms-btn-like");
            const dislikeBtn = document.getElementById("ms-btn-dislike");
            
            if(isLiked) likeBtn.classList.add("bg-red-950/40", "border-sky-900/50"); else likeBtn.classList.remove("bg-red-950/40", "border-sky-900/50");
            if(isDisliked) dislikeBtn.classList.add("bg-zinc-800"); else dislikeBtn.classList.remove("bg-zinc-800");

            document.getElementById("ms-btn-directions").href = `https://maps.google.com/?q=${m.lat},${m.lng}`;
            updateMarkerRating(m);
            const dangerBanner = document.getElementById('ms-danger-banner');
            if(dangerBanner) {
                const dr = m.danger_reports || [];
                if(m.is_dangerous && dr.length > 0) { dangerBanner.classList.remove('hidden'); dangerBanner.innerHTML = '⚠️ ' + dr[dr.length-1].reason; }
                else { dangerBanner.classList.add('hidden'); }
            }

            const adminControls = document.getElementById("ms-admin-controls");
            if (currentUser && (currentUser.role === 'Admin' || currentUser.role === 'SubAdmin' || m.addedBy === currentUser.username)) {
                adminControls.classList.remove("hidden");
                document.getElementById("ms-btn-edit").onclick = () => editMarker(m.id);
                document.getElementById("ms-btn-delete").onclick = () => deleteMarker(m.id);
            } else {
                adminControls.classList.add("hidden");
            }
        }
        
        function closeMarkerSheet() {
            document.getElementById("marker-sheet").classList.add("hidden");
            currentMarkerId = null;
        }

        async function toggleMarkerInteraction(type) {
            if(!currentMarkerId) return;
            const m = db.markers.find(x => x.id === currentMarkerId);
            if(m) {
                if(!m.likes) m.likes = [];
                if(!m.dislikes) m.dislikes = [];
                
                if(type === 'like') {
                    if(m.likes.includes(currentUser.username)) m.likes = m.likes.filter(u => u !== currentUser.username);
                    else { m.likes.push(currentUser.username); m.dislikes = m.dislikes.filter(u => u !== currentUser.username); }
                } else {
                    if(m.dislikes.includes(currentUser.username)) m.dislikes = m.dislikes.filter(u => u !== currentUser.username);
                    else { m.dislikes.push(currentUser.username); m.likes = m.likes.filter(u => u !== currentUser.username); }
                }
                showMarkerSheet(m, true);
            }
            
            if(type === 'like') await sendAction('like_marker', {id: currentMarkerId});
            else await sendAction('dislike_marker', {id: currentMarkerId});
        }

        function openAddEventModal() { 
            if(!tempLat) { 
                alert("Lütfen önce harita üzerinden bir noktaya dokunarak yer seçin!"); 
                toggleAddEventMode(); 
                return; 
            } 
            document.getElementById("add-event-modal").classList.remove("hidden"); 
        }

        function syncMap() {
            markerLayers.forEach(l => map.removeLayer(l)); 
            markerLayers = [];
            
            db.markers.forEach(m => {
                const mapIcon = m.icon_type || '🚴';
                const iconHtml = `
                    <div class="relative flex items-center justify-center w-10 h-10 cursor-pointer transition hover:scale-110">
                        <div class="absolute w-full h-full bg-red-600 rounded-full animate-ping opacity-50"></div>
                        <div class="relative bg-gradient-to-b from-red-500 to-red-800 border-2 border-white text-white w-8 h-8 rounded-full flex items-center justify-center shadow-[0_0_15px_rgba(14,165,233,0.8)] text-lg">${mapIcon}</div>
                    </div>`;
                
                const icon = L.divIcon({ html: iconHtml, className: '', iconSize: [40,40], iconAnchor: [20,20] });
                const mk = L.marker([m.lat, m.lng], {icon: icon}).addTo(map);
                
                mk.on('click', () => { showMarkerSheet(m); });
                markerLayers.push(mk);
            });
            
            db.events.forEach(e => {
                const icon = L.divIcon({ 
                    html: `<div class="bg-gradient-to-b from-blue-500 to-blue-700 text-white w-10 h-10 rounded-full flex items-center justify-center border-2 border-white shadow-[0_0_15px_rgba(59,130,246,0.6)] font-bold text-lg cursor-pointer transition hover:scale-110">📅</div>`, 
                    className: '', 
                    iconSize: [40,40],
                    iconAnchor: [20,20]
                });
                const mk = L.marker([e.lat, e.lng], {icon: icon}).addTo(map); 
                mk.on('click', () => showEventSheet(e)); 
                markerLayers.push(mk);
            });
            
            const now = Date.now();
            db.users.forEach(u => {
                if(u.stats && u.stats.riding_until > now && u.stats.riding_lat && u.stats.riding_lng) {
                    const isMe = u.username === currentUser.username;
                    const avatar = u.avatar || `https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg`;
                    const premTier = getUserPremiumTier(u.username);
                    
                    let ringColor = 'bg-green-500'; 
                    let borderColor = isMe ? 'border-green-400' : 'border-zinc-300'; 
                    let shadowColor = 'rgba(34,197,94,0.8)'; 
                    let crownHtml = '';
                    
                    if(premTier === 3) { 
                        ringColor = 'bg-yellow-500'; 
                        borderColor = 'border-yellow-400'; 
                        shadowColor = 'rgba(234,179,8,0.8)'; 
                        crownHtml = `<div class="absolute -top-3 text-sm drop-shadow-[0_0_10px_rgba(234,179,8,0.8)] z-20 animate-bounce">👑</div>`; 
                    }
                    
                    const iconHtml = `
                        <div class="relative flex items-center justify-center w-12 h-12 flex-col cursor-pointer transition hover:scale-110">
                            ${crownHtml}
                            <div class="absolute w-full h-full ${ringColor} rounded-full animate-ping opacity-70 mt-1"></div>
                            <img src="${avatar}" class="relative w-10 h-10 rounded-full border-2 ${borderColor} object-cover shadow-[0_0_15px_${shadowColor}] mt-1">
                        </div>
                    `;
                    
                    const icon = L.divIcon({ html: iconHtml, className: '', iconSize: [48,48], iconAnchor: [24,24] });
                    const mk = L.marker([u.stats.riding_lat, u.stats.riding_lng], {icon: icon}).addTo(map);
                    mk.on('click', () => showOtherProfile(u.username));
                    markerLayers.push(mk);
                }
            });
        }
        
        function autoZoomToUserLocation() { 
            if(navigator.geolocation) { 
                navigator.geolocation.getCurrentPosition(pos => { 
                    userLat = pos.coords.latitude; 
                    userLng = pos.coords.longitude; 
                    if(map) map.setView([userLat, userLng], 14); 
                }); 
            } 
        }
        
        function showNearbyRoutes() { 
            if(!userLat || !userLng) return alert("Mevcut konumunuz henüz bulunamadı! Lütfen haritadaki GPS (🎯) butonuna tıklayıp konum izni verin.");
            
            const c = document.getElementById("nr-list");
            c.innerHTML = "";
            
            let withDist = db.markers.map(m => {
                let dLat = m.lat - userLat;
                let dLng = m.lng - userLng;
                let dist = Math.sqrt(dLat*dLat + dLng*dLng) * 111;
                return {...m, distance: dist};
            }).sort((a,b) => a.distance - b.distance);
            
            if(withDist.length === 0) {
                c.innerHTML = "<p class='text-zinc-500 text-xs italic text-center mt-5 font-medium'>Çevrenizde kayıtlı rampa veya rota bulunamadı.</p>";
            } else {
                withDist.slice(0, 10).forEach(m => {
                    let img = m.image ? `<img src="${m.image}" class="w-16 h-16 rounded-xl object-cover shrink-0 border border-zinc-700 shadow-sm">` : `<div class="w-16 h-16 rounded-xl bg-black/60 border border-zinc-700 shadow-inner flex items-center justify-center text-2xl shrink-0">${m.icon_type || '🚴'}</div>`;
                    c.innerHTML += `
                    <div class="bg-black/50 p-3 rounded-2xl border border-zinc-800 flex items-center gap-3 mb-3 cursor-pointer hover:bg-zinc-800 hover:border-zinc-600 transition-colors shadow-md group" onclick="map.setView([${m.lat}, ${m.lng}], 16); document.getElementById('nearby-routes-modal').classList.add('hidden');">
                        ${img}
                        <div class="overflow-hidden flex-1">
                            <div class="text-white font-bold text-sm tracking-wide truncate group-hover:text-blue-300 transition-colors">${m.name}</div>
                            <div class="text-sky-400 text-[10px] font-black uppercase tracking-widest mt-1">${m.distance.toFixed(1)} KM UZAKLIKTA</div>
                            <div class="text-zinc-500 text-[10px] font-bold uppercase tracking-widest mt-0.5">Seviye: ${m.difficulty}</div>
                        </div>
                        <div class="text-zinc-400 bg-zinc-900 border border-zinc-700 w-8 h-8 rounded-full flex items-center justify-center shrink-0 group-hover:bg-zinc-700 group-hover:text-white transition-colors">➜</div>
                    </div>`;
                });
            }
            
            document.getElementById("nearby-routes-modal").classList.remove("hidden"); 
        }
        
        async function saveNewMarker() { 
            const n = document.getElementById("new-marker-name").value;
            const d = document.getElementById("new-marker-desc").value; 
            const photoFile = document.getElementById("new-marker-photo").files[0]; 
            const iconType = document.getElementById("new-marker-icon").value;
            
            if(!n) return alert("Rampa adı zorunludur!"); 
            
            document.getElementById("add-marker-modal").classList.add("hidden"); 
            
            let base64Photo = null; 
            if(photoFile) {
                base64Photo = await resizeImage(photoFile, 500); 
            }
            
            let targetId = editingMarkerId ? editingMarkerId : Date.now().toString();
            let targetLat = editingMarkerId ? editingMarkerLat : tempLat;
            let targetLng = editingMarkerId ? editingMarkerLng : tempLng;
            
            let finalImage = base64Photo;
            if(editingMarkerId && !base64Photo) {
                const existingMarker = db.markers.find(m => m.id === editingMarkerId);
                if(existingMarker) finalImage = existingMarker.image;
            }
            
            try { 
                await sendAction('add_marker', { 
                    id: targetId, 
                    lat: targetLat, 
                    lng: targetLng, 
                    name: n, 
                    difficulty: document.getElementById("new-marker-difficulty").value, 
                    desc: d, 
                    image: finalImage, 
                    icon_type: (getUserPremiumTier(currentUser.username) >= 2 || currentUser.role === 'Admin') ? iconType : '🚴' 
                }); 
                
                editingMarkerId = null;
                document.getElementById("add-marker-modal").classList.add("hidden");
            } catch(e) { }
        }
        
        async function saveEvent() { 
            const t = document.getElementById("ev-title").value; 
            const d = document.getElementById("ev-date").value; 
            const tm = document.getElementById("ev-time").value; 
            
            if(!t || !d || !tm) return alert("Tüm alanları doldurunuz!");
            
            await sendAction('add_event', { 
                id: Date.now(), 
                lat: tempLat, 
                lng: tempLng, 
                title: t, 
                datetime: `${d} ${tm}`, 
                max: document.getElementById("ev-max").value, 
                desc: document.getElementById("ev-desc").value 
            }); 
            
            document.getElementById("add-event-modal").classList.add("hidden");
        }
        
        function showEventSheet(e) { 
            currentEventId = e.id; 
            document.getElementById("event-sheet").classList.remove("hidden"); 
            document.getElementById("es-title").textContent = e.title; 
            document.getElementById("es-time").textContent = e.datetime; 
            document.getElementById("es-desc").textContent = e.desc || "Açıklama yok."; 
            
            const att = e.attendees || []; 
            
            const attContainer = document.getElementById("es-attendees");
            attContainer.innerHTML = "";
            if (att.length === 0) {
                attContainer.innerHTML = "<span class='text-zinc-500 text-xs italic font-medium'>Henüz katılan yok. İlk sen ol!</span>";
            } else {
                att.forEach(u => {
                    let isMe = u === currentUser.username;
                    attContainer.innerHTML += `<span class="bg-black/60 text-[10px] px-3 py-1.5 rounded-xl border ${isMe ? 'border-green-500 text-green-400 font-bold shadow-[0_0_10px_rgba(34,197,94,0.3)]' : 'border-zinc-700 text-zinc-300'} shadow-inner tracking-widest uppercase">${u}</span>`;
                });
            }

            const btn = document.getElementById("btn-join"); 
            btn.disabled = false;
            
            let maxCapacity = e.max ? parseInt(e.max) : 0;

            if(att.includes(currentUser.username)) {
                btn.textContent = "AYRIL"; 
                btn.className = "w-full bg-red-950/80 hover:bg-sky-900/80 btn-premium-hover transition text-sky-400 border border-sky-900/50 py-4 rounded-xl font-bold text-sm shadow-md mb-2";
            } else {
                if (maxCapacity > 0 && att.length >= maxCapacity) {
                    btn.textContent = `KAPASİTE DOLU (${att.length}/${maxCapacity})`;
                    btn.className = "w-full bg-black/50 text-zinc-500 py-4 rounded-xl font-bold text-sm cursor-not-allowed mb-2 border border-zinc-700 shadow-inner";
                    btn.disabled = true;
                } else {
                    let limitText = maxCapacity > 0 ? `KATIL (${att.length}/${maxCapacity} Kişi)` : `KATIL (${att.length} Kişi)`;
                    btn.textContent = limitText;
                    btn.className = "w-full bg-green-700 hover:bg-green-600 transition text-white py-4 rounded-xl font-bold text-sm shadow-[0_0_15px_rgba(34,197,94,0.5)] mb-2 btn-premium-hover";
                }
            }
            
            document.getElementById("btn-directions").href = `https://maps.google.com/?q=${e.lat},${e.lng}`;

            if(e.creator === currentUser.username || currentUser.role === 'Admin') {
                document.getElementById("btn-del-event").classList.remove("hidden");
            } else {
                document.getElementById("btn-del-event").classList.add("hidden");
            }
        }
        
        async function toggleJoinEvent() { 
            const ev = db.events.find(x => x.id == currentEventId); 
            if(!ev) return; 
            
            const att = ev.attendees || []; 
            document.getElementById("btn-join").disabled = true;

            if(att.includes(currentUser.username)) {
                await sendAction('leave_event', {id: ev.id}); 
            } else {
                let maxCapacity = ev.max ? parseInt(ev.max) : 0;
                if (maxCapacity > 0 && att.length >= maxCapacity) {
                    alert("Bu etkinliğin kapasitesi maalesef dolmuş!");
                    document.getElementById("btn-join").disabled = false;
                    return;
                }
                
                try {
                    await sendAction('join_event', {id: ev.id}); 
                } catch(e) {}
            }
            
            document.getElementById("event-sheet").classList.add("hidden");
        }

        async function deleteEvent() {
            if(confirm("Bu etkinliği silmek istediğinize emin misiniz?")) {
                await sendAction('delete_event', {id: currentEventId});
                db.events = db.events.filter(e => e.id !== currentEventId);
                document.getElementById("event-sheet").classList.add("hidden");
            }
        }

        // Bildirim badge fonksiyonları
        let chatBadgeCount = 0;
        function showChatBadge() {
            chatBadgeCount++;
            // Sidebar tab butonu
            const btn = document.getElementById('tab-btn-1');
            if(btn) {
                let badge = btn.querySelector('.notif-badge');
                if(!badge) {
                    badge = document.createElement('span');
                    badge.className = 'notif-badge absolute -top-1 -right-1 bg-red-600 text-white text-[9px] font-black rounded-full w-5 h-5 flex items-center justify-center shadow-[0_0_10px_rgba(14,165,233,0.8)] border border-sky-400';
                    btn.style.position = 'relative';
                    btn.appendChild(badge);
                }
                badge.textContent = chatBadgeCount > 9 ? '9+' : chatBadgeCount;
                badge.style.animation = 'none';
                badge.offsetHeight;
                badge.style.animation = 'notifBounce 0.4s ease';
            }
            // Alt nav chat butonu
            const bnavBtn = document.getElementById('bnav-1');
            if(bnavBtn) {
                let badge2 = bnavBtn.querySelector('.notif-badge');
                if(!badge2) {
                    badge2 = document.createElement('span');
                    badge2.className = 'notif-badge absolute -top-0.5 -right-0.5 bg-red-600 text-white text-[9px] font-black rounded-full w-4 h-4 flex items-center justify-center shadow-[0_0_8px_rgba(14,165,233,0.8)] border border-sky-400';
                    bnavBtn.style.position = 'relative';
                    bnavBtn.appendChild(badge2);
                }
                badge2.textContent = chatBadgeCount > 9 ? '9+' : chatBadgeCount;
                badge2.style.animation = 'none';
                badge2.offsetHeight;
                badge2.style.animation = 'notifBounce 0.4s ease';
            }
        }
        function clearChatBadge() {
            chatBadgeCount = 0;
            ['tab-btn-1', 'bnav-1'].forEach(id => {
                const btn = document.getElementById(id);
                if(!btn) return;
                const badge = btn.querySelector('.notif-badge');
                if(badge) badge.remove();
            });
        }

        function switchChatTab(type) {
            if(type === 'group') { 
                document.getElementById("chat-group-area").classList.remove("hidden"); 
                document.getElementById("chat-dm-list-area").classList.add("hidden"); 
                document.getElementById("chat-dm-thread-area").classList.add("hidden"); 
                
                document.getElementById("chat-tab-group").className = "flex-1 py-2 bg-zinc-800 text-white rounded font-bold text-xs transition shadow-sm"; 
                document.getElementById("chat-tab-dm").className = "flex-1 py-2 bg-transparent text-zinc-500 hover:text-white rounded font-bold text-xs transition"; 
                
                renderChat(true); 
            } else { 
                document.getElementById("chat-group-area").classList.add("hidden"); 
                document.getElementById("chat-dm-list-area").classList.remove("hidden"); 
                document.getElementById("chat-dm-thread-area").classList.add("hidden"); 
                
                document.getElementById("chat-tab-dm").className = "flex-1 py-2 bg-zinc-800 text-white rounded font-bold text-xs transition shadow-sm"; 
                document.getElementById("chat-tab-group").className = "flex-1 py-2 bg-transparent text-zinc-500 hover:text-white rounded font-bold text-xs transition"; 
                
                renderDmList(); 
            }
        }

        let _renderedMsgIds = new Set();

        function buildMsgHTML(msg) {

                const isMe = msg.user === currentUser.username; 
                const isAI = msg.user === 'Freerider AI';
                
                const premColor = getUserPremiumColor(msg.user); 
                const premTier = getUserPremiumTier(msg.user); 
                
                const textCls = (premTier > 0) ? getPremiumTextClass(premColor) : '';
                const inlineStyle = (premTier > 0) ? getPremiumInlineStyle(premColor) : '';
                const borderCls = (premTier > 0 && !isAI) ? getPremiumBorderClass(msg.user) : 'border-zinc-700';
                
                const isAdmin = msg.user === 'Admin' || (db.users.find(u => u.username === msg.user) && db.users.find(u => u.username === msg.user).role === 'Admin');
                const adminDel = (currentUser.role === 'Admin' || currentUser.role === 'SubAdmin' || isMe) ? `<button onclick="delMsg('${msg.id}')" class="text-[10px] bg-red-950/80 text-sky-300 px-2 py-1 rounded-lg ml-2 hover:bg-red-900 transition border border-sky-900/50 uppercase font-bold tracking-widest relative z-50 pointer-events-auto">SİL</button>` : '';
                const reportBtn = (!isMe && !isAI) ? '<button onclick="openReportMsgModal(' + JSON.stringify(msg.id) + ',' + JSON.stringify(msg.user) + ',' + JSON.stringify((msg.text||'').substring(0,80)) + ')" class="text-[10px] bg-orange-950/60 text-orange-400 px-2 py-1 rounded-lg ml-1 hover:bg-orange-900/60 transition border border-orange-900/50 uppercase font-bold tracking-widest relative z-50 pointer-events-auto">🚨</button>' : '';
                
                const pinBtn = (isMe && getUserPremiumTier(currentUser.username) === 3 && msg.type === "text") ? `<button onclick="pinMsg('${msg.id}')" class="text-[10px] bg-yellow-900/50 text-yellow-500 px-2 py-1 rounded-lg ml-2 hover:bg-yellow-900 transition border border-yellow-700/50 uppercase font-bold tracking-widest relative z-50 pointer-events-auto">SABİTLE</button>` : '';

                let tick = (premTier === 3) ? verifiedTick : ''; 
                let adminTag = isAdmin ? `<span class="ml-2 bg-red-600 text-white px-2 py-0.5 rounded text-[9px] tracking-widest uppercase shadow-[0_0_10px_red]">👑 Yönetici</span>` : '';
                let aiTag = isAI ? `<span class="ml-2 bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 px-2 py-0.5 rounded-lg text-[9px] font-black tracking-widest uppercase shadow-[0_0_15px_rgba(6,182,212,0.4)] animate-pulse">🤖 YAPAY ZEKA</span>` : '';
                
                let msgDate = new Date(parseInt(msg.id));
                let timeStr = !isNaN(msgDate.getTime()) ? msgDate.getHours().toString().padStart(2, '0') + ":" + msgDate.getMinutes().toString().padStart(2, '0') : "";
                let timeHtml = `<span class="text-[9px] text-zinc-500 ml-2 font-bold tracking-widest bg-black/50 border border-zinc-800 px-1.5 py-0.5 rounded">${timeStr}</span>`;

                let avatarUrl = isAI ? 'https://cdn-icons-png.flaticon.com/512/4712/4712035.png' : (db.users.find(u => u.username === msg.user)?.avatar || 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg');
                let avatarHtml = `<img src="${avatarUrl}" class="w-8 h-8 rounded-full object-cover border shrink-0 ${isMe ? 'ml-2' : 'mr-2'} cursor-pointer hover:scale-110 transition-transform ${borderCls}" onclick="${isAI ? '' : `showOtherProfile('${msg.user}')`}">`;

                let content = ""; 
                let bubbleClass = isMe ? 'bg-white text-black' : 'bg-black/60 border border-zinc-800 text-zinc-300';
                
                if (isAI) {
                    content = `<div class="bg-black/80 border border-cyan-500/50 text-cyan-100 px-4 py-3 rounded-2xl text-sm break-words mt-1 shadow-[0_0_20px_rgba(6,182,212,0.2)] font-medium leading-relaxed relative overflow-hidden"><div class="absolute inset-0 bg-cyan-500/10 animate-pulse"></div><span class="relative z-10">${escapeHtml(msg.text)}</span></div>`;
                } else if (premTier >= 2) {
                    bubbleClass = isMe ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-[0_0_15px_rgba(168,85,247,0.5)]' : 'bg-gradient-to-r from-zinc-900 to-purple-950/40 border border-purple-500/50 text-white shadow-[0_0_15px_rgba(168,85,247,0.2)]';
                }
                
                if(!isAI) {
                    if (msg.type === "photo") {
                        content = `<img src="${msg.photo}" class="w-48 rounded-xl border border-zinc-700 shadow-lg mt-1 cursor-pointer hover:opacity-90 transition">`;
                    } else if (msg.type === "voice") {
                        content = `<div onclick="playVoice('${msg.audio}')" class="${bubbleClass} px-5 py-3 rounded-xl flex items-center gap-3 cursor-pointer mt-1 shadow-md hover:scale-105 transition"><span class="text-xl">🎙️</span><span class="font-bold text-xs uppercase tracking-widest">Ses Kaydı</span></div>`;
                    } else {
                        content = `<div class="${bubbleClass} px-4 py-2.5 rounded-2xl text-sm break-words mt-1 shadow-md font-medium leading-relaxed">${escapeHtml(msg.text)}</div>`;
                    }
                }
                
                let userDisplay = isAI ? `<span class="text-cyan-400 font-black tracking-widest drop-shadow-sm">SİSTEM AI</span>` : `<span onclick="showOtherProfile('${msg.user}')" style="${inlineStyle}" class="cursor-pointer hover:text-white transition ${textCls ? textCls : 'text-zinc-400'}">${msg.user}</span>`;
                
                // Build reaction bar
                const reactions = msg.reactions || {};
                let reactBar = '<div class="flex flex-wrap gap-1 mt-1">';
                const emojiList = ['👍','🔥','😂','😮','❤️','💪'];
                emojiList.forEach(em => {
                    const users = reactions[em] || [];
                    const iReacted = users.includes(currentUser.username);
                    if(users.length > 0 || true) {
                        reactBar += `<button onclick="addReaction('${msg.id}','${em}')" class="flex items-center gap-0.5 text-xs px-2 py-0.5 rounded-full border transition-all ${iReacted ? 'bg-red-900/40 border-sky-600/60 text-white' : 'bg-black/30 border-zinc-700/50 text-zinc-500 hover:border-zinc-500'}">${em}${users.length > 0 ? `<span class="text-[10px] font-bold">${users.length}</span>` : ''}</button>`;
                    }
                });
                reactBar += '</div>';

                return `
                <div class="flex ${isMe ? "justify-end" : "justify-start"} items-start mb-4 w-full ${isMe ? 'slide-in-right' : 'slide-in-left'}">
                    ${!isMe ? avatarHtml : ''}
                    <div class="max-w-[80%] flex flex-col ${isMe ? 'items-end' : 'items-start'}">
                        <div class="flex items-center gap-1 text-[10px] uppercase font-bold tracking-widest mb-1">
                            ${userDisplay}
                            ${tick} ${adminTag} ${aiTag} ${timeHtml} ${pinBtn} ${adminDel} ${reportBtn}
                        </div>
                        ${content}
                        ${reactBar}
                    </div>
                    ${isMe ? avatarHtml : ''}
                </div>`;
        }

        function renderChat(forceRedraw = false) {
            const container = document.getElementById("chat-messages");
            if(!container) return;
            if(!db.messages) db.messages = [];

            // Pinned mesaj
            const pinArea = document.getElementById("pinned-message-area"); 
            const pinText = document.getElementById("pinned-message-text");
            if(db.pinned_message && db.pinned_message.expires && db.pinned_message.expires > Date.now()) { 
                pinArea.classList.remove("hidden"); 
                pinText.textContent = `${db.pinned_message.user}: ${db.pinned_message.text}`; 
            } else { 
                pinArea.classList.add("hidden"); 
            }

            const wasAtBottom = container.scrollHeight - container.clientHeight <= container.scrollTop + 100;

            // Silinen mesaj var mı kontrol et
            const currentIds = new Set(db.messages.map(m => m.id));
            const hasDeleted = [..._renderedMsgIds].some(id => !currentIds.has(id));

            if (forceRedraw || hasDeleted) {
                // Silme veya zorla yenile - tüm container'ı yeniden çiz
                while(container.firstChild) container.removeChild(container.firstChild);
                _renderedMsgIds.clear();
            }

            // Sadece yeni mesajları DOM'a ekle
            db.messages.forEach(msg => {
                if (!_renderedMsgIds.has(msg.id)) {
                    const div = document.createElement('div');
                    div.innerHTML = buildMsgHTML(msg);
                    const el = div.firstElementChild;
                    if(el) {
                        el.dataset.msgId = msg.id;
                        container.appendChild(el);
                    }
                    _renderedMsgIds.add(msg.id);
                }
            });

            if(wasAtBottom || _renderedMsgIds.size <= db.messages.length) {
                requestAnimationFrame(() => {
                    container.scrollTop = container.scrollHeight;
                });
            }
        }

        async function sendChatMessage() { 
            if(!currentUser.accepted_chat_rules) {
                return document.getElementById("chat-rules-modal").classList.remove("hidden");
            }
            const inp = document.getElementById("chat-input"); 
            if(!inp.value.trim()) return;
            haptic([8]);
            const t = inp.value; 
            inp.value = ""; 
            const id = Date.now().toString(); 
            await sendAction('add_message', { id: id, text: t, type: "text" });
            // Daily/weekly mission counters
            if(currentUser.stats) {
                if(!currentUser.stats.daily_missions) currentUser.stats.daily_missions = {};
                if(!currentUser.stats.weekly_missions) currentUser.stats.weekly_missions = {};
                const todayKey = new Date().toISOString().split('T')[0];
                if(currentUser.stats.daily_missions.date !== todayKey) currentUser.stats.daily_missions = { date: todayKey };
                currentUser.stats.daily_missions.daily_msg = (currentUser.stats.daily_missions.daily_msg||0)+1;
                currentUser.stats.weekly_missions.weekly_msg = (currentUser.stats.weekly_missions.weekly_msg||0)+1;
                checkMissions();
            }
        }

        async function askAIGroup() {
            if(!currentUser.accepted_chat_rules) {
                return document.getElementById("chat-rules-modal").classList.remove("hidden");
            }
            const inp = document.getElementById("chat-input");
            const t = inp.value.trim();
            if(!t) return alert("Lutfen Freerider AI'a sormak istediginiz soruyu mesaj kutusuna yazin!");
            inp.value = "";
            await sendAction('ask_ai', { text: t });
            // Daily/weekly AI mission counter
            if(currentUser.stats) {
                if(!currentUser.stats.daily_missions) currentUser.stats.daily_missions = {};
                if(!currentUser.stats.weekly_missions) currentUser.stats.weekly_missions = {};
                const todayKey = new Date().toISOString().split('T')[0];
                if(currentUser.stats.daily_missions.date !== todayKey) currentUser.stats.daily_missions = { date: todayKey };
                currentUser.stats.daily_missions.daily_ai = (currentUser.stats.daily_missions.daily_ai||0)+1;
                currentUser.stats.weekly_missions.weekly_ai = (currentUser.stats.weekly_missions.weekly_ai||0)+1;
                checkMissions();
            }
        }

        function renderDmList() {
            const container = document.getElementById("dm-users-list");
            container.innerHTML = "";
            
            let uniqueUsers = new Set();
            db.dms.forEach(m => {
                if (m.participants && m.participants.includes(currentUser.username)) {
                    m.participants.forEach(p => { if (p !== currentUser.username) uniqueUsers.add(p); });
                }
            });

            uniqueUsers.add("Freerider AI");

            if(uniqueUsers.size === 0) {
                container.innerHTML = "<div class='text-zinc-500 text-xs italic text-center mt-5 font-medium'>Henüz kimseyle özel mesajlaşmadın.</div>";
                return;
            }

            Array.from(uniqueUsers).forEach(uName => {
                const u = db.users.find(x => x.username === uName);
                const isAI = uName === 'Freerider AI';
                
                let avatar = isAI ? 'https://cdn-icons-png.flaticon.com/512/4712/4712035.png' : (u ? u.avatar : 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg');
                
                let premColor = isAI ? '' : getUserPremiumColor(uName);
                let textCls = (getUserPremiumTier(uName) > 0) ? getPremiumTextClass(premColor) : '';
                let inlineStyle = (getUserPremiumTier(uName) > 0) ? getPremiumInlineStyle(premColor) : '';
                let nameHtml = isAI ? `<span class="text-cyan-400 font-black tracking-widest uppercase text-sm drop-shadow-[0_0_10px_cyan] animate-pulse">🤖 Freerider AI</span>` : `<span style="${inlineStyle}" class="font-bold text-sm tracking-wide ${textCls ? textCls : 'text-white'}">${uName}</span>`;

                const dmOnline = isAI ? '' : getOnlineHTML(u);
                container.innerHTML += `
                <div onclick="renderDmThread('${uName}')" class="bg-black/50 p-3 rounded-2xl border border-zinc-800 flex items-center gap-3 cursor-pointer hover:bg-zinc-800 hover:border-zinc-600 transition-all duration-200 shadow-sm mb-3 slide-up-anim">
                    <div class="relative">
                        <img src="${avatar}" class="w-12 h-12 rounded-full object-cover border border-zinc-700 shadow-inner">
                        ${!isAI && getOnlineStatus(u).status === 'online' ? '<span class="online-dot absolute bottom-0 right-0"></span>' : ''}
                    </div>
                    <div class="flex-1 overflow-hidden">
                        ${nameHtml}
                        <div class="flex items-center gap-2 mt-1">
                            ${dmOnline ? `<span class="flex items-center gap-1">${dmOnline}</span>` : `<span class="text-[10px] text-zinc-500 uppercase font-bold tracking-widest truncate">${isAI ? 'Özel Asistanın' : 'Görüntülemek için tıkla'}</span>`}
                        </div>
                    </div>
                    <div class="text-zinc-400 bg-zinc-900 w-8 h-8 rounded-full flex items-center justify-center border border-zinc-700">💬</div>
                </div>`;
            });
        }

        function startDm(targetUser) {
            document.getElementById("other-profile-modal").classList.add("hidden");
            switchTab(1);
            switchChatTab('dm');
            renderDmThread(targetUser);
        }

        function renderDmThread(targetUser) {
            currentDmUser = targetUser;
            document.getElementById("chat-dm-list-area").classList.add("hidden");
            document.getElementById("chat-dm-thread-area").classList.remove("hidden");
            document.getElementById("dm-thread-name").innerHTML = targetUser === 'Freerider AI' ? '<span class="text-cyan-400 drop-shadow-[0_0_10px_cyan] font-black tracking-widest">🤖 Freerider AI</span>' : targetUser;

            const container = document.getElementById("dm-messages");
            const isScrolled = container.scrollHeight - container.clientHeight <= container.scrollTop + 30;
            container.innerHTML = "";

            const threadMsgs = db.dms.filter(m => 
                m.participants && m.participants.includes(currentUser.username) && m.participants.includes(targetUser)
            ).sort((a,b) => parseInt(a.id) - parseInt(b.id));

            if(threadMsgs.length === 0) {
                container.innerHTML = `<div class="text-center text-xs text-zinc-500 mt-10 italic font-medium">Buradan sohbet edebilirsiniz. Mesajlar uçtan uca olmasa da izole şifrelenir.</div>`;
            }

            threadMsgs.forEach(msg => {
                const isMe = msg.sender === currentUser.username;
                const isAI = msg.sender === 'Freerider AI';
                let bubbleClass = isMe ? 'bg-white text-black' : 'bg-black/60 border border-zinc-800 text-zinc-300';
                
                if (isAI) {
                    bubbleClass = 'bg-black border border-cyan-500/50 text-cyan-100 shadow-[0_0_15px_rgba(6,182,212,0.3)] font-medium';
                }

                let content = "";
                if (msg.type === "photo") {
                    content = `<img src="${msg.photo}" onclick="openFullscreen(['${msg.photo}'],0)" class="w-48 rounded-xl border border-zinc-700 shadow-lg mt-1 cursor-pointer hover:opacity-90 transition-opacity">`;
                } else {
                    content = `<div class="${bubbleClass} px-4 py-2.5 rounded-2xl text-sm break-words mt-1 shadow-md leading-relaxed font-medium">${escapeHtml(msg.text)}</div>`;
                }

                let avatarUrl = isAI ? 'https://cdn-icons-png.flaticon.com/512/4712/4712035.png' : (db.users.find(u => u.username === msg.sender)?.avatar || 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg');
                let avatarHtml = `<img src="${avatarUrl}" class="w-8 h-8 rounded-full object-cover border border-zinc-700 shrink-0 ${isMe ? 'ml-2' : 'mr-2'}">`;

                container.innerHTML += `
                <div class="flex ${isMe ? "justify-end" : "justify-start"} items-start mb-5 w-full slide-up-anim">
                    ${!isMe ? avatarHtml : ''}
                    <div class="max-w-[80%] flex flex-col ${isMe ? 'items-end' : 'items-start'}">
                        <div class="flex items-center gap-1 text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1">
                            ${isMe ? 'Sen' : (isAI ? '<span class="text-cyan-400">AI</span>' : msg.sender)}
                        </div>
                        ${content}
                    </div>
                    ${isMe ? avatarHtml : ''}
                </div>`;
            });

            if(isScrolled || container.scrollTop === 0) {
                container.scrollTop = container.scrollHeight;
            }
        }

        function closeDmThread() {
            currentDmUser = null;
            document.getElementById("chat-dm-thread-area").classList.add("hidden");
            document.getElementById("chat-dm-list-area").classList.remove("hidden");
        }

        async function sendDmMessage() {
            const inp = document.getElementById("dm-input");
            const t = inp.value.trim();
            if(!t || !currentDmUser) return;
            
            inp.value = "";
            const id = Date.now().toString();
            
            db.dms.push({ id: id, sender: currentUser.username, receiver: currentDmUser, participants: [currentUser.username, currentDmUser], text: t, type: 'text' });
            renderDmThread(currentDmUser);

            await sendAction('send_dm', { id: id, text: t, receiver: currentDmUser, type: "text" });
        }

        function openMarketModal() {
            document.getElementById("mk-title").value = "";
            document.getElementById("mk-price").value = "";
            document.getElementById("mk-contact").value = "";
            document.getElementById("mk-desc").value = "";
            document.getElementById("mk-photos").value = "";
            
            const tier = getUserPremiumTier(currentUser.username);
            let maxP = 1;
            if(tier >= 3) maxP = 10; else if(tier >= 2) maxP = 4; else if(tier >= 1) maxP = 2;
            document.getElementById("mk-photo-label").textContent = `Fotoğraf Ekle (Maksimum ${maxP} Adet)`;
            
            document.getElementById("market-modal").classList.remove("hidden");
        }

        async function saveMarketItem() {
            const t = document.getElementById("mk-title").value;
            const p = document.getElementById("mk-price").value;
            const c = document.getElementById("mk-contact").value;
            const d = document.getElementById("mk-desc").value;
            const files = document.getElementById("mk-photos").files;

           if(files[0] && !checkFileSize(files[0], 10)) return;
            
            if(!t || !p || !c) return alert("Başlık, Fiyat ve İletişim zorunludur!");
            
            const tier = getUserPremiumTier(currentUser.username);
            let maxP = 1;
            if(tier >= 3) maxP = 10; else if(tier >= 2) maxP = 4; else if(tier >= 1) maxP = 2;
            
            if(files.length > maxP) return alert(`Mevcut paketiniz ${maxP} fotoğraf yüklemenize izin veriyor.`);
            
            document.getElementById("market-modal").classList.add("hidden");
            
            let photoDataArray = [];
            for(let i=0; i<files.length; i++) {
                if(i < maxP) {
                    let b64 = await resizeImage(files[i], 800);
                    if(b64) photoDataArray.push(b64);
                }
            }
            if(photoDataArray.length === 0) photoDataArray = ["https://placehold.co/400x300/121214/FFF?text=FOTO+YOK"];
            
            await sendAction('add_market', { id: Date.now().toString(), title: t, price: p, contact: c, desc: d, image: photoDataArray });
        }

        function renderMarket() {
            const container = document.getElementById("market-list");
            container.innerHTML = "";
            
            if(!db.market || db.market.length === 0) {
                container.innerHTML = "<div class='col-span-2 text-center text-zinc-500 italic mt-10 font-medium'>Pazar şu an boş.</div>";
                return;
            }
            
            const sortedMarket = db.market.sort((a,b) => (b.bumped_at || 0) - (a.bumped_at || 0));

            sortedMarket.forEach(item => {
                let mainImg = Array.isArray(item.image) ? item.image[0] : (item.image || "https://placehold.co/400x300/121214/FFF?text=FOTO+YOK");
                
                const ownerTier = getUserPremiumTier(item.owner);
                let borderClass = ownerTier >= 2 ? "border-purple-500 shadow-[0_0_15px_rgba(168,85,247,0.3)]" : "border-zinc-800 shadow-sm";
                let premiumTag = ownerTier >= 2 ? `<div class="absolute top-0 right-0 bg-purple-600 text-white text-[8px] font-black px-2 py-1 rounded-bl-lg shadow-lg z-10 uppercase tracking-widest">Premium İlan</div>` : "";

                container.innerHTML += `
                <div onclick="openMarketDetail('${item.id}')" class="bg-black/40 rounded-2xl overflow-hidden border ${borderClass} relative cursor-pointer hover:border-zinc-500 transition-all duration-300 hover:scale-[1.02] flex flex-col group">
                    ${premiumTag}
                    <div class="h-32 w-full bg-zinc-950 relative border-b border-zinc-800">
                        <img src="${mainImg}" class="w-full h-full object-cover group-hover:opacity-90 transition-opacity">
                        <div class="absolute bottom-2 left-2 bg-black/80 backdrop-blur-md px-3 py-1.5 rounded-lg border border-zinc-700 text-green-400 font-black text-xs shadow-lg">${item.price} TL</div>
                    </div>
                    <div class="p-4 flex-1 flex flex-col">
                        <h3 class="text-white font-bold text-xs tracking-wide flex-1 leading-snug">${item.title}</h3>
                        <div class="text-[9px] text-zinc-500 font-bold uppercase tracking-widest mt-3 flex justify-between items-center border-t border-zinc-800 pt-2">
                            <span class="truncate pr-2">👤 ${item.owner}</span>
                            <span class="shrink-0">👁️ ${item.views || 0}</span>
                        </div>
                    </div>
                </div>`;
            });
        }

        // openMarketDetail: renderMarket kartlarından çağrılan alias — viewMarketDetail ile aynıdır
        function openMarketDetail(id) {
            const item = db.market.find(x => String(x.id) === String(id));
            if(!item) { console.warn('[Market] openMarketDetail: ID bulunamadı:', id); return; }
            viewMarketDetail(id);
        }

        function viewMarketDetail(id) {
            const item = db.market.find(x => String(x.id) === String(id));
            if(!item) { console.warn('Market item not found for id:', id); return; }
            
            currentMarketId = id;
            window.currentOwner = item.owner;
            
            if(item.owner !== currentUser.username) {
                sendAction('increment_market_view', { id: id }).catch(e=>{});
            }

            const imgContainer = document.getElementById("md-photos");
            imgContainer.innerHTML = "";
            let images = Array.isArray(item.image) ? item.image : [item.image || "https://placehold.co/400x300/121214/FFF?text=FOTO+YOK"];
            images.forEach(img => {
                imgContainer.innerHTML += `<img src="${img}" class="h-full w-auto object-contain shrink-0 scroll-snap-align-center rounded-xl">`;
            });

            document.getElementById("md-title").textContent = item.title;
            document.getElementById("md-price").textContent = `${item.price} TL`;
            
            if(getUserPremiumTier(currentUser.username) === 3 || item.owner === currentUser.username) {
                document.getElementById("md-views-badge").classList.remove("hidden");
                document.getElementById("md-views-badge").textContent = `👁️ ${item.views || 0} Görüntülenme`;
            } else {
                document.getElementById("md-views-badge").classList.add("hidden");
            }
            
            const ownerObj = db.users.find(u => u.username === item.owner);
            document.getElementById("md-owner-avatar").src = ownerObj ? ownerObj.avatar : "https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg";
            document.getElementById("md-owner").textContent = item.owner;
            
            document.getElementById("md-desc").textContent = item.desc || "Açıklama girilmemiş.";
            document.getElementById("md-contact").textContent = item.contact;

            let actionsHtml = "";
            if(item.owner !== currentUser.username) {
                actionsHtml += `<button onclick="startDm('${item.owner}')" class="bg-white hover:bg-gray-200 transition text-black py-4 rounded-xl font-bold text-sm w-full shadow-[0_0_15px_rgba(255,255,255,0.3)] btn-premium-hover">✉️ SATICIYA MESAJ AT</button>`;
            }
            
            if(item.owner === currentUser.username && getUserPremiumTier(currentUser.username) >= 2) {
                actionsHtml += `<button onclick="bumpMarket('${item.id}')" class="bg-purple-900/50 hover:bg-purple-800 transition text-purple-400 border border-purple-500/50 py-3.5 rounded-xl font-bold text-xs w-full mt-3 uppercase tracking-widest shadow-lg btn-premium-hover">🚀 İLANI EN ÜSTE TAŞI (BUMP)</button>`;
            }
            
            if(item.owner === currentUser.username || currentUser.role === 'Admin') {
                actionsHtml += `<button onclick="deleteMarket('${item.id}')" class="bg-red-950/50 hover:bg-sky-900/80 transition text-sky-400 border border-sky-900/50 py-3.5 rounded-xl font-bold text-xs w-full mt-3 uppercase tracking-widest btn-premium-hover shadow-md">İLANI SİL</button>`;
            }
            
            document.getElementById("md-actions-area").innerHTML = actionsHtml;
            document.getElementById("market-detail-modal").classList.remove("hidden");
        }

        async function bumpMarket(id) {
            await sendAction('bump_market', { id: id });
            alert("İlanınız başarıyla en üste taşındı!");
            document.getElementById("market-detail-modal").classList.add("hidden");
            renderMarket();
        }

        async function deleteMarket(id) {
            if(confirm("Bu ilanı silmek istediğinize emin misiniz?")) {
                await sendAction('delete_market', { id: id });
                db.market = db.market.filter(m => m.id !== id);
                document.getElementById("market-detail-modal").classList.add("hidden");
                renderMarket();
            }
        }

        function switchLeaderboard(tab) {
            currentLeaderboardTab = tab;
            document.getElementById("rank-tab-weekly").className = "flex-1 py-2 bg-transparent text-zinc-500 hover:text-white rounded font-bold text-xs transition";
            document.getElementById("rank-tab-month").className = "flex-1 py-2 bg-transparent text-zinc-500 hover:text-white rounded font-bold text-xs transition";
            document.getElementById("rank-tab-all").className = "flex-1 py-2 bg-transparent text-zinc-500 hover:text-white rounded font-bold text-xs transition";
            
            if(tab === 'weekly') {
                document.getElementById("rank-tab-weekly").className = "flex-1 py-2 bg-zinc-800 text-white rounded font-bold text-xs transition shadow-sm";
            } else if(tab === 'month') {
                document.getElementById("rank-tab-month").className = "flex-1 py-2 bg-zinc-800 text-white rounded font-bold text-xs transition shadow-sm";
            } else {
                document.getElementById("rank-tab-all").className = "flex-1 py-2 bg-zinc-800 text-white rounded font-bold text-xs transition shadow-sm";
            }
            renderLeaderboard();
        }


        function renderLeaderboard() {
            const container = document.getElementById("leaderboard");
            container.innerHTML = "";

            // Admin sıralamada gösterilmez
            const visibleUsers = db.users.filter(u => u.username !== 'Admin' && u.role !== 'Admin');

            let sortedUsers = [];
            if(currentLeaderboardTab === 'weekly') {
                sortedUsers = [...visibleUsers].sort((a,b) => ((b.stats&&b.stats.weekly_xp)||0) - ((a.stats&&a.stats.weekly_xp)||0)).slice(0,50);
            } else if(currentLeaderboardTab === 'month') {
                sortedUsers = [...visibleUsers].sort((a,b) => ((b.stats&&b.stats.monthly_xp)||0) - ((a.stats&&a.stats.monthly_xp)||0)).slice(0,50);
            } else {
                sortedUsers = [...visibleUsers].sort((a,b) => (b.xp||0) - (a.xp||0)).slice(0,50);
            }

            if(sortedUsers.length === 0) {
                container.innerHTML = "<div class='text-zinc-500 text-xs italic text-center py-8'>Henuz siralamada kimse yok.</div>";
                return;
            }

            // Champion banner (1st place highlight)
            const champ = sortedUsers[0];
            if(champ) {
                const champColor = getUserPremiumColor(champ.username);
                const champTextCls = getUserPremiumTier(champ.username) > 0 ? getPremiumTextClass(champColor) : 'text-yellow-400';
                const tabLabel = currentLeaderboardTab === 'weekly' ? 'Bu Haftanin Birincisi' : currentLeaderboardTab === 'month' ? 'Bu Ayin Birincisi' : 'Tum Zamanlarin Birincisi';
                const champVal = currentLeaderboardTab === 'weekly' ? ((champ.stats&&champ.stats.weekly_xp)||0) : currentLeaderboardTab === 'month' ? ((champ.stats&&champ.stats.monthly_xp)||0) : (champ.xp||0);
                container.innerHTML += `
                <div class="relative bg-gradient-to-r from-yellow-900/60 to-amber-900/40 rounded-3xl p-5 mb-5 border border-yellow-600/50 shadow-[0_0_30px_rgba(234,179,8,0.25)] overflow-hidden">
                    <div class="absolute inset-0 opacity-10 pointer-events-none" style="background:radial-gradient(circle at 70% 50%, #fbbf24 0%, transparent 70%);"></div>
                    <div class="text-[10px] text-yellow-500 font-black uppercase tracking-[0.15em] mb-2 flex items-center gap-2">
                        <span class="animate-pulse">👑</span> ${tabLabel}
                    </div>
                    <div class="flex items-center gap-4">
                        <div class="relative">
                            <img src="${champ.avatar||'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg'}" class="w-16 h-16 rounded-full object-cover border-4 border-yellow-500 shadow-[0_0_20px_rgba(234,179,8,0.6)]">
                            <div class="absolute -bottom-1 -right-1 text-2xl">🥇</div>
                        </div>
                        <div class="flex-1">
                            <div class="font-black text-xl ${champTextCls} teko-font tracking-wide">${champ.username}</div>
                            <div class="text-yellow-400 font-black text-2xl teko-font">${champVal.toLocaleString()} XP</div>
                            <div class="text-[10px] text-zinc-400 mt-1">${currentLeaderboardTab === 'weekly' ? '🏆 1 Haftalik Ultra+ Odulu Kazanacak!' : currentLeaderboardTab === 'month' ? '🏆 1 Aylik Deluxe Odulu Kazanacak!' : ''}</div>
                        </div>
                    </div>
                </div>`;
            }

            sortedUsers.forEach((u, index) => {
                const title = getTitle(u.xp);
                const isMe = u.username === currentUser.username;
                let rankVisual = `<div class="w-8 h-8 rounded-full bg-black/60 border border-zinc-700 flex items-center justify-center font-black text-xs text-zinc-400">${index+1}</div>`;
                if(index === 0) rankVisual = `<div class="text-3xl drop-shadow-[0_0_15px_rgba(251,191,36,0.9)] animate-pulse">🥇</div>`;
                if(index === 1) rankVisual = `<div class="text-3xl drop-shadow-[0_0_12px_rgba(156,163,175,0.8)]">🥈</div>`;
                if(index === 2) rankVisual = `<div class="text-3xl drop-shadow-[0_0_12px_rgba(180,83,9,0.8)]">🥉</div>`;

                const premColor = getUserPremiumColor(u.username);
                const textCls = getUserPremiumTier(u.username)>0 ? getPremiumTextClass(premColor) : '';
                const inlineStyle = getUserPremiumTier(u.username)>0 ? getPremiumInlineStyle(premColor) : '';
                const borderCls = getUserPremiumTier(u.username)>0 ? getPremiumBorderClass(u.username) : 'border-zinc-700';
                const onlineHtml = getOnlineHTML(u);

                let val = currentLeaderboardTab==='weekly' ? ((u.stats&&u.stats.weekly_xp)||0)
                        : currentLeaderboardTab==='month' ? ((u.stats&&u.stats.monthly_xp)||0)
                        : (u.xp||0);

                // Reward badge for top 3
                let rewardTag = '';
                if(index === 0 && currentLeaderboardTab === 'weekly') rewardTag = '<span class="text-[9px] bg-yellow-600 text-black px-2 py-0.5 rounded font-black ml-1">1HFT ULTRA+</span>';
                else if((index===1||index===2) && currentLeaderboardTab==='weekly') rewardTag = '<span class="text-[9px] bg-purple-600 text-white px-2 py-0.5 rounded font-black ml-1">1HFT DLX</span>';
                else if(index<=2 && currentLeaderboardTab==='month') rewardTag = '<span class="text-[9px] bg-blue-600 text-white px-2 py-0.5 rounded font-black ml-1">1AY DLX</span>';

                container.innerHTML += `
                <div onclick="showOtherProfile('${u.username}')" class="bg-black/40 p-4 rounded-2xl border ${isMe?'border-zinc-400 shadow-[0_0_15px_rgba(255,255,255,0.15)]':'border-zinc-800'} flex items-center gap-4 cursor-pointer hover:bg-zinc-800/50 transition-all duration-200 shadow-sm group slide-up-anim mb-2">
                    <div class="w-10 flex justify-center shrink-0">${rankVisual}</div>
                    <div class="relative shrink-0">
                        <img src="${u.avatar||'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg'}" class="w-11 h-11 rounded-full object-cover border-2 ${borderCls} shadow-md group-hover:scale-110 transition-transform">
                        ${getOnlineStatus(u).status==='online'?'<span class="online-dot absolute bottom-0 right-0"></span>':''}
                    </div>
                    <div class="flex-1 overflow-hidden">
                        <div class="flex items-center gap-1 flex-wrap">
                            <span style="${inlineStyle}" class="font-bold text-sm tracking-wide truncate ${textCls||'text-white'}">${u.username}</span>${rewardTag}
                        </div>
                        <div class="flex items-center gap-2 mt-0.5">
                            <span class="text-[9px] text-zinc-500 font-bold uppercase">${title.icon} ${title.name}</span>
                            ${onlineHtml?`<span class="flex items-center gap-1">${onlineHtml}</span>`:''}
                        </div>
                    </div>
                    <div class="text-right shrink-0 bg-zinc-950/50 px-3 py-2 rounded-xl border border-zinc-800">
                        <div class="text-white font-black text-lg teko-font tracking-widest">${val.toLocaleString()}</div>
                        <div class="text-[9px] text-zinc-500 uppercase font-bold">XP</div>
                    </div>
                </div>`;
            });
        }
        function renderNews() {
            const container = document.getElementById("news-list");
            container.innerHTML = "";
            db.news.forEach(n => {
                let imgHtml = n.image ? `<img src="${n.image}" class="w-full h-48 object-cover rounded-xl mt-4 border border-zinc-700 shadow-md">` : '';
                let delBtn = currentUser.role === 'Admin' ? `<button onclick="deleteNews('${n.id}')" class="mt-4 bg-red-950/50 hover:bg-sky-900/80 text-sky-400 px-5 py-2.5 rounded-xl text-xs font-bold border border-sky-900/50 transition btn-premium-hover uppercase tracking-widest shadow-md">Haberi Sil</button>` : '';
                
                container.innerHTML += `
                <div class="glass-panel p-6 rounded-3xl border border-zinc-800 shadow-xl mb-5 slide-up-anim">
                    <h3 class="text-2xl text-white font-bold tracking-wide drop-shadow-sm leading-tight">${n.title}</h3>
                    <div class="text-[10px] text-zinc-500 font-bold uppercase tracking-widest mt-2 flex items-center gap-2"><span class="animate-pulse">🕒</span> ${n.date}</div>
                    ${imgHtml}
                    <p class="text-sm text-zinc-300 mt-5 leading-relaxed whitespace-pre-wrap font-medium">${n.content}</p>
                    ${delBtn}
                </div>`;
            });
        }

        function openNewsAdminModal() { document.getElementById("news-admin-modal").classList.remove("hidden"); }
        
        async function saveNews() {
            const t = document.getElementById("news-title").value;
            const c = document.getElementById("news-content").value;
            const f = document.getElementById("news-photo").files[0];
            
            if(!t || !c) return alert("Başlık ve içerik zorunludur!");
            
            document.getElementById("news-admin-modal").classList.add("hidden");
            
            let imgData = null;
            if(f) imgData = await resizeImage(f, 800);
            
            await sendAction('add_news', { id: Date.now().toString(), title: t, content: c, image: imgData, date: new Date().toLocaleDateString() });
            renderNews();
        }
        
        async function deleteNews(id) {
            if(confirm("Haberi silmek istiyor musunuz?")) {
                await sendAction('delete_news', {id: id});
                db.news = db.news.filter(n => n.id !== id);
                renderNews();
            }
        }

        function switchTab(idx) {
            stopAllMedia(); // Hayalet ses önleme — tüm medyayı durdur
            // ── Premium Reklam: İlk gösterimden sonra her sekme geçişinde %15 ihtimal ──
            if (idx !== 6 && sessionStorage.getItem('fr_premium_shown') === '1') {
                if (Math.random() < 0.15) {
                    // Önce hedef sekmeye NOT git; önce premium göster, sonra geçişi iptal et
                    switchTab(6);
                    return;
                }
            }
            if (idx !== 9) _prevTab = idx; // Reels dışındaki son sekmeyi hatırla
            const tabs = ['screen-map', 'screen-chat', 'screen-market', 'screen-rank', 'screen-news', 'screen-missions', 'screen-premium', 'screen-profile', 'screen-referral', 'screen-reels'];
            tabs.forEach((t, i) => {
                const el = document.getElementById(t);
                if(!el) return;
                if(i === idx) {
                    // Görünür yap - chat için innerHTML'e dokunmadan
                    el.style.display = 'flex';
                    el.style.flexDirection = 'column';
                    el.style.zIndex = '20';
                    el.style.opacity = '1';
                    el.style.pointerEvents = 'auto';
                    el.classList.remove('hidden');
                    el.style.animation = 'none';
                    el.offsetHeight;
                    el.style.animation = 'slideUpFade 0.38s cubic-bezier(0.16, 1, 0.3, 1) both';
                } else {
                    // Gizle ama innerHTML'e dokunma
                    el.style.display = 'none';
                    el.style.zIndex = '-1';
                    el.style.pointerEvents = 'none';
                    el.classList.add('hidden');
                    el.style.animation = 'none';
                }
            });
            
            document.querySelectorAll(".tab-btn").forEach((btn, i) => {
                if(i === idx) {
                    btn.classList.add("text-white", "scale-105", "opacity-100", "bg-zinc-800/80", "shadow-md");
                    btn.classList.remove("text-zinc-500", "opacity-70", "bg-zinc-900/50", "hover:bg-zinc-900/50");
                } else {
                    btn.classList.remove("text-white", "scale-105", "opacity-100", "bg-zinc-800/80", "shadow-md");
                    btn.classList.add("text-zinc-500", "opacity-70", "hover:bg-zinc-900/50");
                }
            });

            // Reels tam ekran: alt nav'ı gizle/göster
            const bottomNav = document.getElementById('bottom-nav');
            const soundBtn2 = document.getElementById('reel-sound-btn');
            const gridBtn2  = document.getElementById('grid-view-btn');
            const uploadTopBtn2 = document.getElementById('reels-upload-top-btn');
            if(idx === 9) {
                if(bottomNav) bottomNav.style.display = 'none';
                // Ses, ızgara ve yükleme butonlarını göster (loadReels bitmeden önce de görünsün)
                if(soundBtn2) { soundBtn2.style.display = 'flex'; soundBtn2.textContent = _reelMuted ? '🔇' : '🔊'; }
                if(gridBtn2)  gridBtn2.style.display = 'flex';
                if(uploadTopBtn2) uploadTopBtn2.style.display = 'flex';
                document.getElementById('screen-map') && (document.getElementById('screen-map').style.zIndex = '1');
            } else {
                if(bottomNav) bottomNav.style.display = '';
                if(soundBtn2) soundBtn2.style.display = 'none';
                if(gridBtn2)  gridBtn2.style.display = 'none';
                if(uploadTopBtn2) uploadTopBtn2.style.display = 'none';
                // stopAllMedia zaten başta çağrıldı, ek pause gerekmez
            }

            if(idx === 0) { if(map) map.invalidateSize(); }
            if(idx === 1) { renderChat(); renderDmList(); clearChatBadge(); renderStoryBar(); }
            if(idx === 2) renderMarket();
            if(idx === 3) renderLeaderboard();
            if(idx === 4) renderNews();
            if(idx === 5) { renderMissions(); updateSpinInfo(); setTimeout(initWheel3D, 150); }
            if(idx === 7) { updateProfileUI(); updateNotifBtnState(); }
            if(idx === 8) renderReferralTab();
            if(idx === 9) loadReels();
            
            // Alt nav güncelle (premium animasyonlu)
            const bnavIds = [0,1,9,3,7];
            bnavIds.forEach(i => {
                const btn = document.getElementById('bnav-' + i);
                if(!btn) return;
                const iconEl = btn.querySelector('span:first-child');
                const labelEl = btn.querySelector('span:last-child');
                if(i === idx) {
                    btn.classList.add('text-white');
                    btn.classList.remove('text-zinc-500');
                    btn.style.background = 'linear-gradient(135deg,rgba(2,132,199,0.3),rgba(3,105,161,0.15))';
                    btn.style.boxShadow = '0 0 16px rgba(14,165,233,0.25),inset 0 1px 0 rgba(255,255,255,0.05)';
                    if(iconEl) {
                        iconEl.style.transform = 'scale(1.18) translateY(-1px)';
                        iconEl.style.filter = 'drop-shadow(0 0 6px rgba(14,165,233,0.8))';
                    }
                    if(labelEl) {
                        labelEl.style.color = '#7dd3fc';
                        labelEl.style.opacity = '1';
                    }
                } else {
                    btn.classList.remove('text-white');
                    btn.classList.add('text-zinc-500');
                    btn.style.background = '';
                    btn.style.boxShadow = '';
                    if(iconEl) {
                        iconEl.style.transform = '';
                        iconEl.style.filter = '';
                    }
                    if(labelEl) {
                        labelEl.style.color = '';
                        labelEl.style.opacity = '';
                    }
                }
            });

            const sidebar = document.getElementById("sidebar");
            if(sidebar && !sidebar.classList.contains("-translate-x-full") && window.innerWidth < 768) {
                toggleSidebar();
            }
        }

        // ============================================================
        // PROMINENT DISCLOSURE — Fotoğraf (Google Play uyumu)
        // file input tetiklenmeden ÖNCE kullanıcıya amaç gösterilir.
        // ============================================================
        const _PD_PHOTO_CFG = {
            group:   { icon:'💬', title:'Sohbete Fotoğraf Ekle',   sub:'Grup Sohbeti',
                       desc:'Seçeceğin fotoğraf <strong class="text-white">grup sohbetine</strong> gönderilecek.',
                       items:['Fotoğraf yalnızca grup üyelerine görünür','Görsel otomatik boyutlandırılır (maks. 800px)','Yalnızca seçtiğin görsel paylaşılır'] },
            dm:      { icon:'✉️', title:'Mesaja Fotoğraf Ekle',     sub:'Özel Mesaj',
                       desc:'Seçeceğin fotoğraf <strong class="text-white">özel mesaj</strong> olarak gönderilecek.',
                       items:['Yalnızca mesaj gönderdiğin kişi görebilir','Görsel otomatik boyutlandırılır (maks. 800px)','Yalnızca seçtiğin görsel paylaşılır'] },
            profile: { icon:'👤', title:'Profil Fotoğrafı Güncelle', sub:'Profil Görseli',
                       desc:'Seçeceğin fotoğraf <strong class="text-white">profil resmin</strong> olarak ayarlanacak.',
                       items:['Tüm kullanıcılar profil fotoğrafını görebilir','Görsel otomatik kırpılır ve optimize edilir (400px)','Yalnızca seçtiğin görsel yüklenir'] },
            reel:    { icon:'🎬', title:'Reel Medya Seç',           sub:'Reel / Gönderi',
                       desc:'Seçeceğin fotoğraf veya video <strong class="text-white">reel olarak paylaşılacak</strong>.',
                       items:['Tüm topluluk üyeleri görebilir','Fotoğraflar optimize edilir, videolar maks. 50MB','Yalnızca seçtiğin dosya paylaşılır'] },
        };

        function _showPhotoDisclosure(context, onConfirm) {
            const cfg = _PD_PHOTO_CFG[context] || _PD_PHOTO_CFG.profile;
            document.getElementById('pd-photo-icon').textContent     = cfg.icon;
            document.getElementById('pd-photo-title').textContent    = cfg.title;
            document.getElementById('pd-photo-subtitle').textContent = cfg.sub;
            document.getElementById('pd-photo-desc').innerHTML       = cfg.desc;
            document.getElementById('pd-photo-list').innerHTML = cfg.items
                .map(t => `<li class="flex items-start gap-2"><span class="text-pink-400 shrink-0 mt-0.5">✔</span><span>${t}</span></li>`)
                .join('');
            const modal    = document.getElementById('pd-photo-modal');
            const allowBtn = document.getElementById('pd-photo-allow');
            const denyBtn  = document.getElementById('pd-photo-deny');
            modal.classList.remove('hidden');
            const cleanup = () => { allowBtn.removeEventListener('click', onAllow); denyBtn.removeEventListener('click', onDeny); };
            function onAllow() { modal.classList.add('hidden'); cleanup(); onConfirm(); }
            function onDeny()  { modal.classList.add('hidden'); cleanup(); }
            allowBtn.addEventListener('click', onAllow);
            denyBtn.addEventListener('click',  onDeny);
        }

        function openPhotoUpload(context) {
            currentPhotoContext = context;
            _showPhotoDisclosure(context, () => { document.getElementById("chat-photo-upload").click(); });
        }

        async function handleChatPhotoUpload(input) {
            if(!input.files[0]) return;
            const b64 = await resizeImage(input.files[0], 800);
            if(b64) {
                const id = Date.now().toString();
                if(currentPhotoContext === 'group') {
                    await sendAction('add_message', { id: id, photo: b64, type: "photo" });
                } else if(currentPhotoContext === 'dm' && currentDmUser) {
                    db.dms.push({ id: id, sender: currentUser.username, receiver: currentDmUser, participants: [currentUser.username, currentDmUser], photo: b64, type: 'photo' });
                    renderDmThread(currentDmUser);
                    await sendAction('send_dm', { id: id, photo: b64, receiver: currentDmUser, type: "photo" });
                }
            }
            input.value = "";
        }

        // ============================================================
        // PROMINENT DISCLOSURE — Mikrofon (Google Play uyumu)
        // getUserMedia() çağrısından ÖNCE kullanıcıya amaç gösterilir.
        // İzin zaten verildiyse modal atlanır, kayıt doğrudan başlar.
        // ============================================================
        async function toggleVoiceRecord(context) {
            if(getUserPremiumTier(currentUser.username) < 2) {
                return alert("Sesli mesaj gönderme özelliği Deluxe ve Ultra+ üyelerine özeldir!");
            }
            const btn = document.getElementById("voice-btn");

            // Aktif kayıt varsa durdur — disclosure gerektirmez
            // NOT: MediaRecorder.state değerleri: "inactive", "recording", "paused"
            // Önceki kodda "active" kullanılıyordu ki bu HİÇBİR ZAMAN true olmaz!
            if (mediaRecorder && mediaRecorder.state === "recording") {
                _voiceStopping = true;   // Blob işlenene kadar yeni kaydı engelle
                mediaRecorder.stop();
                // stop event handler içinde btn sıfırlanacak ve mediaRecorder = null yapılacak
                return;
            }

            // Blob henüz işleniyorsa (stop() sonrası kısa pencere) izin akışına düşme
            if (_voiceStopping) return;

            // İzin zaten verilmişse doğrudan kaydı başlat (modal gösterme)
            try {
                const perm = await navigator.permissions.query({ name: 'microphone' });
                if (perm.state === 'granted') { await _startVoiceCapture(context, btn); return; }
            } catch(_) { /* permissions API desteklenmiyor — modal göster */ }

            // Prominent Disclosure modal — sadece izin granted DEĞİLSE gösterilir
            const modal    = document.getElementById('pd-mic-modal');
            const allowBtn = document.getElementById('pd-mic-allow');
            const denyBtn  = document.getElementById('pd-mic-deny');
            modal.classList.remove('hidden');
            const cleanup = () => { allowBtn.removeEventListener('click', onAllow); denyBtn.removeEventListener('click', onDeny); };
            async function onAllow() { modal.classList.add('hidden'); cleanup(); await _startVoiceCapture(context, btn); }
            function onDeny()        { modal.classList.add('hidden'); cleanup(); }
            allowBtn.addEventListener('click', onAllow);
            denyBtn.addEventListener('click',  onDeny);
        }

        async function _startVoiceCapture(context, btn) {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                mediaRecorder = new MediaRecorder(stream);
                audioChunks = [];
                btn.className = "bg-red-600 w-10 h-10 md:w-12 md:h-12 rounded-xl text-lg flex items-center justify-center animate-pulse shadow-[0_0_20px_rgba(14,165,233,0.8)] border border-sky-400 transition-all";
                btn.innerHTML = "⏹️";
                mediaRecorder.addEventListener("dataavailable", ev => { audioChunks.push(ev.data); });
                mediaRecorder.addEventListener("stop", async () => {
                    // Ses verisini hazırla ve gönder
                    const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                    const reader = new FileReader();
                    reader.readAsDataURL(audioBlob);
                    reader.onloadend = async function() {
                        const b64 = reader.result;
                        const id  = Date.now().toString();
                        if(context === 'group') await sendAction('add_message', { id, audio: b64, type: "voice" });
                    };
                    // Mikrofon stream'ini kapat
                    stream.getTracks().forEach(t => t.stop());
                    // Butonu sıfırla
                    btn.className = "bg-zinc-800/80 hover:bg-zinc-700 transition w-10 h-10 md:w-12 md:h-12 rounded-xl text-lg flex items-center justify-center border border-zinc-700 btn-premium-hover";
                    btn.innerHTML = "🎤";
                    // KRITIK: mediaRecorder'ı null yap ki sonraki tıklamada
                    // stale "inactive" state yüzünden yanlış dallanma olmasın
                    audioChunks = [];
                    mediaRecorder = null;
                    _voiceStopping = false; // Artık yeni kayda izin ver
                });
                // start() çağrısı event listener'lardan SONRA yapılmalı
                mediaRecorder.start();
            } catch(err) {
                console.error('Mikrofon hatası:', err);
                mediaRecorder = null;
                alert("Mikrofon izni alınamadı. Tarayıcı ayarlarından mikrofon iznini etkinleştir.");
            }
        }
        
        function playVoice(src) { const a = new Audio(src); a.play(); }

        // Premium modal animasyon yardımcısı
        function showModal(id) {
            const el = document.getElementById(id);
            if(!el) return;
            el.classList.remove('hidden');
            const inner = el.querySelector('.modal-inner, [class*="glass-panel"], [class*="bg-zinc"], [class*="bg-black"]');
            if(inner) {
                inner.style.animation = 'none';
                inner.offsetHeight;
                inner.style.animation = 'scaleInFade 0.32s cubic-bezier(0.34,1.56,0.64,1) both';
            }
        }
        function hideModal(id) {
            const el = document.getElementById(id);
            if(!el) return;
            el.classList.add('hidden');
        }

        function openSettingsModal() {
            document.getElementById("edit-name").value = currentUser.name || "";
            document.getElementById("edit-bio").value = currentUser.bio || "";
            document.getElementById("edit-password").value = "";
            
            const stats = currentUser.stats || {};
            document.getElementById("edit-email").value = stats.email || "";
            document.getElementById("edit-marketing").checked = stats.marketing_opt_in || false;
            
            const statusDiv = document.getElementById("profile-email-status");
            if(stats.email) {
                if(stats.email_verified) {
                    statusDiv.innerHTML = `<span class="bg-green-900/40 text-green-400 text-[10px] px-3 py-1.5 rounded-lg font-bold border border-green-800/50 shadow-sm uppercase tracking-widest inline-flex items-center gap-1"><span class="text-sm">✅</span> E-Posta Doğrulandı</span>`;
                } else {
                    statusDiv.innerHTML = `<span class="bg-yellow-900/40 text-yellow-500 text-[10px] px-3 py-1.5 rounded-lg font-bold border border-yellow-800/50 shadow-sm uppercase tracking-widest inline-flex items-center gap-1"><span class="text-sm">⚠️</span> E-Posta Doğrulanmadı</span>`;
                }
            } else {
                statusDiv.innerHTML = `<span class="bg-zinc-800 text-zinc-400 text-[10px] px-3 py-1.5 rounded-lg font-bold border border-zinc-700 uppercase tracking-widest inline-block">E-Posta Eklenmemiş</span>`;
            }

            checkEmailChange();
            document.getElementById("settings-modal").classList.remove("hidden");
        }

        function checkEmailChange() {
            const stats = currentUser.stats || {};
            const currentEmail = stats.email || "";
            const inputEmail = document.getElementById("edit-email").value.trim();
            const btn = document.getElementById("btn-verify-email");
            
            if (inputEmail !== "" && (inputEmail !== currentEmail || !stats.email_verified)) {
                btn.classList.remove("hidden");
            } else {
                btn.classList.add("hidden");
            }
        }

        function closeSettingsModal() { document.getElementById("settings-modal").classList.add("hidden"); }

        async function saveSettings() {
            const n = document.getElementById("edit-name").value;
            const b = document.getElementById("edit-bio").value;
            const p = document.getElementById("edit-password").value;
            
            const emailEl = document.getElementById("edit-email");
            const emailInput = emailEl ? emailEl.value.trim() : "";
            
            const stats = currentUser.stats || {};
            let emailChanged = false;
            
            const currentSavedEmail = (stats.email || "").trim().toLowerCase();
            const newEmailNorm = emailInput.toLowerCase();
            
            if (newEmailNorm !== currentSavedEmail && emailInput !== "") {
                // Gerçekten farklı bir email girildiyse değiştir
                emailChanged = true;
                stats.email = emailInput;
                stats.email_verified = false;
            } else if (emailInput === "") {
                // Email alanı boş bırakıldıysa mevcut emaili koru
                // stats.email değişmesin
            }
            // email aynıysa hiçbir şey yapma (email_verified korunur)

            if (p && p.trim() !== "") { 
                if (p.length < 4) return alert("Şifre en az 4 hane olmalı."); 
            }
            
            currentUser.name = n;
            currentUser.bio = b;
            
            const data = { username: currentUser.username, name: n, bio: b };
            if (p && p.trim() !== "") data.password = p;
            
            data.stats = stats;

            try {
                await sendAction('update_user', data);
                
                if (p && p.trim() !== "") {
                    if (localStorage.getItem("fr_remembered_username")) {
                        localStorage.setItem("fr_remembered_password", btoa(unescape(encodeURIComponent(p))));
                    }
                }

                currentUser.stats = stats;
                localStorage.setItem("fr_user", JSON.stringify(currentUser));

                updateProfileUI(); 
                
                if (emailChanged && emailInput !== "") {
                    alert("Profil güncellendi! E-posta adresiniz güncellendi ancak henüz ONAYLANMADI. 'Doğrulama Kodu Gönder' butonuyla e-postanızı onaylayın.");
                } else {
                    alert("Profil başarıyla güncellendi.");
                }
                closeSettingsModal(); 
            } catch(e) {
                alert("Hata oluştu: " + e.message);
            }
        }

        async function requestProfileEmailVerify() {
            const email = document.getElementById("edit-email").value.trim();
            const marketing = document.getElementById("edit-marketing").checked;
            if(!email) return alert("Lütfen bir e-posta adresi girin.");
            
            try {
                await sendAction('send_profile_verification', { email: email, marketing: marketing });
                
                document.getElementById("settings-modal").classList.add("hidden");
                verificationUsername = currentUser.username;
                
                document.getElementById("verify-code-input").value = ""; 
                document.getElementById("email-verify-modal").classList.remove("hidden");
                alert("Doğrulama kodu e-posta adresinize gönderildi!");
            } catch(e) { }
        }

        function openProfilePicUpload() {
            _showPhotoDisclosure('profile', () => { document.getElementById('pic-upload').click(); });
        }

        async function uploadProfilePic(input) {
            if(!input.files[0]) return;
            const b64 = await resizeImage(input.files[0], 400);
            if(b64) {
                currentUser.avatar = b64;
                await sendAction('update_user', { username: currentUser.username, avatar: b64 });
                updateProfileUI();
            }
        }

        // ==============================================================
        // READY PLAYER ME 3D AVATAR
        // ==============================================================
        function openRpmModal() {
            const modal = document.getElementById('rpm-modal');
            const iframe = document.getElementById('rpm-iframe');
            const loading = document.getElementById('rpm-loading');
            modal.classList.remove('hidden');
            loading.classList.remove('hidden');
            iframe.classList.add('hidden');
            // RPM partner subdomain — freeridertr için özel subdomain yoksa genel URL
            const rpmUrl = 'https://freeridertr.readyplayer.me/avatar?frameApi&clearCache';
            iframe.src = rpmUrl;
            iframe.onload = () => {
                loading.classList.add('hidden');
                iframe.classList.remove('hidden');
            };
        }

        function closeRpmModal() {
            const modal = document.getElementById('rpm-modal');
            const iframe = document.getElementById('rpm-iframe');
            modal.classList.add('hidden');
            iframe.src = '';
        }

        // RPM iframe'den mesaj dinle — avatar URL'i gelince kaydet
        window.addEventListener('message', async (event) => {
            if(!event.data || typeof event.data !== 'string') return;
            // RPM, avatar URL'ini JSON veya düz string olarak gönderir
            let avatarUrl = null;
            try {
                const parsed = JSON.parse(event.data);
                if(parsed.source === 'readyplayerme' && parsed.eventName === 'v1.avatar.exported') {
                    avatarUrl = parsed.data?.url;
                }
            } catch(e) {
                // Bazı sürümlerde düz URL gelir
                if(typeof event.data === 'string' && event.data.includes('models.readyplayer.me')) {
                    avatarUrl = event.data;
                }
            }
            if(avatarUrl && currentUser) {
                // PNG render URL'i oluştur (fullbody portrait)
                const renderUrl = avatarUrl.replace('.glb', '.png') + '?scene=fullbody-portrait-v1-transparent&background=transparent&quality=100';
                closeRpmModal();
                // Kaydet
                currentUser.avatar = renderUrl;
                document.getElementById('profile-avatar').src = renderUrl;
                try {
                    await sendAction('update_user', { username: currentUser.username, avatar: renderUrl });
                    localStorage.setItem("fr_user", JSON.stringify(currentUser));
                    updateProfileUI();
                    haptic([50, 30, 100]);
                    // Küçük kutlama toast
                    const t = document.createElement('div');
                    t.className = 'fixed top-20 left-1/2 -translate-x-1/2 z-[99999] bg-gradient-to-r from-purple-600 to-indigo-600 text-white px-6 py-3 rounded-2xl font-bold text-sm shadow-2xl flex items-center gap-3 scale-in-anim';
                    t.innerHTML = '<span style="font-size:20px">🎭</span><div><div style="font-size:10px;opacity:0.8;text-transform:uppercase;letter-spacing:0.1em">Avatar Kaydedildi!</div><div>3D avatarın profile eklendi</div></div>';
                    document.body.appendChild(t);
                    setTimeout(() => { t.style.opacity='0'; t.style.transition='opacity 0.5s'; setTimeout(()=>t.remove(),500); }, 3000);
                } catch(e) { alert('Avatar kaydedilemedi: ' + e.message); }
            }
        });

        async function acceptChatRules() {
            await sendAction('accept_chat_rules', {});
            currentUser.accepted_chat_rules = true;
            document.getElementById("chat-rules-modal").classList.add("hidden");
            alert("Kuralları kabul ettiniz, sisteme hoş geldiniz.");
        }

        // ===============================================================
        // GELİŞMİŞ ADMİN PANELİ - TAM SİSTEM
        // ===============================================================
        let _currentAdminTab = 'overview';
        let _uaCurrentUser = null;
        let _uaCurrentTab = 'messages';
        let _uaActivityData = null;

        function showAdminPanel() {
            const isMainAdmin = (currentUser && (currentUser.role === 'Admin' || currentUser.username === 'Admin'));
            const isSubAdmin  = (currentUser && currentUser.role === 'SubAdmin');

            // Role label
            const roleTag = document.getElementById('admin-panel-role-tag');
            if(roleTag) roleTag.textContent = isMainAdmin ? '👑 Ana Yönetici' : '🛡️ Yardımcı Yönetici';

            // Ana admin only elements
            document.querySelectorAll('.admin-main-only').forEach(el => {
                el.style.display = isMainAdmin ? '' : 'none';
            });
            document.querySelectorAll('.admin-sub-only').forEach(el => {
                el.style.display = isSubAdmin ? '' : 'none';
            });

            // Ekip tab: sadece main admin
            const tabAdmins = document.getElementById('atab-admins');
            if(tabAdmins) tabAdmins.style.display = isMainAdmin ? '' : 'none';

            // Stats güncelle
            document.getElementById('astat-users').textContent = db.users.length;
            document.getElementById('astat-banned').textContent = db.banned.length;

            // Maintenance
            const maintChk = document.getElementById("admin-maintenance");
            if(maintChk) maintChk.checked = db.maintenance;

            // Google Play IAP — Bekleyen manuel onay listesi (main admin only)
            // NOT: Google Play IAP akışında satın alımlar /api/verify_google_purchase
            // üzerinden otomatik doğrulanır. Bu panel yalnızca otomatik doğrulaması
            // başarısız olan veya admin tarafından manuel onay gerektiren durumları gösterir.
            if(isMainAdmin) {
                const reqContainer = document.getElementById("admin-iap-requests");
                reqContainer.innerHTML = "";
                let hasReqs = false;
                db.users.forEach(u => {
                    // pending_premium: otomatik doğrulaması tamamlanamamış IAP'lar
                    if(u.stats && u.stats.pending_premium) {
                        hasReqs = true;
                        const tierNum = parseInt(u.stats.pending_premium);
                        const productId = u.stats.gp_product_id || '—';
                        const pName = tierNum === 3 ? "👑 Ultra+" : (tierNum === 2 ? "🌟 Deluxe" : "⭐ Standart");
                        const isAdminOverride = u.stats.gp_admin_override ? ' (Manuel)' : ' (IAP)';
                        reqContainer.innerHTML += `
                        <div class="rounded-xl p-3 border border-zinc-700/60 flex justify-between items-center admin-card-enter" style="background:rgba(0,0,0,0.5)">
                            <div>
                                <div class="font-bold text-white text-sm">${u.username}</div>
                                <div class="text-[10px] text-yellow-400 font-bold uppercase tracking-widest mt-0.5">${pName}${isAdminOverride}</div>
                                <div class="text-[9px] text-zinc-500 mt-0.5">Product: ${productId}</div>
                            </div>
                            <div class="flex gap-2">
                                <button onclick="approvePrem('${u.username}', ${tierNum})" class="bg-green-800/80 hover:bg-green-700 px-3 py-2 rounded-lg text-[10px] font-bold text-white transition">✓ Onayla</button>
                                <button onclick="rejectPrem('${u.username}')" class="bg-red-900/60 hover:bg-red-800/80 px-3 py-2 rounded-lg text-[10px] font-bold text-white transition">✕ Red</button>
                            </div>
                        </div>`;
                    }
                });
                if(!hasReqs) reqContainer.innerHTML = "<div class='text-zinc-600 text-xs italic py-1 font-medium'>✅ Bekleyen IAP onayı yok.</div>";
            }

            adminSwitchTab('overview');
            document.getElementById("admin-panel").classList.remove("hidden");

            // Load sub-admin count for stats
            loadSubAdminCount();
        }

        async function loadSubAdminCount() {
            try {
                const res = await sendAction('get_all_sub_admins', {});
                if(res && res.sub_admins) {
                    const el = document.getElementById('astat-admins');
                    if(el) { el.textContent = res.sub_admins.length; el.classList.add('count-up-anim'); }
                }
            } catch(e) {}
        }

        function adminSwitchTab(tab) {
            _currentAdminTab = tab;
            ['overview','users','reels','logs','admins'].forEach(t => {
                const btn = document.getElementById(`atab-${t}`);
                const content = document.getElementById(`admin-tab-${t}`);
                if(btn) btn.className = btn.className.replace(' active-admin-tab','').replace('active-admin-tab','') + (t === tab ? ' active-admin-tab' : '');
                if(content) content.classList.toggle('hidden', t !== tab);
            });
            if(tab === 'users') renderAdminUserList(db.users);
            if(tab === 'reels') loadAdminReels();
            if(tab === 'logs') loadAdminLogs();
            if(tab === 'admins') loadSubAdmins();
        }

        function renderAdminUserList(users) {
            const container = document.getElementById('admin-user-list');
            if(!container) return;
            container.innerHTML = '';
            (users || []).slice(0, 500).forEach((u, i) => {
                const isBanned = db.banned.includes(u.username);
                const premTier = (u.stats && u.stats.premium_tier) ? parseInt(u.stats.premium_tier) : 0;
                const roleLabel = u.role === 'Admin' ? '👑' : (u.role === 'SubAdmin' ? '🛡️' : '');
                const premBadge = premTier === 3 ? '<span class="text-yellow-400 text-[8px] font-black">ULTRA+</span>' : (premTier === 2 ? '<span class="text-purple-400 text-[8px] font-black">DLX</span>' : (premTier === 1 ? '<span class="text-blue-400 text-[8px] font-black">STD</span>' : ''));
                container.innerHTML += `
                <div class="rounded-xl p-3 border flex items-center gap-3 admin-card-enter transition-all hover:border-zinc-600 cursor-pointer" style="background:rgba(0,0,0,0.45);border-color:rgba(63,63,70,0.7);animation-delay:${i*0.03}s" onclick="openUserActivity('${u.username}')">
                    <img src="${u.avatar || 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg'}" class="w-10 h-10 rounded-full object-cover shrink-0 border-2 ${isBanned ? 'border-sky-600' : 'border-zinc-700'}">
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-1.5">
                            <span class="text-white font-bold text-sm truncate">${u.username}</span>
                            <span>${roleLabel}</span>
                            ${premBadge}
                            ${isBanned ? '<span class="ban-reason-badge">Banlı</span>' : ''}
                        </div>
                        <div class="text-zinc-500 text-[10px] font-bold truncate mt-0.5">${u.city || '—'} · ${u.xp || 0} XP</div>
                    </div>
                    <div class="shrink-0 text-zinc-600 text-xs">›</div>
                </div>`;
            });
            if(!users || users.length === 0) container.innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-4">Kullanıcı bulunamadı.</div>';
        }

        function adminSearchUsers() {
            const q = document.getElementById('admin-user-search').value.toLowerCase().trim();
            const filtered = q ? db.users.filter(u => u.username.toLowerCase().includes(q) || (u.city||'').toLowerCase().includes(q)) : db.users;
            renderAdminUserList(filtered);
        }

        async function loadAdminReels() {
            const container = document.getElementById('admin-reels-list');
            if(!container) return;
            container.innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-4 animate-pulse">Yükleniyor...</div>';
            try {
                const res = await sendAction('get_reels', {offset: 0});
                const reels = (res && res.reels) ? res.reels : [];
                container.innerHTML = '';
                if(!reels.length) { container.innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-4">Reel bulunamadı.</div>'; return; }
                reels.forEach((r, i) => {
                    const isVideo = r.media_type === 'video';
                    const dt = r.created_at ? new Date(r.created_at * 1000).toLocaleDateString('tr-TR') : '—';
                    container.innerHTML += `
                    <div class="rounded-xl p-3 border border-zinc-800/70 flex items-center gap-3 admin-card-enter" style="background:rgba(0,0,0,0.5);animation-delay:${i*0.04}s">
                        <div class="w-14 h-14 rounded-xl overflow-hidden shrink-0 border border-zinc-700 bg-zinc-900 flex items-center justify-center">
                            ${isVideo ? `<span class="text-2xl">🎥</span>` : `<img src="${r.media_url}" class="w-full h-full object-cover">`}
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="text-white font-bold text-sm truncate">${r.user}</div>
                            <div class="text-zinc-500 text-[10px] font-bold mt-0.5 truncate">${r.caption || '(Açıklama yok)'}</div>
                            <div class="flex items-center gap-2 mt-1">
                                <span class="text-zinc-600 text-[9px] font-bold">${dt}</span>
                                <span class="text-pink-500 text-[9px] font-bold">❤ ${(r.likes||[]).length}</span>
                                <span class="text-zinc-500 text-[9px] font-bold">${isVideo ? '🎥 Video' : '📸 Foto'}</span>
                            </div>
                        </div>
                        <button onclick="adminDeleteReel('${r.id}', '${r.user}', this)" class="shrink-0 w-8 h-8 rounded-lg bg-red-900/40 border border-sky-800/50 text-sky-300 hover:bg-sky-800/60 flex items-center justify-center text-sm transition hover:scale-110">🗑</button>
                    </div>`;
                });
            } catch(e) {
                container.innerHTML = '<div class="text-sky-400 text-xs italic text-center py-4">Yüklenirken hata oluştu.</div>';
            }
        }

        async function adminDeleteReel(reelId, owner, btn) {
            if(!confirm(`${owner} adlı kullanıcının reelini silmek istediğine emin misin?`)) return;
            btn.disabled = true; btn.textContent = '...';
            const res = await sendAction('delete_reel', {reel_id: reelId});
            if(res && res.status === 'ok') {
                btn.closest('.rounded-xl').style.opacity = '0.3';
                btn.textContent = '✓';
                showToast(`🗑️ Reel silindi.`);
            }
        }

        async function loadAdminLogs() {
            const container = document.getElementById('admin-logs-list');
            if(!container) return;
            container.innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-4 animate-pulse">Yükleniyor...</div>';
            try {
                const res = await sendAction('get_admin_logs', {});
                const logs = (res && res.logs) ? res.logs : [];
                container.innerHTML = '';
                if(!logs.length) { container.innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-4">Henüz kayıt yok.</div>'; return; }
                const actionColors = { ban_user: 'log-ban', delete_reel: 'log-delete', delete_message: 'log-delete', delete_marker: 'log-delete', assign_admin: 'log-assign', revoke_admin: 'log-revoke', notify_main: 'log-notify' };
                const actionEmojis = { ban_user: '🚨', delete_reel: '🎬', delete_message: '💬', delete_marker: '📍', assign_admin: '✅', revoke_admin: '❌', notify_main: '📢' };
                logs.forEach((l, i) => {
                    const colorClass = actionColors[l.action] || 'log-default';
                    const emoji = actionEmojis[l.action] || '🔧';
                    const dt = l.ts ? new Date(l.ts * 1000).toLocaleString('tr-TR') : '—';
                    container.innerHTML += `
                    <div class="rounded-xl p-3 pl-4 admin-card-enter ${colorClass}" style="background:rgba(0,0,0,0.5);animation-delay:${i*0.03}s">
                        <div class="flex items-center justify-between gap-2">
                            <div class="flex items-center gap-2 min-w-0">
                                <span class="text-sm shrink-0">${emoji}</span>
                                <div class="min-w-0">
                                    <div class="text-white text-xs font-bold"><span class="text-red-300">${l.admin}</span> → <span class="text-zinc-300">${l.target || '—'}</span></div>
                                    <div class="text-zinc-500 text-[10px] font-bold truncate mt-0.5">${l.detail || l.action}</div>
                                </div>
                            </div>
                            <div class="text-zinc-600 text-[9px] font-bold shrink-0">${dt}</div>
                        </div>
                    </div>`;
                });
            } catch(e) {
                container.innerHTML = '<div class="text-sky-400 text-xs italic text-center py-4">Yüklenirken hata oluştu.</div>';
            }
        }

        async function loadSubAdmins() {
            const container = document.getElementById('sub-admin-list');
            if(!container) return;
            container.innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-3 animate-pulse">Yükleniyor...</div>';
            try {
                const res = await sendAction('get_all_sub_admins', {});
                const admins = (res && res.sub_admins) ? res.sub_admins : [];
                const el2 = document.getElementById('astat-admins');
                if(el2) el2.textContent = admins.length;
                container.innerHTML = '';
                if(!admins.length) { container.innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-3">Henüz yardımcı admin yok.</div>'; return; }
                admins.forEach((a, i) => {
                    container.innerHTML += `
                    <div class="flex items-center gap-3 p-2.5 rounded-xl admin-card-enter" style="background:rgba(0,0,0,0.4);animation-delay:${i*0.05}s">
                        <img src="${a.avatar || 'https://cdn.freeridertr.com.tr/profil%20resmi/unnamed.jpg'}" class="w-9 h-9 rounded-full object-cover border border-amber-700/60">
                        <div class="flex-1 min-w-0">
                            <div class="text-amber-300 font-bold text-sm truncate">${a.username}</div>
                            <div class="text-zinc-600 text-[10px] font-bold">${a.xp || 0} XP</div>
                        </div>
                        <button onclick="quickRevokeAdmin('${a.username}', this)" class="shrink-0 px-3 py-1.5 rounded-lg bg-sky-900/30 border border-sky-800/50 text-sky-300 hover:bg-sky-800/50 text-[10px] font-bold transition">Yetkiyi Al</button>
                    </div>`;
                });
            } catch(e) {
                container.innerHTML = '<div class="text-sky-400 text-xs italic text-center py-3">Yüklenirken hata oluştu.</div>';
            }
        }

        async function assignSubAdmin() {
            const uname = document.getElementById('assign-admin-username').value.trim();
            if(!uname) { showToast('Kullanıcı adı gir!'); return; }
            if(!confirm(`${uname} adlı kullanıcıya yardımcı admin yetkisi verilecek. Emin misin?`)) return;
            const res = await sendAction('assign_sub_admin', {username: uname});
            if(res && res.status === 'ok') {
                showToast(`✅ ${uname} artık yardımcı admin!`);
                document.getElementById('assign-admin-username').value = '';
                loadSubAdmins();
            } else {
                alert(res?.message || 'Hata oluştu.');
            }
        }

        async function revokeSubAdmin() {
            const uname = document.getElementById('revoke-admin-username').value.trim();
            if(!uname) { showToast('Kullanıcı adı gir!'); return; }
            if(!confirm(`${uname} adlı kullanıcının admin yetkisi alınacak. Emin misin?`)) return;
            const res = await sendAction('revoke_sub_admin', {username: uname});
            if(res && res.status === 'ok') {
                showToast(`❌ ${uname} yetkisi alındı.`);
                document.getElementById('revoke-admin-username').value = '';
                loadSubAdmins();
            } else {
                alert(res?.message || 'Hata oluştu.');
            }
        }

        async function quickRevokeAdmin(uname, btn) {
            if(!confirm(`${uname} yöneticilikten çıkarılsın mı?`)) return;
            btn.disabled = true; btn.textContent = '...';
            const res = await sendAction('revoke_sub_admin', {username: uname});
            if(res && res.status === 'ok') {
                btn.closest('.rounded-xl').style.opacity = '0.3';
                showToast(`❌ ${uname} yetkisi alındı.`);
                loadSubAdmins();
            }
        }

        async function adminNotifyMain() {
            const msg = document.getElementById('admin-notify-msg').value.trim();
            if(!msg) { showToast('Mesaj boş olamaz!'); return; }
            const res = await sendAction('admin_notify_main', {message: msg});
            if(res && res.status === 'ok') {
                document.getElementById('admin-notify-msg').value = '';
                showToast('📨 Ana admine bildirim gönderildi!');
            }
        }

        // ---- Kullanıcı Aktivite Modalı ----
        async function openUserActivity(username) {
            _uaCurrentUser = username;
            _uaActivityData = null;
            document.getElementById('ua-username-label').textContent = '@' + username;
            document.getElementById('ua-content').innerHTML = '<div class="text-zinc-600 text-xs italic text-center py-6 animate-pulse">Yükleniyor...</div>';
            document.getElementById('user-activity-modal').classList.remove('hidden');
            uaTab('messages');

            try {
                const res = await sendAction('get_user_activity', {username});
                if(res && res.activity) {
                    _uaActivityData = res.activity;
                    uaRender(_uaCurrentTab);
                }
            } catch(e) {
                document.getElementById('ua-content').innerHTML = '<div class="text-sky-300 text-xs italic text-center py-6">Yüklenirken hata oluştu.</div>';
            }
        }

        function uaTab(tab) {
            _uaCurrentTab = tab;
            ['messages','dms','reels','markers'].forEach(t => {
                const btn = document.getElementById(`uatab-${t}`);
                if(btn) {
                    btn.className = btn.className.replace(' ua-active-tab','').replace('ua-active-tab','');
                    if(t === tab) btn.className += ' ua-active-tab';
                }
            });
            if(_uaActivityData) uaRender(tab);
        }

        function uaRender(tab) {
            const container = document.getElementById('ua-content');
            if(!container || !_uaActivityData) return;
            const data_ua = _uaActivityData[tab] || [];
            container.innerHTML = '';
            if(!data_ua.length) {
                container.innerHTML = `<div class="text-zinc-600 text-xs italic text-center py-6">Bu kategoride içerik yok.</div>`;
                return;
            }
            if(tab === 'messages') {
                data_ua.forEach((m, i) => {
                    const txt = m.text ? String(m.text).substring(0,120) : (m.type || '?');
                    container.innerHTML += `
                    <div class="rounded-xl p-3 border border-zinc-800/70 flex items-start gap-2 admin-card-enter" style="background:rgba(0,0,0,0.45);animation-delay:${i*0.03}s">
                        <div class="flex-1 min-w-0">
                            <div class="text-zinc-300 text-xs font-medium">${txt}</div>
                            ${m.image ? `<div class="text-[9px] text-zinc-600 mt-1">📸 Görsel içerik</div>` : ''}
                        </div>
                        <button onclick="adminDelMsg('${m.id}', this)" class="shrink-0 w-7 h-7 bg-sky-900/30 border border-red-800/40 rounded-lg text-sky-300 hover:bg-sky-800/50 flex items-center justify-center text-[10px] transition">🗑</button>
                    </div>`;
                });
            } else if(tab === 'dms') {
                data_ua.forEach((m, i) => {
                    const others = (m.participants || []).filter(p => p !== _uaCurrentUser);
                    const txt = m.text ? String(m.text).substring(0,100) : (m.type || '?');
                    container.innerHTML += `
                    <div class="rounded-xl p-3 border border-zinc-800/70 admin-card-enter" style="background:rgba(0,0,0,0.45);animation-delay:${i*0.03}s">
                        <div class="text-[10px] text-zinc-500 font-bold mb-1">↔ ${others.join(', ') || '?'}</div>
                        <div class="text-zinc-300 text-xs font-medium">${txt}</div>
                    </div>`;
                });
            } else if(tab === 'reels') {
                data_ua.forEach((r, i) => {
                    const isVideo = r.media_type === 'video';
                    container.innerHTML += `
                    <div class="rounded-xl p-3 border border-zinc-800/70 flex items-center gap-3 admin-card-enter" style="background:rgba(0,0,0,0.45);animation-delay:${i*0.04}s">
                        <div class="w-12 h-12 rounded-lg overflow-hidden shrink-0 bg-zinc-900 border border-zinc-800 flex items-center justify-center">
                            ${isVideo ? `<span class="text-xl">🎥</span>` : `<img src="${r.media_url}" class="w-full h-full object-cover" onerror="this.parentElement.innerHTML='📸'">`}
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="text-zinc-300 text-xs font-medium truncate">${r.caption || '(Açıklama yok)'}</div>
                            <div class="text-pink-400 text-[9px] font-bold mt-0.5">❤ ${(r.likes||[]).length}</div>
                        </div>
                        <button onclick="adminDeleteReel('${r.id}','${r.user}',this)" class="shrink-0 w-7 h-7 bg-sky-900/30 border border-red-800/40 rounded-lg text-sky-300 hover:bg-sky-800/50 flex items-center justify-center text-[10px] transition">🗑</button>
                    </div>`;
                });
            } else if(tab === 'markers') {
                data_ua.forEach((m, i) => {
                    container.innerHTML += `
                    <div class="rounded-xl p-3 border border-zinc-800/70 flex items-center gap-3 admin-card-enter" style="background:rgba(0,0,0,0.45);animation-delay:${i*0.04}s">
                        <div class="w-10 h-10 rounded-lg bg-sky-900/30 border border-red-800/40 flex items-center justify-center text-xl shrink-0">${m.icon_type || '🚴'}</div>
                        <div class="flex-1 min-w-0">
                            <div class="text-white text-sm font-bold truncate">${m.name || '—'}</div>
                            <div class="text-zinc-500 text-[10px] font-bold">${m.difficulty || '—'}</div>
                        </div>
                        <button onclick="adminDelMarker('${m.id}','${m.name}',this)" class="shrink-0 w-7 h-7 bg-sky-900/30 border border-red-800/40 rounded-lg text-sky-300 hover:bg-sky-800/50 flex items-center justify-center text-[10px] transition">🗑</button>
                    </div>`;
                });
            }
        }

        async function adminDelMsg(msgId, btn) {
            if(!confirm('Bu mesajı silmek istediğine emin misin?')) return;
            btn.disabled = true; btn.textContent = '...';
            const res = await sendAction('admin_delete_message_by_id', {msg_id: msgId});
            if(res && res.status === 'ok') {
                btn.closest('.rounded-xl').style.opacity = '0.2';
                showToast('💬 Mesaj silindi.');
            }
        }

        async function adminDelMarker(markerId, markerName, btn) {
            if(!confirm(`"${markerName}" yerini silmek istediğine emin misin?`)) return;
            btn.disabled = true; btn.textContent = '...';
            const res = await sendAction('admin_delete_marker_by_id', {marker_id: markerId});
            if(res && res.status === 'ok') {
                btn.closest('.rounded-xl').style.opacity = '0.2';
                showToast('📍 Yer silindi.');
            }
        }

        async function adminBanFromActivity() {
            if(!_uaCurrentUser) return;
            const reason = prompt(`${_uaCurrentUser} adlı kullanıcıyı banlamak için sebep gir:`);
            if(!reason) return;
            const res = await sendAction('admin_ban_user', {username: _uaCurrentUser, reason});
            if(res && res.status === 'ok') {
                db.banned.push(_uaCurrentUser);
                document.getElementById('user-activity-modal').classList.add('hidden');
                showToast(`🚨 ${_uaCurrentUser} banlandı.`);
                document.getElementById('astat-banned').textContent = db.banned.length;
            }
        }

        async function approvePrem(u, tier) { await sendAction('admin_approve_premium', {username: u, tier: tier}); showToast('✅ Abonelik onaylandı!'); showAdminPanel(); }
        async function rejectPrem(u) { await sendAction('admin_reject_premium', {username: u}); showToast('❌ Abonelik reddedildi.'); showAdminPanel(); }
        async function toggleMaintenance() { const chk = document.getElementById("admin-maintenance").checked; await sendAction('toggle_maintenance', {status: chk}); showToast(chk ? '🔧 Bakım modu açıldı' : '✅ Bakım modu kapatıldı'); }
        async function delMsg(id) { if(confirm("Mesajı sil?")) { await sendAction('delete_message', {id: id}); db.messages = db.messages.filter(m=>m.id!==id); renderChat(true); } }
        async function pinMsg(id) {
            const m = db.messages.find(x => x.id === id);
            if(m && m.type === "text") {
                await sendAction('pin_message', { text: m.text, user: m.user, expires: Date.now() + (24*60*60*1000) });
                showToast('📌 Mesaj 24 saat sabitlendi!');
            }
        }

        // ==== 3D ÇARK MOTORU ====
        let _wheelAngle = 0;
        let _wheelSpinning = false;
        let _winnerIndex = -1;

        function initWheel3D() {
            const canvas = document.getElementById('wheel-canvas-3d');
            if(!canvas) return;
            _winnerIndex = -1;
            _drawWheel3D(canvas, _wheelAngle);
        }

        function _drawWheel3D(canvas, angle) {
            const ctx = canvas.getContext('2d');
            const W = canvas.width, H = canvas.height;
            const cx = W/2, cy = H/2;
            const R = W/2 - 6;
            const prizes = window.WHEEL_PRIZES || [];
            const n = prizes.length;
            if(n === 0) return;
            const slice = (Math.PI * 2) / n;
            ctx.clearRect(0, 0, W, H);

            // Dış parlak halka
            const glowGrd = ctx.createRadialGradient(cx,cy,R-4,cx,cy,R+8);
            glowGrd.addColorStop(0,'rgba(234,179,8,0.0)');
            glowGrd.addColorStop(1,'rgba(234,179,8,0.35)');
            ctx.beginPath(); ctx.arc(cx,cy,R+6,0,Math.PI*2);
            ctx.fillStyle=glowGrd; ctx.fill();

            // Dilimleri çiz
            prizes.forEach((p, i) => {
                // İbre saat 12'de (üstte) → -Math.PI/2 offset
                const startA = angle + i * slice - Math.PI/2;
                const endA = startA + slice;
                const mid = startA + slice/2;

                const isWinner = (_winnerIndex === i);
                const baseColor = p.color || '#0ea5e9';

                // Dilim
                ctx.beginPath();
                ctx.moveTo(cx, cy);
                ctx.arc(cx, cy, R, startA, endA);
                ctx.closePath();
                if(isWinner) {
                    const winGrd = ctx.createRadialGradient(
                        cx + Math.cos(mid)*R*0.5, cy + Math.sin(mid)*R*0.5, 0,
                        cx + Math.cos(mid)*R*0.5, cy + Math.sin(mid)*R*0.5, R*0.7
                    );
                    winGrd.addColorStop(0,'#fffde7');
                    winGrd.addColorStop(0.5,'#fbbf24');
                    winGrd.addColorStop(1,'#b45309');
                    ctx.fillStyle = winGrd;
                } else {
                    ctx.fillStyle = baseColor;
                }
                ctx.fill();
                // Kenarlık
                ctx.strokeStyle = isWinner ? '#fbbf24' : 'rgba(0,0,0,0.35)';
                ctx.lineWidth = isWinner ? 4 : 1.5;
                ctx.stroke();

                // Parlaklık efekti
                const shineGrd = ctx.createRadialGradient(
                    cx + Math.cos(mid)*R*0.4, cy + Math.sin(mid)*R*0.4, 0,
                    cx + Math.cos(mid)*R*0.4, cy + Math.sin(mid)*R*0.4, R*0.6
                );
                shineGrd.addColorStop(0,'rgba(255,255,255,0.20)');
                shineGrd.addColorStop(1,'rgba(0,0,0,0.0)');
                ctx.beginPath();
                ctx.moveTo(cx,cy);
                ctx.arc(cx,cy,R,startA,endA);
                ctx.closePath();
                ctx.fillStyle = shineGrd;
                ctx.fill();

                // Metin
                ctx.save();
                ctx.translate(cx + Math.cos(mid)*(R*0.64), cy + Math.sin(mid)*(R*0.64));
                ctx.rotate(mid + Math.PI/2);
                ctx.fillStyle = isWinner ? '#1c0a00' : '#ffffff';
                ctx.textAlign = 'center';
                ctx.shadowColor = isWinner ? 'rgba(255,220,100,0.6)' : 'rgba(0,0,0,0.9)';
                ctx.shadowBlur = 4;
                const nameParts = (p.name || '').split(' ');
                if(nameParts.length >= 2) {
                    ctx.font = `bold ${isWinner ? '10' : '9'}px sans-serif`;
                    ctx.fillText(nameParts[0], 0, -5);
                    ctx.fillText(nameParts.slice(1).join(' '), 0, 6);
                } else {
                    ctx.font = `bold ${isWinner ? '11' : '10'}px sans-serif`;
                    ctx.fillText(p.name || '', 0, 2);
                }
                ctx.restore();
            });

            // Merkez daire
            const cGrd = ctx.createRadialGradient(cx-4,cy-4,0,cx,cy,26);
            cGrd.addColorStop(0,'#71717a');
            cGrd.addColorStop(1,'#18181b');
            ctx.beginPath(); ctx.arc(cx,cy,26,0,Math.PI*2);
            ctx.fillStyle=cGrd; ctx.fill();
            ctx.strokeStyle='rgba(255,255,255,0.15)'; ctx.lineWidth=2.5; ctx.stroke();

            // Dönüş hızı görsel — çark dönerken radyal çizgiler
            if(_wheelSpinning) {
                ctx.save();
                const lineCount = 18;
                for(let li = 0; li < lineCount; li++) {
                    const a = angle + li * (Math.PI*2/lineCount);
                    const opacity = (li % 2 === 0) ? 0.10 : 0.05;
                    ctx.strokeStyle = `rgba(255,255,255,${opacity})`;
                    ctx.lineWidth = 2;
                    ctx.beginPath();
                    ctx.moveTo(cx + Math.cos(a)*28, cy + Math.sin(a)*28);
                    ctx.lineTo(cx + Math.cos(a)*R, cy + Math.sin(a)*R);
                    ctx.stroke();
                }
                ctx.restore();
            }

            // Kazanan dilim etrafında parlayan halka
            if(!_wheelSpinning && _winnerIndex >= 0) {
                ctx.save();
                const wStartA = angle + _winnerIndex * slice - Math.PI/2;
                const wEndA = wStartA + slice;
                ctx.beginPath();
                ctx.moveTo(cx, cy);
                ctx.arc(cx, cy, R + 5, wStartA, wEndA);
                ctx.closePath();
                ctx.strokeStyle = 'rgba(251,191,36,0.85)';
                ctx.lineWidth = 5;
                ctx.shadowColor = '#fbbf24';
                ctx.shadowBlur = 18;
                ctx.stroke();
                ctx.restore();
            }
        }

        // Init wheel when spin modal opens


        function updateSpinInfo() {
            const el = document.getElementById('spin-inline-info');
            if(!el || !currentUser) return;
            const stats = currentUser.stats || {};
            const prem = parseInt(stats.premium_tier) || 0;
            const maxSpins = prem >= 2 ? 2 : 1;
            const today = new Date().toISOString().slice(0,10);
            const count = stats.last_spin_date === today ? (stats.spin_count || 0) : 0;
            const left = Math.max(0, maxSpins - count);
            el.textContent = left > 0 ? `${left} hak kaldı` : 'Bugün bitti';
            el.className = left > 0
                ? 'text-[10px] text-green-400 font-bold uppercase tracking-widest text-right'
                : 'text-[10px] text-sky-300 font-bold uppercase tracking-widest text-right';
        }

        async function spinWheelAction() {
            const btn = document.getElementById('spin-btn');
            if(btn.disabled || _wheelSpinning) return;
            btn.disabled = true;
            _wheelSpinning = true;
            btn.innerText = "DÖNÜYOR...";
            haptic([20,10,20,10,20]);

            try {
                const res = await sendAction('daily_spin', {});
                if(res.status !== 'ok') {
                    alert(res.message);
                    btn.disabled = false;
                    _wheelSpinning = false;
                    btn.innerText = "ÇARKI ÇEVİR";
                    return;
                }

                const prizes = window.WHEEL_PRIZES || [];
                const prizeIndex = prizes.findIndex(p => p.id === res.prize_id);
                const n = prizes.length;
                if(prizeIndex < 0 || n === 0) { alert("Hata: ödül bulunamadı."); return; }

                const sliceAngle = (Math.PI * 2) / n;

                // İbre üstte (saat 12 = -Math.PI/2).
                // Kazanan dilim index=prizeIndex, merkezinin açısı: prizeIndex*sliceAngle + sliceAngle/2
                // Bunu üste getirmek için: _wheelAngle = -(prizeIndex*sliceAngle + sliceAngle/2)
                // Ama mevcut _wheelAngle'dan devam etmeli + en az 8 tam tur dönsün
                const currentNorm = ((_wheelAngle % (Math.PI*2)) + Math.PI*2) % (Math.PI*2);
                const targetSliceCenter = prizeIndex * sliceAngle + sliceAngle / 2;
                // Hedef: çarkın açısı = -targetSliceCenter (yani o dilim tam üste gelsin)
                const targetNorm = ((-targetSliceCenter) % (Math.PI*2) + Math.PI*2) % (Math.PI*2);
                let delta = targetNorm - currentNorm;
                if(delta < 0) delta += Math.PI*2;
                // En az 8 tam tur + biraz daha
                const extraSpins = Math.PI * 2 * (8 + Math.floor(Math.random()*4));
                const finalAngle = _wheelAngle + extraSpins + delta;

                // Tick sound
                const tickSound = document.getElementById('spin-tick-sound');

                const canvas = document.getElementById('wheel-canvas-3d');
                const start = performance.now();
                const duration = 6500;
                const startAngle = _wheelAngle;
                const totalAngle = finalAngle - startAngle;
                let lastTickSlice = -1;

                // Çarkı dönerken parlat
                if(canvas) canvas.classList.add('wheel-spinning-canvas');

                function easeInOut(t) {
                    return t < 0.5
                        ? 4 * t * t * t
                        : 1 - Math.pow(-2 * t + 2, 3) / 2;
                }

                function animate(now) {
                    const elapsed = now - start;
                    const t = Math.min(elapsed / duration, 1);
                    const eased = easeInOut(t);
                    _wheelAngle = startAngle + totalAngle * eased;

                    // 3D tilt — sadece orta hızda belirgin, başta ve sonda sıfır
                    const tiltEnvelope = Math.sin(t * Math.PI); // 0→1→0
                    const tiltX = Math.sin(elapsed * 0.004) * tiltEnvelope * 12;
                    if(canvas) {
                        canvas.style.transform = `rotateX(${tiltX}deg)`;
                        _drawWheel3D(canvas, _wheelAngle);
                    }

                    // Slice sınırına göre tick sesi (gerçekçi tık-tık)
                    const tickSound = document.getElementById('spin-tick-sound');
                    const currentSlice = Math.floor(((_wheelAngle % (Math.PI*2) + Math.PI*2) % (Math.PI*2)) / sliceAngle);
                    if(currentSlice !== lastTickSlice && t > 0.05 && t < 0.97) {
                        lastTickSlice = currentSlice;
                        if(tickSound) {
                            tickSound.currentTime = 0;
                            try { tickSound.play().catch(()=>{}); } catch(e){}
                        }
                    }

                    if(t < 1) {
                        requestAnimationFrame(animate);
                    } else {
                        if(canvas) {
                            canvas.classList.remove('wheel-spinning-canvas');
                            canvas.style.transform = '';
                        }
                        // Kazanan dilimi vurgula + kısa pulse animasyonu
                        _winnerIndex = prizeIndex;
                        _drawWheel3D(canvas, _wheelAngle);

                        // Kazanan için 3 kez kısa parlama
                        let pulseCount = 0;
                        const pulseInterval = setInterval(() => {
                            pulseCount++;
                            if(canvas) {
                                canvas.style.boxShadow = pulseCount % 2 === 1
                                    ? '0 0 60px rgba(251,191,36,1), 0 0 120px rgba(251,191,36,0.6)'
                                    : '0 0 35px rgba(14,165,233,0.5), 0 0 60px rgba(234,179,8,0.2)';
                            }
                            if(pulseCount >= 6) {
                                clearInterval(pulseInterval);
                                if(canvas) canvas.style.boxShadow = '';
                            }
                        }, 180);
                        _wheelSpinning = false;
                        btn.disabled = false;
                        btn.innerText = "ÇARKI ÇEVİR";

                        // Win sound + confetti
                        const winSound = document.getElementById('spin-win-sound');
                        if(winSound) { winSound.currentTime=0; try{winSound.play().catch(()=>{});}catch(e){} }
                        haptic([100,50,100,50,200]);
                        showSpinConfetti();

                        setTimeout(async () => {
                            // Güzel sonuç banner'ı göster
                            showSpinResult(res.prize_name);
                            // loadData yerine sadece spin sayacını ve XP'yi local güncelle
                            if(currentUser && currentUser.stats) {
                                const today = new Date().toISOString().slice(0,10);
                                currentUser.stats.last_spin_date = today;
                                currentUser.stats.spin_count = (currentUser.stats.spin_count || 0) + 1;
                                localStorage.setItem("fr_user", JSON.stringify(currentUser));
                                updateProfileUI();
                                renderMissions();
                                updateSpinInfo();
                            }
                        }, 400);
                    }
                }
                requestAnimationFrame(animate);

            } catch(e) {
                btn.disabled = false;
                _wheelSpinning = false;
                btn.innerText = "ÇARKI ÇEVİR";
            }
        }

        function showSpinResult(prizeName) {
            // Varsa eski result div'i temizle
            const old = document.getElementById('spin-result-banner');
            if(old) old.remove();

            const banner = document.createElement('div');
            banner.id = 'spin-result-banner';
            banner.style.cssText = 'position:fixed;inset:0;z-index:999999;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(0,0,0,0.65);backdrop-filter:blur(4px);';
            banner.innerHTML = `
            <div style="background:linear-gradient(135deg,#1c1c1e,#2a1500);border:2px solid #eab308;border-radius:28px;padding:36px 28px;max-width:340px;width:100%;text-align:center;box-shadow:0 0 60px rgba(234,179,8,0.5),0 0 120px rgba(234,179,8,0.2);animation:scaleIn 0.4s cubic-bezier(0.16,1,0.3,1) both;">
                <div style="font-size:56px;margin-bottom:12px;display:inline-block;animation:bounce 0.55s ease-in-out infinite alternate;">🎉</div>
                <div style="color:#fbbf24;font-size:11px;font-weight:900;text-transform:uppercase;letter-spacing:0.2em;margin-bottom:6px;">Tebrikler!</div>
                <div style="color:#ffffff;font-size:32px;font-weight:900;letter-spacing:0.05em;text-shadow:0 0 20px rgba(234,179,8,0.8);">${prizeName}</div>
                <div style="color:#a1a1aa;font-size:11px;margin-top:8px;font-weight:600;">Hesabına eklendi!</div>
                <button onclick="document.getElementById('spin-result-banner').remove()" style="margin-top:24px;background:linear-gradient(135deg,#eab308,#b45309);color:#000;border:none;border-radius:14px;padding:14px 32px;font-size:15px;font-weight:900;cursor:pointer;text-transform:uppercase;letter-spacing:0.1em;width:100%;">HARIKA! ✓</button>
            </div>`;
            document.body.appendChild(banner);
            banner.addEventListener('click', (e) => { if(e.target === banner) banner.remove(); });
        }

        function showSpinConfetti() {
            const colors = ['#ff4444','#ffbb00','#44ff88','#4488ff','#ff44ff','#ffffff','#ff8800','#00ffcc'];
            const count = 70;
            for(let i = 0; i < count; i++) {
                const el = document.createElement('div');
                const color = colors[i % colors.length];
                const isRect = i % 3 !== 0;
                const size = 6 + Math.random() * 8;
                const delay = Math.random() * 0.6;
                const duration = 1.8 + Math.random() * 1.0;
                const startX = Math.random() * 100;
                if(isRect) {
                    el.style.cssText = `position:fixed;width:${size}px;height:${size * 0.45}px;border-radius:1px;background:${color};left:${startX}vw;top:-2vh;pointer-events:none;z-index:999999;animation:confettiRect ${duration}s ease-in ${delay}s forwards;`;
                } else {
                    el.style.cssText = `position:fixed;width:${size}px;height:${size}px;border-radius:50%;background:${color};left:${startX}vw;top:-2vh;pointer-events:none;z-index:999999;animation:confettiFall ${duration}s ease-in ${delay}s forwards;`;
                }
                document.body.appendChild(el);
                setTimeout(()=>el.remove(), (duration + delay + 0.2) * 1000);
            }
        }

        // Cark acilinca init et - window.onload sonrasi guvenli


        // ==============================================================
        // ŞİFRE SIFIRLAMA (FORGOT PASSWORD)
        // ==============================================================

        function openForgotPasswordModal() {
            const modal = document.getElementById("forgot-password-modal");
            if (modal) {
                document.getElementById("fp-step-1").classList.remove("hidden");
                document.getElementById("fp-step-2").classList.add("hidden");
                document.getElementById("fp-email").value = "";
                modal.classList.remove("hidden");
            }
        }

        function closeForgotPasswordModal() {
            const modal = document.getElementById("forgot-password-modal");
            if (modal) modal.classList.add("hidden");
        }

        async function requestPasswordReset() {
            const email = document.getElementById("fp-email").value.trim();
            if(!email) return alert("Lütfen kayıtlı e-posta adresinizi girin!");
            try {
                const res = await sendAction('request_reset', { email: email });
                if(res.status === 'ok') {
                    alert("Sıfırlama kodu e-postanıza gönderildi!");
                    document.getElementById("fp-step-1").classList.add("hidden");
                    document.getElementById("fp-step-2").classList.remove("hidden");
                }
            } catch(e) {}
        }

        async function submitNewPassword() {
            const email = document.getElementById("fp-email").value.trim();
            const code = document.getElementById("fp-code").value.trim();
            const newPw = document.getElementById("fp-new-password").value.trim();
            
            if(!code || !newPw) return alert("Kod ve yeni şifre boş bırakılamaz!");
            if(newPw.length < 4) return alert("Şifre en az 4 karakter olmalıdır.");
            
            try {
                await sendAction('reset_password_code', { email: email, code: code, new_password: newPw });
                
                // Kayıtlı kullanıcı varsa yeni şifreyi encode ederek güncelle
                if (localStorage.getItem("fr_remembered_username")) {
                    localStorage.setItem("fr_remembered_password", btoa(unescape(encodeURIComponent(newPw))));
                }
                const loginPassInput = document.getElementById("login-password");
                if(loginPassInput) loginPassInput.value = newPw;

                alert("Şifreniz başarıyla güncellendi! Artık yeni şifrenizle giriş yapabilirsiniz.");
                document.getElementById("forgot-password-modal").classList.add("hidden");
            } catch(e) { }
        }

    </script>

    <!-- ============================================================ -->
    <!-- STORY MODALLARI -->
    <!-- ============================================================ -->
    <div id="story-view-modal" class="hidden fixed inset-0 bg-black z-[99998] flex flex-col">
        <div class="absolute top-4 left-4 right-4 flex gap-1 z-10" id="story-progress-bars"></div>
        <button onclick="closeStoryView()" class="absolute top-10 right-4 z-20 w-10 h-10 bg-black/60 rounded-full text-white text-xl flex items-center justify-center">✕</button>
        <div id="story-view-user" class="absolute top-12 left-4 flex items-center gap-3 z-20">
            <img id="story-view-avatar" class="w-10 h-10 rounded-full border-2 border-sky-400 object-cover" src="">
            <div>
                <div id="story-view-username" class="text-white font-bold text-sm"></div>
                <div id="story-view-time" class="text-zinc-400 text-[10px]"></div>
            </div>
        </div>
        <img id="story-view-img" class="w-full h-full object-contain" src="" style="display:none;">
        <div id="story-view-text" class="flex-1 flex items-center justify-center p-8 text-center">
            <div id="story-view-text-content" class="text-white text-xl font-bold leading-relaxed"></div>
        </div>
        <div id="story-view-viewers" class="absolute bottom-6 left-0 right-0 flex flex-col items-center gap-2">
            <div class="bg-black/60 backdrop-blur px-4 py-2 rounded-full text-zinc-400 text-xs font-bold" id="story-viewer-count"></div>
            <button id="story-delete-btn" onclick="deleteCurrentStory()" class="hidden bg-sky-700/80 backdrop-blur px-5 py-2 rounded-full text-white text-xs font-bold border border-sky-400/50">🗑️ Story'yi Sil</button>
        </div>
    </div>

    <div id="add-story-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-zinc-700 shadow-2xl scale-in-anim">
            <div class="flex items-center justify-between mb-5">
                <h3 class="text-3xl text-white teko-font tracking-wide">📸 Story Paylaş</h3>
                <button onclick="document.getElementById('add-story-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">✕</button>
            </div>
            <p class="text-[10px] text-yellow-500 font-bold uppercase tracking-widest mb-4 flex items-center gap-1"><span class="animate-pulse">⭐</span> Standart, Deluxe ve Ultra+ üyelere özel · 24 saat sonra silinir</p>
            <textarea id="story-text-input" placeholder="Ne düşünüyorsun? Nerede sürdün?" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 h-24 text-white text-sm outline-none focus:border-sky-400 transition custom-scrollbar mb-3" maxlength="200"></textarea>
            <input id="story-photo-input" type="file" accept="image/*" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-3 py-3 text-xs text-zinc-300 cursor-pointer mb-4">
            <div class="grid grid-cols-2 gap-3">
                <button onclick="document.getElementById('add-story-modal').classList.add('hidden')" class="bg-zinc-900 border border-zinc-700 text-zinc-400 py-3 rounded-xl font-bold text-sm transition hover:bg-zinc-800">İptal</button>
                <button onclick="submitStory()" class="bg-gradient-to-r from-sky-700 to-sky-500 text-white py-3 rounded-xl font-bold text-sm btn-premium-hover shadow-[0_0_15px_rgba(14,165,233,0.4)]">PAYLAŞ</button>
            </div>
        </div>
    </div>

    <!-- YORUM MODALI -->
    <div id="comment-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4">
        <div class="glass-panel w-full max-w-md rounded-3xl border border-zinc-700 shadow-2xl scale-in-anim max-h-[80vh] flex flex-col">
            <div class="p-5 border-b border-zinc-800 flex items-center justify-between shrink-0">
                <h3 class="text-2xl text-white teko-font tracking-wide" id="comment-modal-title">💬 Yorumlar</h3>
                <button onclick="document.getElementById('comment-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">✕</button>
            </div>
            <div id="comment-list" class="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar"></div>
            <div class="p-3 border-t border-zinc-800 shrink-0 flex gap-2">
                <input id="comment-input" type="text" placeholder="Yorumunu yaz..." maxlength="200" class="flex-1 bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-sky-400 transition">
                <button onclick="submitComment()" class="bg-white hover:bg-gray-200 text-black px-4 py-3 rounded-xl font-bold text-sm btn-premium-hover">Gönder</button>
            </div>
        </div>
    </div>

    <!-- SEVİYE ATLAMA KUTLAMA OVERLAYİ -->
    <div id="levelup-overlay" class="hidden fixed inset-0 pointer-events-none z-[99997] flex items-center justify-center">
        <div id="levelup-card" class="bg-gradient-to-br from-yellow-600/90 to-amber-500/90 backdrop-blur-md rounded-3xl p-8 text-center border border-yellow-400/50 shadow-[0_0_60px_rgba(234,179,8,0.8)] level-up-anim max-w-xs w-full mx-4">
            <div class="text-6xl mb-3" id="levelup-icon">🏆</div>
            <div class="text-white text-[10px] font-black uppercase tracking-[0.2em] mb-1">SEVİYE ATLAMA!</div>
            <div class="text-black font-black text-3xl teko-font tracking-wide" id="levelup-name">Şampiyon</div>
            <div class="text-black/70 text-xs mt-2 font-bold" id="levelup-desc">Tebrikler! Yeni ünvanına ulaştın.</div>
        </div>
    </div>

    <!-- ÖNCELİKLİ DESTEK MODALI -->
    <div id="support-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-zinc-700 shadow-2xl scale-in-anim">
            <div class="flex items-center justify-between mb-5">
                <h3 class="text-2xl text-white teko-font tracking-wide">🎧 Destek</h3>
                <button onclick="document.getElementById('support-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">✕</button>
            </div>
            <div id="support-priority-badge" class="mb-4 text-center py-2 rounded-xl text-xs font-black uppercase tracking-widest"></div>
            <textarea id="support-message" placeholder="Sorununu veya önerini yaz..." class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 h-28 text-white text-sm outline-none focus:border-sky-400 transition custom-scrollbar mb-4"></textarea>
            <div class="grid grid-cols-2 gap-3">
                <button onclick="document.getElementById('support-modal').classList.add('hidden')" class="bg-zinc-900 border border-zinc-700 text-zinc-400 py-3 rounded-xl font-bold text-sm">İptal</button>
                <button onclick="submitSupport()" class="bg-gradient-to-r from-sky-700 to-sky-500 text-white py-3 rounded-xl font-bold text-sm btn-premium-hover">GÖNDER</button>
            </div>
        </div>
    </div>

    <!-- TEHLİKE BİLDİR MODALI -->
    <div id="danger-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[9999] px-4">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-sky-900/50 shadow-2xl scale-in-anim">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-2xl text-sky-300 teko-font tracking-wide">⚠️ Tehlike Bildir</h3>
                <button onclick="document.getElementById('danger-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">✕</button>
            </div>
            <p class="text-xs text-zinc-400 mb-4">Bu rampada bir tehlike mi var? Kapalı mı, hasar mı var? Bildirin, topluluk uyarılsın.</p>
            <div class="grid grid-cols-2 gap-2 mb-4">
                <button onclick="setDangerReason('Rampa kapalı')" class="bg-zinc-900 border border-zinc-700 hover:border-sky-500 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">🚫 Kapalı</button>
                <button onclick="setDangerReason('Hasar var / tehlikeli')" class="bg-zinc-900 border border-zinc-700 hover:border-sky-500 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">💥 Hasarlı</button>
                <button onclick="setDangerReason('Yüzey ıslak / kaygan')" class="bg-zinc-900 border border-zinc-700 hover:border-sky-500 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">💧 Kaygan</button>
                <button onclick="setDangerReason('Engel var / yol kapalı')" class="bg-zinc-900 border border-zinc-700 hover:border-sky-500 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">🚧 Engel</button>
            </div>
            <textarea id="danger-reason-input" placeholder="Detay ekle (isteğe bağlı)..." class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 h-20 text-white text-sm outline-none focus:border-sky-400 transition custom-scrollbar mb-4"></textarea>
            <div class="grid grid-cols-2 gap-3">
                <button onclick="document.getElementById('danger-modal').classList.add('hidden')" class="bg-zinc-900 border border-zinc-700 text-zinc-400 py-3 rounded-xl font-bold text-sm">İptal</button>
                <button onclick="submitDangerReport()" class="bg-sky-800 hover:bg-sky-700 text-white py-3 rounded-xl font-bold text-sm btn-premium-hover">BİLDİR</button>
            </div>
        </div>
    </div>

    <!-- KULLANICI ŞİKAYET MODALI -->
    <div id="report-user-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[99999] px-4">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-orange-900/50 shadow-2xl scale-in-anim">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-2xl text-orange-400 teko-font tracking-wide">&#128680; Kullanıcı Sikayet Et</h3>
                <button onclick="document.getElementById('report-user-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">&#10005;</button>
            </div>
            <p class="text-xs text-zinc-400 mb-4"><b id="report-user-target-label" class="text-orange-400"></b> adli kullaniciyi neden sikayet ediyorsunuz?</p>
            <div class="grid grid-cols-2 gap-2 mb-4">
                <button onclick="setReportReason('Taciz / Zorbalik')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Taciz</button>
                <button onclick="setReportReason('Uygunsuz Icerik')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Uygunsuz</button>
                <button onclick="setReportReason('Spam / Bot')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Spam</button>
                <button onclick="setReportReason('Sahte Hesap')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Sahte Hesap</button>
                <button onclick="setReportReason('Nefret Soylemi')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Nefret Soylemi</button>
                <button onclick="setReportReason('Diger')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Diger</button>
            </div>
            <textarea id="report-user-detail" placeholder="Ek aciklama (istege bagli)..." class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 h-16 text-white text-sm outline-none focus:border-orange-500 transition custom-scrollbar mb-4"></textarea>
            <div class="grid grid-cols-2 gap-3">
                <button onclick="document.getElementById('report-user-modal').classList.add('hidden')" class="bg-zinc-900 border border-zinc-700 text-zinc-400 py-3 rounded-xl font-bold text-sm">Iptal</button>
                <button onclick="submitReportUser()" class="bg-orange-800 hover:bg-orange-700 text-white py-3 rounded-xl font-bold text-sm btn-premium-hover">SIKAYET ET</button>
            </div>
        </div>
    </div>

    <!-- MESAJ SIKAYET MODALI -->
    <div id="report-msg-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[99999] px-4">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-orange-900/50 shadow-2xl scale-in-anim">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-2xl text-orange-400 teko-font tracking-wide">&#128680; Mesaji Sikayet Et</h3>
                <button onclick="document.getElementById('report-msg-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">&#10005;</button>
            </div>
            <div id="report-msg-preview" class="bg-black/60 border border-zinc-700 rounded-xl p-3 mb-4 text-zinc-300 text-xs italic break-words"></div>
            <div class="grid grid-cols-2 gap-2 mb-4">
                <button onclick="setMsgReportReason('Taciz / Zorbalik')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Taciz</button>
                <button onclick="setMsgReportReason('Uygunsuz Icerik')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Uygunsuz</button>
                <button onclick="setMsgReportReason('Spam / Reklam')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Spam</button>
                <button onclick="setMsgReportReason('Nefret Soylemi')" class="bg-zinc-900 border border-zinc-700 hover:border-orange-600 transition text-zinc-300 py-2.5 rounded-xl text-xs font-bold">Nefret</button>
            </div>
            <div class="grid grid-cols-2 gap-3">
                <button onclick="document.getElementById('report-msg-modal').classList.add('hidden')" class="bg-zinc-900 border border-zinc-700 text-zinc-400 py-3 rounded-xl font-bold text-sm">Iptal</button>
                <button onclick="submitReportMsg()" class="bg-orange-800 hover:bg-orange-700 text-white py-3 rounded-xl font-bold text-sm btn-premium-hover">SIKAYET ET</button>
            </div>
        </div>
    </div>

    <!-- TAM EKRAN FOTOGRAF GORUNTULEME -->
    <div id="fullscreen-img-modal" class="hidden fixed inset-0 bg-black z-[99999] flex items-center justify-center" onclick="closeFullscreenImg()">
        <button class="absolute top-4 right-4 z-10 w-10 h-10 bg-black/60 rounded-full text-white text-xl flex items-center justify-center border border-zinc-700">✕</button>
        <div class="absolute top-4 left-4 flex gap-2 z-10" id="fullscreen-nav">
            <button onclick="event.stopPropagation(); fullscreenPrev()" class="w-10 h-10 bg-black/60 rounded-full text-white text-lg flex items-center justify-center border border-zinc-700">‹</button>
            <button onclick="event.stopPropagation(); fullscreenNext()" class="w-10 h-10 bg-black/60 rounded-full text-white text-lg flex items-center justify-center border border-zinc-700">›</button>
        </div>
        <img id="fullscreen-img" src="" class="max-w-full max-h-full object-contain select-none" style="touch-action:pinch-zoom;">
        <div id="fullscreen-counter" class="absolute bottom-6 left-1/2 -translate-x-1/2 bg-black/60 text-white text-xs px-3 py-1 rounded-full font-bold"></div>
    </div>

    <!-- REEL YÜKLEME MODALI -->
    <div id="reel-upload-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[99999] px-4 backdrop-blur-md">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-6 border border-pink-900/50 shadow-2xl scale-in-anim">
            <div class="flex items-center justify-between mb-5">
                <h3 class="text-3xl text-white teko-font tracking-wide">🎬 REEL PAYLAŞ</h3>
                <button onclick="document.getElementById('reel-upload-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">✕</button>
            </div>

            <!-- Üyelik bilgisi -->
            <div id="reel-limit-info" class="bg-zinc-900/80 border border-zinc-700 rounded-xl p-3 mb-4 text-xs text-zinc-400 font-bold"></div>

            <!-- Medya seçimi -->
            <div class="grid grid-cols-2 gap-3 mb-4">
                <!-- Reel medya seçimi — Prominent Disclosure ile açılır -->
                <button id="reel-photo-btn" onclick="_showPhotoDisclosure('reel', () => document.getElementById('reel-photo-input').click())" class="flex flex-col items-center justify-center gap-2 bg-zinc-900 border-2 border-pink-600/50 rounded-xl p-4 cursor-pointer hover:bg-pink-900/20 transition">
                    <span class="text-3xl">📸</span>
                    <span class="text-xs font-black text-white uppercase tracking-widest">Fotoğraf</span>
                </button>
                <input type="file" id="reel-photo-input" accept="image/*" class="hidden" onchange="handleReelFile(this,'image')">
                <button id="reel-video-btn" onclick="_showPhotoDisclosure('reel', () => document.getElementById('reel-video-input').click())" class="flex flex-col items-center justify-center gap-2 bg-zinc-900 border-2 border-zinc-700 rounded-xl p-4 cursor-pointer hover:bg-zinc-800 transition">
                    <span class="text-3xl">🎥</span>
                    <span class="text-xs font-black text-white uppercase tracking-widest">Video</span>
                    <span class="text-[9px] text-zinc-500 font-bold">Standart+ gerekli</span>
                </button>
                <input type="file" id="reel-video-input" accept="video/*" class="hidden" onchange="handleReelFile(this,'video')">
            </div>

            <!-- Önizleme -->
            <div id="reel-preview-container" class="hidden mb-4 rounded-xl overflow-hidden bg-black border border-zinc-700 relative" style="max-height:200px">
                <img id="reel-preview-img" class="hidden w-full object-cover" style="max-height:200px">
                <video id="reel-preview-video" class="hidden w-full" style="max-height:200px" controls muted playsinline></video>
                <button onclick="clearReelFile()" class="absolute top-2 right-2 w-7 h-7 bg-black/70 rounded-full text-white text-xs flex items-center justify-center border border-zinc-600">✕</button>
                <div id="reel-compress-info" class="absolute bottom-2 left-2 bg-black/70 text-green-400 text-[9px] font-bold px-2 py-1 rounded-lg hidden">✓ Optimize edildi</div>
            </div>

            <textarea id="reel-caption" placeholder="Açıklama ekle... #downhill #freeride" class="w-full bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 h-16 text-white text-sm outline-none focus:border-pink-500 transition custom-scrollbar mb-4 font-medium resize-none"></textarea>

            <div id="reel-upload-progress" class="hidden mb-3">
                <div class="text-xs text-zinc-400 font-bold mb-1 text-center">Yükleniyor...</div>
                <div class="w-full bg-zinc-800 rounded-full h-2"><div id="reel-progress-bar" class="bg-gradient-to-r from-pink-600 to-sky-400 h-2 rounded-full transition-all" style="width:0%"></div></div>
            </div>

            <div class="grid grid-cols-2 gap-3">
                <button onclick="document.getElementById('reel-upload-modal').classList.add('hidden')" class="bg-zinc-900 border border-zinc-700 text-zinc-400 py-3 rounded-xl font-bold text-sm">İptal</button>
                <button onclick="submitReel()" id="reel-submit-btn" class="bg-gradient-to-r from-pink-700 to-sky-500 hover:opacity-90 text-white py-3 rounded-xl font-black text-sm tracking-widest btn-premium-hover shadow-[0_0_15px_rgba(236,72,153,0.4)]">PAYLAŞ</button>
            </div>
        </div>
    </div>

    <!-- Reel Yorum Modali -->
    <div id="reel-comment-modal" class="hidden fixed inset-0 modal-backdrop flex items-end justify-center z-[99999]">
        <div class="glass-panel w-full max-w-md rounded-t-3xl p-5 border-t border-zinc-700 shadow-2xl" style="max-height:70vh;display:flex;flex-direction:column;">
            <div class="flex items-center justify-between mb-4 shrink-0">
                <h3 class="text-xl text-white teko-font tracking-wide">💬 Yorumlar</h3>
                <button onclick="document.getElementById('reel-comment-modal').classList.add('hidden')" class="w-8 h-8 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center">✕</button>
            </div>
            <div id="reel-comments-list" class="flex-1 overflow-y-auto custom-scrollbar space-y-3 mb-4 pr-1"></div>
            <div class="flex gap-2 shrink-0">
                <input id="reel-comment-input" type="text" placeholder="Yorum yaz..." class="flex-1 bg-black/60 border border-zinc-700 rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-pink-500 transition font-medium">
                <button onclick="submitReelComment()" class="bg-pink-700 hover:bg-pink-600 text-white px-5 py-3 rounded-xl font-black text-sm btn-premium-hover">GÖNDER</button>
            </div>
        </div>
    </div>

    <!-- Trial Bitti Modali -->
    <div id="trial-expired-modal" class="hidden fixed inset-0 modal-backdrop flex items-center justify-center z-[99999] px-4">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-7 border border-yellow-600/50 shadow-[0_0_50px_rgba(234,179,8,0.3)] text-center scale-in-anim">
            <div class="text-6xl mb-4">🏔️</div>
            <h2 class="text-3xl text-white teko-font tracking-wide mb-2">3 Gunluk Denemen Bitti!</h2>
            <p class="text-zinc-300 text-sm mb-2 leading-relaxed">Ultra+ deneyimin nasıldı? Sınırsız AI, özel renkler, alev efekti ve çok daha fazlası seni bekliyor!</p>
            <div class="bg-black/40 rounded-2xl p-4 mb-5 border border-yellow-900/40">
                <div class="text-yellow-400 font-black text-sm uppercase tracking-widest mb-2">Ultra+ ile Neler Kazanırsın?</div>
                <div class="text-left text-xs text-zinc-300 space-y-1">
                    <div>👑 Özel isim rengi ve efekt</div>
                    <div>🤖 Sınırsız Freerider AI</div>
                    <div>🔥 Alev/Buz profil efekti</div>
                    <div>📍 Sapphire harita ikonları</div>
                    <div>📸 10 bisiklet fotoğrafı</div>
                    <div>📌 Mesaj sabitleme</div>
                </div>
            </div>
            <button onclick="document.getElementById('trial-expired-modal').classList.add('hidden'); switchTab(6);" class="w-full bg-gradient-to-r from-yellow-600 to-amber-500 hover:opacity-90 text-black py-4 rounded-xl font-black text-base tracking-widest btn-premium-hover shadow-[0_0_20px_rgba(234,179,8,0.5)] mb-3">👑 PLUS ALMAK İSTİYORUM!</button>
            <button onclick="document.getElementById('trial-expired-modal').classList.add('hidden')" class="w-full bg-zinc-900 border border-zinc-700 hover:bg-zinc-800 text-zinc-400 py-3 rounded-xl font-bold text-sm transition">Daha Sonra</button>
        </div>
    </div>

    <!-- READY PLAYER ME AVATAR MODAL -->
    <div id="rpm-modal" class="hidden fixed inset-0 z-[99999] flex flex-col" style="background:#000;">
        <div class="flex items-center justify-between px-4 py-3 bg-zinc-950 border-b border-zinc-800 shrink-0">
            <div class="flex items-center gap-3">
                <span class="text-xl">🎭</span>
                <span class="text-white font-black text-sm teko-font tracking-widest">3D AVATAR OLUŞTUR</span>
            </div>
            <button onclick="closeRpmModal()" class="w-9 h-9 bg-zinc-800 rounded-full text-zinc-400 hover:text-white flex items-center justify-center text-lg border border-zinc-700">✕</button>
        </div>
        <div id="rpm-loading" class="flex flex-col items-center justify-center flex-1 gap-4">
            <div class="w-12 h-12 rounded-full border-4 border-purple-900/40 border-t-purple-500 animate-spin"></div>
            <p class="text-zinc-400 text-sm font-bold">Avatar editörü yükleniyor...</p>
        </div>
        <iframe id="rpm-iframe" class="hidden flex-1 w-full border-none" allow="camera *; microphone *"></iframe>
        <div class="px-4 py-3 bg-zinc-950 border-t border-zinc-800 shrink-0">
            <p class="text-[10px] text-zinc-500 text-center font-bold uppercase tracking-widest">Avatarını oluşturduktan sonra "Kullan" butonuna bas — otomatik kaydedilir</p>
        </div>
    </div>

    <!-- ================================================================ -->
    <!-- GOOGLE PLAY PROMINENT DISCLOSURE — MİKROFON İZNİ MODALI         -->
    <!-- Politika: getUserMedia() çağrısından ÖNCE gösterilmesi zorunlu   -->
    <!-- ================================================================ -->
    <div id="pd-mic-modal" class="hidden fixed inset-0 z-[999999] flex items-center justify-center px-4" style="background:rgba(0,0,0,0.75);backdrop-filter:blur(6px)">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-7 border border-sky-700/60 shadow-[0_0_50px_rgba(14,165,233,0.2)] scale-in-anim">
            <div class="flex flex-col items-center text-center gap-4">
                <div class="w-16 h-16 rounded-2xl bg-sky-900/60 border border-sky-600/50 flex items-center justify-center text-4xl shadow-lg">🎤</div>
                <div>
                    <h2 class="text-2xl text-white font-black tracking-wide mb-1">Mikrofon İzni</h2>
                    <p class="text-xs text-sky-400 font-bold uppercase tracking-widest">Sesli Mesaj Özelliği</p>
                </div>
                <div class="bg-black/50 rounded-2xl p-4 border border-zinc-700 text-left w-full space-y-2">
                    <p class="text-sm text-zinc-200 leading-relaxed">FreeriderTR, <strong class="text-white">sesli mesaj kaydedip göndermek</strong> için mikrofonuna erişmek istiyor.</p>
                    <ul class="text-xs text-zinc-400 space-y-1.5 pt-1">
                        <li class="flex items-start gap-2"><span class="text-sky-400 shrink-0 mt-0.5">✔</span><span>Ses yalnızca kayıt düğmesine bastığında alınır</span></li>
                        <li class="flex items-start gap-2"><span class="text-sky-400 shrink-0 mt-0.5">✔</span><span>Kayıt dışında mikrofon hiçbir zaman aktif olmaz</span></li>
                        <li class="flex items-start gap-2"><span class="text-sky-400 shrink-0 mt-0.5">✔</span><span>Ses verisi yalnızca mesaj olarak iletilir, başka amaçla kullanılmaz</span></li>
                        <li class="flex items-start gap-2"><span class="text-zinc-500 shrink-0 mt-0.5">ⓘ</span><span class="text-zinc-500">İzni tarayıcı ayarlarından istediğin zaman iptal edebilirsin</span></li>
                    </ul>
                </div>
                <div class="grid grid-cols-2 gap-3 w-full">
                    <button id="pd-mic-deny" class="bg-zinc-900 border border-zinc-700 hover:bg-zinc-800 text-zinc-400 py-3 rounded-xl font-bold text-sm transition">Vazgeç</button>
                    <button id="pd-mic-allow" class="bg-gradient-to-r from-sky-700 to-sky-500 hover:opacity-90 text-white py-3 rounded-xl font-black text-sm tracking-widest shadow-[0_0_15px_rgba(14,165,233,0.35)]">İzin Ver</button>
                </div>
                <p class="text-[10px] text-zinc-600 leading-relaxed">"İzin Ver"e basınca tarayıcının standart izin penceresi açılır. Orada da onaylaman gerekir.</p>
            </div>
        </div>
    </div>

    <!-- ================================================================ -->
    <!-- GOOGLE PLAY PROMINENT DISCLOSURE — FOTOĞRAF / GALERİ MODALI      -->
    <!-- Politika: file input tetiklenmeden ÖNCE gösterilmesi zorunlu      -->
    <!-- ================================================================ -->
    <div id="pd-photo-modal" class="hidden fixed inset-0 z-[999999] flex items-center justify-center px-4" style="background:rgba(0,0,0,0.75);backdrop-filter:blur(6px)">
        <div class="glass-panel w-full max-w-sm rounded-3xl p-7 border border-pink-700/60 shadow-[0_0_50px_rgba(236,72,153,0.15)] scale-in-anim">
            <div class="flex flex-col items-center text-center gap-4">
                <div class="w-16 h-16 rounded-2xl bg-pink-900/50 border border-pink-600/50 flex items-center justify-center text-4xl shadow-lg" id="pd-photo-icon">📸</div>
                <div>
                    <h2 class="text-2xl text-white font-black tracking-wide mb-1" id="pd-photo-title">Fotoğraf Erişimi</h2>
                    <p class="text-xs text-pink-400 font-bold uppercase tracking-widest" id="pd-photo-subtitle">Galeri Erişimi</p>
                </div>
                <div class="bg-black/50 rounded-2xl p-4 border border-zinc-700 text-left w-full space-y-2">
                    <p class="text-sm text-zinc-200 leading-relaxed" id="pd-photo-desc">FreeriderTR, seçtiğin fotoğrafa erişmek için galerini kullanacak.</p>
                    <ul class="text-xs text-zinc-400 space-y-1.5 pt-1" id="pd-photo-list"></ul>
                </div>
                <div class="grid grid-cols-2 gap-3 w-full">
                    <button id="pd-photo-deny" class="bg-zinc-900 border border-zinc-700 hover:bg-zinc-800 text-zinc-400 py-3 rounded-xl font-bold text-sm transition">Vazgeç</button>
                    <button id="pd-photo-allow" class="bg-gradient-to-r from-pink-700 to-rose-500 hover:opacity-90 text-white py-3 rounded-xl font-black text-sm tracking-widest shadow-[0_0_15px_rgba(236,72,153,0.3)]">Galeriye Git</button>
                </div>
                <p class="text-[10px] text-zinc-600 leading-relaxed">Seçilen medya yalnızca belirtilen amaçla kullanılır ve üçüncü taraflarla paylaşılmaz.</p>
            </div>
        </div>
    </div>

    <!-- ================================================================ -->
    <!-- GOOGLE PLAY IAP — Android Satın Alma Callback'leri               -->
    <!-- ================================================================ -->
    <script>
    // Android Google Play Satın Alma Callback'leri
    function onGooglePurchaseSuccess(purchaseToken, subscriptionId) {
        fetch('/api/verify_google_purchase', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                purchaseToken: purchaseToken,
                productId: subscriptionId    // Python'ın beklediği field adı
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'ok') {
                location.reload();
            } else {
                alert("Doğrulama hatası: " + (data.message || "Hata"));
            }
        })
        .catch(err => {
            alert("Sunucuya ulaşılamadı, tekrar dene.");
        });
    }

    function onGooglePurchaseCancelled(msg) {
        console.log("Satın alma iptal edildi");
    }

    function onGooglePurchaseError(errorMessage) {
        alert("Ödeme başarısız: " + errorMessage);
    }

    function handleBuyButton(productId) {
        if (typeof window.Android !== 'undefined' && window.Android.isAndroidApp()) {
            window.Android.launchBilling(productId);
        } else {
            // Mevcut web ödeme fonksiyonun buraya
            console.log("Web ödeme:", productId);
        }
    }
    </script>

</body>
</html>
""" # <--- HTML Bloğu tam burada, her şey bittikten sonra kapanmalı!

@app.route("/")
def index():
    return render_template_string(
        HTML_CODE,
        onesignal_app_id=ONESIGNAL_APP_ID or "",
        supabase_url=SUPABASE_URL or "",
        supabase_key=SUPABASE_KEY or "",
    )

if __name__ == "__main__":
    print("===================================================")
    print("💎 V7.0 FREERIDER PLUS (HAFTALIK YARIŞ & SOSYAL MEDYA EDITION)")
    print("🚀 SİSTEM CANLIYA HAZIR, BANDWIDTH OPTİMİZE EDİLDİ!")
    print("===================================================")
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
