import os
import sys
import json
import logging
import base64
import hashlib
import hmac
import secrets
import uuid
import asyncio
from datetime import datetime
import io
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, Request, Query, UploadFile, File
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import Optional, List
import uvicorn
from starlette.middleware.gzip import GZipMiddleware

try:
    from multicolorcaptcha import CaptchaGenerator
except ImportError:
    CaptchaGenerator = None

from managers.ssh_manager import SSHManager
from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager
from managers import db
import telegram_bot as tg_bot

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ordered list of OpenAPI tag groups — the order here drives the section order in /docs and /redoc.
OPENAPI_TAGS = [
    {"name": "System Templates", "description": "HTML pages served to browsers. These return Jinja-rendered templates rather than a JSON contract — they are not part of the public API and are listed here only for completeness."},
    {"name": "Authentication", "description": "Login, captcha, and session lifecycle."},
    {"name": "Servers", "description": "Server inventory, lifecycle and host-level operations (add, edit, delete, ping, reorder, reboot, clear, stats, status check)."},
    {"name": "Protocols", "description": "Install, uninstall, container start/stop and raw config editing for the protocols/services on a server (AWG, Xray, WireGuard, Telemt, AmneziaDNS, AdGuard Home, SOCKS5)."},
    {"name": "Connections", "description": "Per-protocol VPN client connections on a server (CRUD plus enable/disable and config retrieval)."},
    {"name": "Users", "description": "Panel user accounts and the connections assigned to them."},
    {"name": "Self-service", "description": "Endpoints called by a regular user for their own data (the /my surface)."},
    {"name": "Sharing", "description": "Public, token-protected configuration sharing for end users — no panel session required."},
    {"name": "Settings", "description": "Panel-wide settings, Telegram bot, JSON backup/restore."},
    {"name": "API Tokens", "description": "Bearer tokens for external integrations. Send the token in `Authorization: Bearer <token>`; tokens have admin-equivalent rights and are tied to the admin user that created them."},
]

app = FastAPI(
    title="Amnezia Web Panel",
    openapi_tags=OPENAPI_TAGS,
    redoc_url=None,
)


@app.on_event("startup")
async def startup():
    await db.init_db(DB_PATH)
    
    if not await db.has_users():
        admin = {
            'id': str(uuid.uuid4()),
            'username': 'admin',
            'password_hash': await asyncio.to_thread(hash_password, 'admin'),
            'role': 'admin',
            'enabled': True,
            'created_at': datetime.now().isoformat(),
        }
        await db.add_user(admin)
        logger.info("Default admin created (admin / admin)")

    asyncio.create_task(periodic_background_tasks())

    tg_cfg = await db.get_setting('telegram', {})
    if tg_cfg.get('enabled') and tg_cfg.get('token'):
        logger.info("Starting Telegram bot from saved settings...")
        tg_bot.launch_bot(tg_cfg['token'], _get_telegram_data_fn, generate_vpn_link)


@app.get("/redoc", include_in_schema=False)
async def custom_redoc():
    """Self-curated ReDoc page. Differs from FastAPI's default in two ways:
    pinned bundle (`redoc@2` instead of `@next`) and Google Fonts disabled
    (the Montserrat/Roboto stylesheet is blocked on a lot of networks and made
    the page hang for some users)."""
    from fastapi.openapi.docs import get_redoc_html
    return get_redoc_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} — ReDoc",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js",
        with_google_fonts=False,
    )
app.add_middleware(SessionMiddleware, secret_key=os.environ.get('SECRET_KEY', secrets.token_hex(32)))
app.add_middleware(GZipMiddleware, minimum_size=500)

# Mount static files & templates
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(__file__)

DB_PATH = os.environ.get('DB_PATH', os.path.join(application_path, 'panel.db'))
CURRENT_VERSION = "v2.2.0"


# ======================== Translations ========================
TRANSLATIONS = {}

def load_translations():
    global TRANSLATIONS
    trans_dir = os.path.join(os.path.dirname(__file__), 'translations')
    if os.path.exists(trans_dir):
        for f in os.listdir(trans_dir):
            if f.endswith('.json'):
                lang = f.split('.')[0]
                try:
                    with open(os.path.join(trans_dir, f), 'r', encoding='utf-8') as tf:
                        TRANSLATIONS[lang] = json.load(tf)
                except Exception as e:
                    logger.error(f"Error loading translation {f}: {e}")
    logger.info(f"Loaded translations: {list(TRANSLATIONS.keys())}")

def _t(text_id, lang='en'):
    lang_batch = TRANSLATIONS.get(lang, TRANSLATIONS.get('en', {}))
    return lang_batch.get(text_id, text_id)

load_translations()


# ======================== Helpers ========================


async def run_ssh_command(ssh, method, *args, **kwargs):
    """Run an SSH command in a thread to avoid blocking the event loop."""
    return await asyncio.to_thread(method, *args, **kwargs)


def get_ssh(server):
    return SSHManager(
        host=server['host'],
        port=server.get('ssh_port', 22),
        username=server['username'],
        password=server.get('password'),
        private_key=server.get('private_key'),
    )


def get_protocol_manager(ssh, protocol: str):
    if protocol == 'telemt':
        from managers.telemt_manager import TelemtManager
        return TelemtManager(ssh)
    elif protocol == 'dns':
        from managers.dns_manager import DNSManager
        return DNSManager(ssh)
    elif protocol == 'wireguard':
        from managers.wireguard_manager import WireGuardManager
        return WireGuardManager(ssh)
    elif protocol == 'socks5':
        from managers.socks5_manager import Socks5Manager
        return Socks5Manager(ssh)
    elif protocol == 'adguard':
        from managers.adguard_manager import AdguardManager
        return AdguardManager(ssh)
    from managers.awg_manager import AWGManager
    return AWGManager(ssh)


def _manager_call(manager, method, protocol, *args, **kwargs):
    """Unified call: WireGuard manager methods don't take protocol_type argument."""
    fn = getattr(manager, method)
    if isinstance(manager, WireGuardManager):
        return fn(*args, **kwargs)
    return fn(protocol, *args, **kwargs)


def generate_vpn_link(config_text):
    b64 = base64.b64encode(config_text.strip().encode('utf-8')).decode('utf-8')
    return f"vpn://{b64}"


# ===================== API tokens =====================

API_TOKEN_PREFIX = 'awp_'  # "Amnezia Web Panel" — makes tokens visually distinct in logs / configs
API_TOKEN_TOUCH_INTERVAL = 300  # don't re-write the DB more than once per 5 min per token


def _hash_api_token(raw: str) -> str:
    """One-way hash of a raw token. We never store the original token — only the
    SHA-256 digest, plus a short prefix for the UI to identify rotations."""
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _generate_api_token() -> str:
    """Generate a fresh bearer token. ~256 bits of entropy with a recognizable
    'awp_' prefix so leaked tokens are obvious in source control / pastes."""
    return f"{API_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


async def _resolve_api_token(raw_token: str):
    """Match a raw bearer token against stored hashes. Returns the user record
    that owns the token, or None if the token is unknown / its owner is gone /
    its owner is no longer admin-or-support."""
    if not raw_token:
        return None
    token_hash = _hash_api_token(raw_token)
    tokens = await db.get_api_tokens()
    entry = next(
        (t for t in tokens if t.get('token_hash') == token_hash),
        None,
    )
    if not entry:
        return None
    user = await db.get_user(entry.get('user_id'))
    if not user:
        return None
    if not user.get('enabled', True):
        return None
    if user.get('role') not in ('admin', 'support'):
        return None
    return (entry, user)


async def _touch_api_token(token_entry: dict) -> bool:
    """Update last_used_at on a token entry, but only if enough time has passed
    since the previous touch — avoids hot-write loops under load. Returns True
    if the entry was updated and the caller should persist data."""
    now = datetime.now()
    last = token_entry.get('last_used_at')
    if last:
        try:
            prev = datetime.fromisoformat(last)
            if (now - prev).total_seconds() < API_TOKEN_TOUCH_INTERVAL:
                return False
        except Exception:
            pass
    token_entry['last_used_at'] = now.isoformat()
    return True


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${h.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, h = password_hash.split('$', 1)
        new_h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(new_h.hex(), h)
    except Exception:
        return False


async def _get_telegram_data_fn():
    """Return all data needed by the telegram bot as a dict."""
    servers = await db.get_servers()
    users = await db.get_users()
    conns = await db.get_user_connections()
    settings = await db.get_all_settings()
    return {
        'servers': servers,
        'users': users,
        'user_connections': conns,
        'settings': settings,
    }


def _scrape_server_traffic(server, sid, my_conns):
    server_updates = []
    try:
        ssh = get_ssh(server)
        ssh.connect()
        for proto in ['awg2', 'telemt', 'wireguard']:
            if proto in server.get('protocols', {}):
                manager = get_protocol_manager(ssh, proto)
                clients = _manager_call(manager, 'get_clients', proto)
                client_bytes = {}
                for c in clients:
                    rx = c.get('userData', {}).get('dataReceivedBytes', 0)
                    tx = c.get('userData', {}).get('dataSentBytes', 0)
                    client_bytes[c.get('clientId')] = rx + tx

                for uc in my_conns:
                    if uc['protocol'] == proto and uc['client_id'] in client_bytes:
                        curr_bytes = client_bytes[uc['client_id']]
                        last_bytes = uc.get('last_bytes', 0)
                        delta = curr_bytes - last_bytes if curr_bytes >= last_bytes else curr_bytes
                        server_updates.append((uc['id'], delta, curr_bytes))
        ssh.disconnect()
    except Exception as e:
        logger.error(f"Traffic sync err server {sid}: {e}")
    return server_updates


async def periodic_background_tasks():
    """Background task to sync traffic limits every 10 minutes"""
    while True:
        try:
            await asyncio.sleep(60)

            logger.info("Starting background traffic sync...")
            servers = await db.get_servers()
            all_conns = await db.get_user_connections()
            users = await db.get_users()

            conns_by_server = {}
            for uc in all_conns:
                sid = uc['server_id']
                conns_by_server.setdefault(sid, []).append(uc)

            updates = []
            tasks = []
            for server in servers:
                sid = server['server_id']
                if sid not in conns_by_server:
                    continue
                tasks.append(asyncio.to_thread(_scrape_server_traffic, server, sid, conns_by_server[sid]))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, list):
                        updates.extend(res)
                    elif isinstance(res, Exception):
                        logger.error(f"Background traffic sync server failed: {res}")

            to_disable_uids = []
            if updates:
                users_map = {u['id']: u for u in users}
                for uc_id, delta, curr_bytes in updates:
                    conns_list = await db.get_user_connections()
                    uc = next((c for c in conns_list if c['id'] == uc_id), None)
                    if not uc:
                        continue
                    uc['last_bytes'] = curr_bytes
                    await db.update_connection(uc)
                    uid = uc['user_id']
                    if uid not in users_map:
                        continue
                    u = users_map[uid]
                    strategy = u.get('traffic_reset_strategy', 'never')
                    last_reset_iso = u.get('last_reset_at')
                    now = datetime.now()

                    reset_needed = False
                    if strategy != 'never' and last_reset_iso:
                        try:
                            last = datetime.fromisoformat(last_reset_iso)
                            if strategy == 'daily':
                                reset_needed = now.date() > last.date()
                            elif strategy == 'weekly':
                                reset_needed = now.isocalendar()[1] != last.isocalendar()[1] or now.year != last.year
                            elif strategy == 'monthly':
                                reset_needed = now.month != last.month or now.year != last.year
                        except Exception:
                            pass

                    if reset_needed:
                        logger.info(f"Resetting traffic for user {u['username']} (strategy: {strategy})")
                        u['traffic_used'] = 0
                        u['last_reset_at'] = now.isoformat()

                    u['traffic_used'] = u.get('traffic_used', 0) + delta
                    u['traffic_total'] = u.get('traffic_total', 0) + delta

                    limit = u.get('traffic_limit', 0)
                    if limit > 0 and u['traffic_used'] >= limit and u.get('enabled', True):
                        if uid not in to_disable_uids:
                            to_disable_uids.append(uid)

                    exp_str = u.get('expiration_date')
                    if exp_str and u.get('enabled', True):
                        try:
                            exp_date = datetime.fromisoformat(exp_str)
                            if now > exp_date:
                                logger.info(f"Subscription expired for user {u['username']} (expired at {exp_str})")
                                if uid not in to_disable_uids:
                                    to_disable_uids.append(uid)
                        except Exception:
                            pass

                await db.update_users_bulk(list(users_map.values()))

            if to_disable_uids:
                logger.info(f"Traffic limit reached, disabling users: {to_disable_uids}")
                await perform_mass_operations(toggle_uids=[(uid, False) for uid in to_disable_uids])

        except Exception as e:
            logger.error(f"Error in periodic_background_tasks: {e}")

        await asyncio.sleep(600)


async def perform_delete_user(user_id: str):
    user = await db.get_user(user_id)
    if not user:
        return False
    await perform_mass_operations(delete_uids=[user_id])
    return True


async def perform_toggle_user(user_id: str, enable: bool) -> bool:
    """Enable or disable a user and propagate the change to all their VPN connections."""
    user = await db.get_user(user_id)
    if not user:
        return False
    await perform_mass_operations(toggle_uids=[(user_id, enable)])
    return True


async def perform_mass_operations(delete_uids: List[str] = None, toggle_uids: List[tuple] = None):
    """
    Executes multiple SSH operations efficiently.
    """
    servers_map = {s['server_id']: s for s in await db.get_servers()}
    server_ops = {}

    def get_ops(sid):
        if sid not in server_ops:
            server_ops[sid] = {'delete': [], 'toggle': []}
        return server_ops[sid]

    if delete_uids:
        for uid in delete_uids:
            conns = await db.get_user_connections(uid)
            for c in conns:
                get_ops(c['server_id'])['delete'].append(c)

    if toggle_uids:
        for uid, enabled in toggle_uids:
            conns = await db.get_user_connections(uid)
            for c in conns:
                get_ops(c['server_id'])['toggle'].append((c, enabled))

    async def run_server_ops(srv_id, ops):
        srv = servers_map.get(srv_id)
        if not srv:
            return

        try:
            ssh = get_ssh(srv)
            await asyncio.to_thread(ssh.connect)

            for c in ops['delete']:
                manager = get_protocol_manager(ssh, c['protocol'])
                await asyncio.to_thread(_manager_call, manager, 'remove_client', c['protocol'], c['client_id'])
                await db.delete_connection(c['id'])

            for c, enabled in ops['toggle']:
                manager = get_protocol_manager(ssh, c['protocol'])
                await asyncio.to_thread(_manager_call, manager, 'toggle_client', c['protocol'], c['client_id'], enabled)

            await asyncio.to_thread(ssh.disconnect)
        except Exception as e:
            logger.error(f"Mass ops failed for server {srv_id}: {e}")

    tasks = [run_server_ops(sid, ops) for sid, ops in server_ops.items()]
    if tasks:
        await asyncio.gather(*tasks)

    # Invalidate cache for affected servers/protocols
    from managers.cache import ssh_cache
    for sid, ops in server_ops.items():
        for c in ops['delete']:
            await ssh_cache.invalidate(sid, c['protocol'])
        for c, _ in ops['toggle']:
            await ssh_cache.invalidate(sid, c['protocol'])

    if delete_uids:
        await db.delete_users(delete_uids)
    if toggle_uids:
        for uid, enabled in toggle_uids:
            user = await db.get_user(uid)
            if user:
                user['enabled'] = enabled
                await db.update_user(user)

    return True




async def get_current_user(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    return await db.get_user(user_id)


async def tpl(request, template, **kwargs):
    settings = await db.get_all_settings()
    lang = request.cookies.get('lang', 'en')
    ctx = {
        'request': request,
        'current_user': await get_current_user(request),
        'site_settings': settings.get('appearance', {}),
        'captcha_settings': settings.get('captcha', {}),
        'telegram_settings': settings.get('telegram', {}),
        'bot_running': tg_bot.is_running(),
        'lang': lang,
        '_': lambda text_id: _t(text_id, lang),
        'translations_json': json.dumps(TRANSLATIONS.get(lang, TRANSLATIONS.get('en', {}))),
        'all_translations_json': json.dumps(TRANSLATIONS)
    }
    ctx.update(kwargs)
    return templates.TemplateResponse(request, template, ctx)


# ======================== Pydantic Models ========================

class LoginRequest(BaseModel):
    username: str
    password: str
    captcha: Optional[str] = None


class AddServerRequest(BaseModel):
    host: str = ''
    ssh_port: int = 22
    username: str = ''
    password: str = ''
    private_key: str = ''
    name: str = ''


class EditServerRequest(BaseModel):
    name: str = ''
    host: str = ''
    ssh_port: int = 22
    username: str = ''
    # Optional[str] = None lets the client distinguish "leave field as is"
    # (omit / null) from "explicitly clear" (empty string). Both credential
    # fields can be omitted to keep current auth unchanged.
    password: Optional[str] = None
    private_key: Optional[str] = None


class ReorderServersRequest(BaseModel):
    # `order[i]` is the *old* server index now at position `i` in the new layout.
    order: List[int]


class InstallProtocolRequest(BaseModel):
    protocol: str = 'awg2'
    port: str = '55424'
    tls_emulation: Optional[bool] = None
    tls_domain: Optional[str] = None
    max_connections: Optional[int] = None
    # SOCKS5
    socks5_username: Optional[str] = None
    socks5_password: Optional[str] = None
    # AdGuard Home
    adguard_mode: Optional[str] = None  # 'replace' or 'sidebyside'
    adguard_web_port: Optional[int] = None
    adguard_expose_web: Optional[bool] = None
    adguard_dot_port: Optional[int] = None
    adguard_doh_port: Optional[int] = None
    adguard_expose_dns: Optional[bool] = None
    adguard_expose_dot: Optional[bool] = None
    adguard_expose_doh: Optional[bool] = None


class Socks5SettingsRequest(BaseModel):
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None


class ProtocolRequest(BaseModel):
    protocol: str = 'awg2'


class AddConnectionRequest(BaseModel):
    protocol: str = 'awg2'
    name: str = 'Connection'
    user_id: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None


class EditConnectionRequest(BaseModel):
    protocol: str = 'telemt'
    client_id: str = ''
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None


class ConnectionActionRequest(BaseModel):
    protocol: str = 'awg2'
    client_id: str = ''


class ToggleConnectionRequest(BaseModel):
    protocol: str = 'awg2'
    client_id: str = ''
    enable: bool = True


class AddUserRequest(BaseModel):
    username: str
    password: str
    role: str = 'user'
    telegramId: Optional[str] = None
    email: Optional[str] = None
    description: Optional[str] = None
    traffic_limit: Optional[float] = 0
    traffic_reset_strategy: Optional[str] = 'never'
    server_id: Optional[int] = None
    protocol: Optional[str] = None
    connection_name: Optional[str] = None
    expiration_date: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None



class ServerConfigSaveRequest(BaseModel):
    protocol: str
    config: str


class AppearanceSettings(BaseModel):
    title: str = 'Amnezia'
    logo: str = '🛡'
    subtitle: str = 'Web Panel'


class CaptchaSettings(BaseModel):
    enabled: bool = False


class SSLSettings(BaseModel):
    enabled: bool = False
    domain: str = ''
    cert_path: str = ''
    key_path: str = ''
    cert_text: str = ''
    key_text: str = ''
    panel_port: int = 8000

class TelegramSettings(BaseModel):
    token: str = ''
    enabled: bool = False




class UpdateUserRequest(BaseModel):
    telegramId: Optional[str] = None
    email: Optional[str] = None
    description: Optional[str] = None
    traffic_limit: Optional[float] = 0
    traffic_reset_strategy: Optional[str] = None
    expiration_date: Optional[str] = None
    password: Optional[str] = None



class SaveSettingsRequest(BaseModel):
    appearance: AppearanceSettings
    captcha: CaptchaSettings
    telegram: TelegramSettings
    ssl: SSLSettings


class ToggleUserRequest(BaseModel):
    enabled: bool


class AddUserConnectionRequest(BaseModel):
    server_id: int
    protocol: str = 'awg2'
    name: str = 'VPN Connection'
    client_id: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None


class CreateApiTokenRequest(BaseModel):
    name: str


class ShareSetupRequest(BaseModel):
    enabled: bool
    password: Optional[str] = None


class ShareAuthRequest(BaseModel):
    password: str



@app.get('/login', response_class=HTMLResponse, tags=["System Templates"])
async def login_page(request: Request):
    if await get_current_user(request):
        return RedirectResponse(url='/', status_code=302)
    return await tpl(request, 'login.html')


@app.get("/set_lang/{lang}", tags=["System Templates"])
async def set_lang(lang: str, request: Request):
    ref = request.headers.get("referer", "/")
    # Validate referer is same-origin to prevent open redirect
    if ref.startswith("//") or ("://" in ref and not ref.startswith(str(request.base_url))):
        ref = "/"
    response = RedirectResponse(url=ref)
    response.set_cookie(key="lang", value=lang, max_age=31536000)
    return response


@app.get('/logout', tags=["System Templates"])
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url='/login', status_code=302)


@app.get('/', response_class=HTMLResponse, tags=["System Templates"])
async def index(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] == 'user':
        return RedirectResponse(url='/my', status_code=302)
    servers = await db.get_servers()
    return await tpl(request, 'index.html', servers=servers)


@app.get('/server/{server_id}', response_class=HTMLResponse, tags=["System Templates"])
async def server_detail(request: Request, server_id: int):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    server = await db.get_server(server_id)
    if not server:
        return RedirectResponse(url='/')
    users_list = await db.get_users()
    return await tpl(request, 'server.html', server=server, server_id=server_id, users=users_list)


@app.get('/users', response_class=HTMLResponse, tags=["System Templates"])
async def users_page(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    users_list = await db.get_users()
    conns = await db.get_user_connections()
    for u in users_list:
        u['connections_count'] = sum(1 for c in conns if c['user_id'] == u['id'])
    servers = await db.get_servers()
    return await tpl(request, 'users.html', users=users_list, servers=servers)


@app.get('/my', response_class=HTMLResponse, tags=["System Templates"])
async def my_connections_page(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    conns = await db.get_user_connections(user['id'])
    servers_map = {s['server_id']: s for s in await db.get_servers()}
    for c in conns:
        server = servers_map.get(c.get('server_id', 0))
        if server:
            c['server_name'] = server.get('name', server.get('host', ''))
        else:
            c['server_name'] = 'Unknown'
    return await tpl(request, 'my_connections.html', connections=conns)


# ======================== AUTH API ========================

@app.get('/api/auth/captcha', tags=["Authentication"])
async def api_captcha(request: Request):
    if not CaptchaGenerator:
        return JSONResponse({"error": "multicolorcaptcha is not installed"}, status_code=500)
    
    # 2 is a multiplier for the image resolution size
    generator = CaptchaGenerator(2)
    captcha = generator.gen_captcha_image(difficult_level=2)
    request.session['captcha_answer'] = captcha.characters
    
    img_bytes = io.BytesIO()
    await asyncio.to_thread(captcha.image.save, img_bytes, format='PNG')
    img_bytes.seek(0)
    
    return StreamingResponse(img_bytes, media_type="image/png")


@app.post('/api/auth/login', tags=["Authentication"])
async def api_login(request: Request, req: LoginRequest):
    captcha_settings = (await db.get_all_settings()).get('captcha', {})
    if captcha_settings.get('enabled') is True:
        answer = request.session.get('captcha_answer')
        lang = request.cookies.get('lang', 'ru')
        if not answer or not req.captcha or answer.lower() != req.captcha.lower():
            request.session.pop('captcha_answer', None)
            return JSONResponse({'error': _t('invalid_captcha', lang)}, status_code=400)
        request.session.pop('captcha_answer', None)

    u = await db.get_user_by_username(req.username)
    if u and await asyncio.to_thread(verify_password, req.password, u['password_hash']):
        lang = request.cookies.get('lang', 'ru')
        if not u.get('enabled', True):
            return JSONResponse({'error': _t('account_disabled', lang)}, status_code=403)
        request.session['user_id'] = u['id']
        return {'status': 'success', 'role': u['role']}
    lang = request.cookies.get('lang', 'ru')
    return JSONResponse({'error': _t('invalid_login', lang)}, status_code=401)


# ======================== SERVER API (admin/support) ========================

async def _check_admin(request):
    """Authorize an admin/support action via session cookie OR Bearer token.

    Tokens are admin-equivalent and inherit the role of the user who created
    them — if that user is later disabled or demoted, the token stops working.
    """
    user = await get_current_user(request)
    if user and user['role'] in ('admin', 'support'):
        return user

    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        raw_token = auth_header[7:].strip()
        resolved = await _resolve_api_token(raw_token)
        if resolved:
            entry, token_user = resolved
            try:
                if await _touch_api_token(entry):
                    tokens = await db.get_api_tokens()
                    await db.set_api_tokens(tokens)
            except Exception as e:
                logger.warning(f"Failed to touch API token last_used_at: {e}")
            return token_user

    return None


@app.post('/api/servers/add', tags=["Servers"])
async def api_add_server(request: Request, req: AddServerRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        host = req.host.strip()
        username = req.username.strip()
        name = req.name.strip() or host
        if not host or not username:
            return JSONResponse({'error': 'Host and username are required'}, status_code=400)
        if not req.password and not req.private_key:
            return JSONResponse({'error': 'Password or SSH key is required'}, status_code=400)

        ssh = SSHManager(host, req.ssh_port, username, req.password, req.private_key)

        def _test_connection():
            ssh.connect()
            try:
                return ssh.test_connection()
            finally:
                ssh.disconnect()

        try:
            server_info = await asyncio.to_thread(_test_connection)
        except Exception as e:
            return JSONResponse({'error': f'Connection failed: {str(e)}'}, status_code=400)

        server = {
            'name': name, 'host': host, 'ssh_port': req.ssh_port,
            'username': username, 'password': req.password,
            'private_key': req.private_key, 'server_info': server_info,
            'protocols': {},
        }
        server_id = await db.add_server(server)
        return {'status': 'success', 'server_id': server_id, 'server_info': server_info}
    except Exception as e:
        logger.exception("Error adding server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/edit', tags=["Servers"])
async def api_edit_server(request: Request, server_id: int, req: EditServerRequest):
    """Update connection details for an existing server entry. Verifies the new
    credentials by SSH-connecting before persisting, so a typo can't lock us out.
    """
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        new_host = (req.host or '').strip() or server['host']
        new_user = (req.username or '').strip() or server['username']
        new_port = int(req.ssh_port or server.get('ssh_port', 22))
        new_name = (req.name or '').strip() or server.get('name') or new_host

        # Credential resolution: a non-empty value in either field switches to
        # that auth method (and clears the other). Both omitted => keep current.
        if req.private_key:
            new_pass, new_key = '', req.private_key
        elif req.password:
            new_pass, new_key = req.password, ''
        else:
            new_pass = server.get('password', '')
            new_key = server.get('private_key', '')

        if not new_pass and not new_key:
            return JSONResponse({'error': 'Password or SSH key is required'}, status_code=400)

        # Verify the new connection details before committing the change.
        ssh = SSHManager(new_host, new_port, new_user, new_pass, new_key)

        def _test_connection():
            ssh.connect()
            try:
                return ssh.test_connection()
            finally:
                ssh.disconnect()

        try:
            server_info = await asyncio.to_thread(_test_connection)
        except Exception as e:
            return JSONResponse({'error': f'Connection failed: {e}'}, status_code=400)

        server['name'] = new_name
        server['host'] = new_host
        server['ssh_port'] = new_port
        server['username'] = new_user
        server['password'] = new_pass
        server['private_key'] = new_key
        server['server_info'] = server_info
        await db.update_server(server_id, server)
        return {'status': 'success', 'server_info': server_info}
    except Exception as e:
        logger.exception("Error editing server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/ping', tags=["Servers"])
async def api_server_ping(request: Request, server_id: int):
    """Cheap reachability check: opens a TCP connection to the SSH port,
    measures RTT, immediately closes. Runs on the asyncio loop so the page
    can issue many pings in parallel without blocking each other.
    """
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    server = await db.get_server(server_id)
    if not server:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    host = server['host']
    port = int(server.get('ssh_port', 22))

    import time as _time
    t0 = _time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=2.0
        )
        ms = round((_time.perf_counter() - t0) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {'alive': True, 'ms': ms}
    except asyncio.TimeoutError:
        return {'alive': False, 'error': 'timeout', 'ms': None}
    except Exception as e:
        return {'alive': False, 'error': str(e), 'ms': None}


@app.post('/api/servers/reorder', tags=["Servers"])
async def api_reorder_servers(request: Request, req: ReorderServersRequest):
    """Persist a user-defined ordering of servers. Also remaps `server_id`
    references in user_connections so existing assignments survive the move.
    """
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    servers = await db.get_servers()
    n = len(servers)
    order = req.order or []
    server_ids = {s['server_id'] for s in servers}
    if len(order) != n or set(order) != server_ids:
        return JSONResponse(
            {'error': 'Order must contain all server IDs exactly once'},
            status_code=400,
        )
    await db.reorder_servers(order)
    return {'status': 'success'}


@app.post('/api/servers/{server_id}/delete', tags=["Servers"])
async def api_delete_server(request: Request, server_id: int):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        await db.delete_server(server_id)
        await db.adjust_connection_server_ids(server_id)
        return {'status': 'success'}
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/reboot', tags=["Servers"])
async def api_reboot_server(request: Request, server_id: int):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _reboot():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                ssh.run_sudo_command("nohup reboot > /dev/null 2>&1 &")
            except Exception:
                pass
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        await asyncio.to_thread(_reboot)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error rebooting server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/clear', tags=["Servers"])
async def api_clear_server(request: Request, server_id: int):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _clear_server():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                # Match every Amnezia container by name prefix (catches awg/awg2/awg-legacy,
                # wireguard, xray/ssxray, openvpn, dns, and any future amnezia-* protocol)
                # plus the telemt container which doesn't share that prefix.
                # Using a single script avoids one SSH round-trip per command.
                cleanup_script = r"""
for c in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^(amnezia-|telemt$)'); do
    docker stop "$c" >/dev/null 2>&1 || true
    docker rm -fv "$c" >/dev/null 2>&1 || true
done

# Drop locally-built and pulled Amnezia images so reinstall starts from a clean slate
for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '^(amnezia-|amneziavpn/|telemt:)'); do
    docker rmi -f "$img" >/dev/null 2>&1 || true
done

docker network rm amnezia-dns-net >/dev/null 2>&1 || true
rm -rf /opt/amnezia
"""
                ssh.run_sudo_script(cleanup_script, timeout=120)
            finally:
                ssh.disconnect()

        await asyncio.to_thread(_clear_server)

        server['protocols'] = {}
        await db.update_server(server_id, server)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error clearing server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/stats', tags=["Servers"])
async def api_server_stats(request: Request, server_id: int):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _get_stats():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                cmd = (
                    "echo '===CPU==='; "
                    "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || "
                    "awk '{u=$2+$4; t=$2+$4+$5; if(NR==1){pu=u;pt=t} else printf \"%.1f\", (u-pu)/(t-pt)*100}' "
                    "<(grep 'cpu ' /proc/stat) <(sleep 0.5 && grep 'cpu ' /proc/stat) 2>/dev/null; "
                    "echo ''; echo '===RAM==='; "
                    "free -b | awk 'NR==2{printf \"%s %s\", $3, $2}'; "
                    "echo ''; echo '===DISK==='; "
                    "df -B1 / | awk 'NR==2{printf \"%s %s\", $3, $2}'; "
                    "echo ''; echo '===NET==='; "
                    "DEV=$(ip route | awk '/default/ {print $5}' | head -1); "
                    "if [ -n \"$DEV\" ]; then "
                    "  cat /proc/net/dev | awk -v dev=\"$DEV:\" '$1==dev{printf \"%s %s\", $2, $10}'; "
                    "else "
                    "  echo '0 0'; "
                    "fi; "
                    "echo ''; echo '===UPTIME==='; "
                    "uptime -p 2>/dev/null || uptime"
                )
                out, _, _ = ssh.run_command(cmd)

                sections = {}
                current_section = None
                for line in out.split('\n'):
                    line = line.strip()
                    if line.startswith('==='):
                        current_section = line.strip('=')
                        sections[current_section] = []
                    elif current_section:
                        sections[current_section].append(line)

                stats = {}

                # CPU
                try:
                    cpu_lines = sections.get('CPU', [])
                    cpu_val = next((l for l in cpu_lines if l), "0")
                    stats['cpu'] = round(float(cpu_val), 1)
                except Exception:
                    stats['cpu'] = 0.0

                # RAM
                try:
                    ram_lines = sections.get('RAM', [])
                    ram_val = next((l for l in ram_lines if l), "0 0")
                    parts = ram_val.split()
                    used, total = int(parts[0]), int(parts[1])
                    stats.update(ram_used=used, ram_total=total, ram_percent=round(used / total * 100, 1) if total > 0 else 0)
                except Exception:
                    stats.update(ram_used=0, ram_total=0, ram_percent=0.0)

                # DISK
                try:
                    disk_lines = sections.get('DISK', [])
                    disk_val = next((l for l in disk_lines if l), "0 0")
                    parts = disk_val.split()
                    used, total = int(parts[0]), int(parts[1])
                    stats.update(disk_used=used, disk_total=total, disk_percent=round(used / total * 100, 1) if total > 0 else 0)
                except Exception:
                    stats.update(disk_used=0, disk_total=0, disk_percent=0.0)

                # NET
                try:
                    net_lines = sections.get('NET', [])
                    net_val = next((l for l in net_lines if l), "0 0")
                    parts = net_val.split()
                    stats['net_rx'], stats['net_tx'] = int(parts[0]), int(parts[1])
                except Exception:
                    stats['net_rx'] = stats['net_tx'] = 0

                # UPTIME
                try:
                    uptime_lines = sections.get('UPTIME', [])
                    stats['uptime'] = " ".join([l for l in uptime_lines if l]).strip()
                except Exception:
                    stats['uptime'] = ""

                return stats
            finally:
                ssh.disconnect()

        return await asyncio.to_thread(_get_stats)
    except Exception as e:
        logger.exception("Error getting server stats")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/check', tags=["Servers"])
async def api_check_server(request: Request, server_id: int):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _check_server():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, 'awg2')
                status = {'connection': 'ok', 'docker_installed': manager.check_docker_installed(), 'protocols': {}}
                
                changed = False
                if 'protocols' not in server:
                    server['protocols'] = {}

                import concurrent.futures

                def check_proto(proto):
                    try:
                        p_manager = get_protocol_manager(ssh, proto)
                        result = _manager_call(p_manager, 'get_server_status', proto)
                        db_proto = server.get('protocols', {}).get(proto, {})
                        if not result.get('port') and db_proto.get('port'):
                            result['port'] = db_proto['port']
                        return proto, result, None
                    except Exception as e:
                        return proto, None, str(e)

                with concurrent.futures.ThreadPoolExecutor(max_workers=9) as executor:
                    futures = [executor.submit(check_proto, p) for p in ['awg2', 'telemt', 'dns', 'wireguard', 'socks5', 'adguard']]
                    for future in concurrent.futures.as_completed(futures):
                        proto, result, err = future.result()
                        if err:
                            status['protocols'][proto] = {'error': err}
                        else:
                            status['protocols'][proto] = result
                            if result.get('container_exists'):
                                if proto not in server['protocols']:
                                    server['protocols'][proto] = {
                                        'installed': True,
                                    'port': result.get('port', '55424'),
                                        'awg_params': result.get('awg_params', {})
                                    }
                                    changed = True
                            else:
                                if proto in server['protocols']:
                                    del server['protocols'][proto]
                                    changed = True
                        
                return status, changed
            finally:
                ssh.disconnect()

        status, changed = await asyncio.to_thread(_check_server)
        if changed:
            await db.update_server(server_id, server)
            
        return status
    except Exception as e:
        logger.exception("Error checking server")
        return JSONResponse({'error': str(e), 'connection': 'failed'}, status_code=500)


@app.post('/api/servers/{server_id}/install', tags=["Protocols"])
async def api_install_protocol(request: Request, server_id: int, req: InstallProtocolRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        if req.protocol not in ['awg2', 'telemt', 'dns', 'wireguard', 'socks5', 'adguard']:
            return JSONResponse({'error': 'Invalid protocol type'}, status_code=400)

        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _install_protocol():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)

                # Pass parameters to installer
                if req.protocol == 'telemt':
                    result = manager.install_protocol(
                        protocol_type=req.protocol,
                        port=req.port,
                        tls_emulation=req.tls_emulation if req.tls_emulation is not None else True,
                        tls_domain=req.tls_domain,
                        max_connections=req.max_connections if req.max_connections is not None else 0
                    )
                elif req.protocol == 'wireguard':
                    result = manager.install_protocol(port=req.port)
                elif req.protocol == 'socks5':
                    result = manager.install_protocol(
                        protocol_type='socks5',
                        port=req.port,
                        username=req.socks5_username,
                        password=req.socks5_password,
                    )
                elif req.protocol == 'adguard':
                    result = manager.install_protocol(
                        protocol_type='adguard',
                        mode=req.adguard_mode or 'sidebyside',
                        web_port=req.adguard_web_port,
                        expose_web=bool(req.adguard_expose_web),
                        dns_port=req.port,
                        dot_port=req.adguard_dot_port,
                        doh_port=req.adguard_doh_port,
                        expose_dns=bool(req.adguard_expose_dns),
                        expose_dot=bool(req.adguard_expose_dot),
                        expose_doh=bool(req.adguard_expose_doh),
                    )
                else:
                    result = manager.install_protocol(req.protocol, port=req.port)

                return result
            finally:
                ssh.disconnect()

        result = await asyncio.to_thread(_install_protocol)

        proto_record = {
            'installed': True,
            'port': req.port,
            'awg_params': result.get('awg_params', {}),
        }
        if req.protocol == 'adguard':
            proto_record['mode'] = result.get('mode')
            proto_record['internal_ip'] = result.get('internal_ip')
            proto_record['web_port'] = result.get('web_port')
            proto_record['expose_web'] = result.get('expose_web')
        server['protocols'][req.protocol] = proto_record
        await db.update_server(server_id, server)
        return result
    except Exception as e:
        logger.exception("Error installing protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/socks5/credentials', tags=["Protocols"])
async def api_socks5_get_credentials(request: Request, server_id: int):
    """Return the current SOCKS5 port/username/password for the panel UI."""
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _get_creds():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, 'socks5')
                return manager.get_credentials()
            finally:
                ssh.disconnect()

        creds = await asyncio.to_thread(_get_creds)
        return {'status': 'success', **creds}
    except Exception as e:
        logger.exception("Error reading SOCKS5 credentials")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/socks5/credentials', tags=["Protocols"])
async def api_socks5_update_credentials(request: Request, server_id: int, req: Socks5SettingsRequest):
    """Apply new SOCKS5 connection settings — regenerates the 3proxy config and
    reconciles the container (recreating it if the listening port changed)."""
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _update_creds():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, 'socks5')
                return manager.update_credentials(
                    port=req.port, username=req.username, password=req.password
                )
            finally:
                ssh.disconnect()

        result = await asyncio.to_thread(_update_creds)
        # Persist the new port in the saved server record so the dashboard
        # shows the right value on next check without an SSH round-trip.
        if result.get('status') == 'success' and result.get('port'):
            srv_proto = server.setdefault('protocols', {}).setdefault('socks5', {})
            srv_proto['port'] = str(result['port'])
            srv_proto['installed'] = True
            await db.update_server(server_id, server)
        return result
    except Exception as e:
        logger.exception("Error updating SOCKS5 credentials")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/uninstall', tags=["Protocols"])
async def api_uninstall_protocol(request: Request, server_id: int, req: ProtocolRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _uninstall():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                if req.protocol == 'wireguard':
                    manager.remove_container()
                else:
                    manager.remove_container(req.protocol)
            finally:
                ssh.disconnect()

        await asyncio.to_thread(_uninstall)

        if req.protocol in server.get('protocols', {}):
            del server['protocols'][req.protocol]
            await db.update_server(server_id, server)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error uninstalling protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


CONTAINER_NAMES = {
    'awg2': 'amnezia-awg2',
    'telemt': 'telemt',
    'dns': 'amnezia-dns',
    'wireguard': 'amnezia-wireguard',
    'socks5': 'amnezia-socks5proxy',
    'adguard': 'amnezia-adguard',
}

CONTAINER_NAMES_ALT = {
    'socks5': ['amnezia-socks5proxy', 'socks5'],
}


@app.post('/api/servers/{server_id}/container/toggle', tags=["Protocols"])
async def api_container_toggle(request: Request, server_id: int, req: ProtocolRequest):
    """Start or stop a protocol Docker container."""
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        container = CONTAINER_NAMES.get(req.protocol)
        if not container:
            return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _toggle():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                # Check current state — try primary name then legacy alternatives
                names_to_try = [container] + CONTAINER_NAMES_ALT.get(req.protocol, [])
                actual_name = None
                for name in names_to_try:
                    out, _, _ = ssh.run_sudo_command(
                        f"docker inspect -f '{{{{.State.Running}}}}' {name} 2>/dev/null"
                    )
                    if out.strip():
                        actual_name = name
                        break
                if not actual_name:
                    return {'error': f'Container {container} not found'}
                is_running = out.strip().lower() == 'true'
                if is_running:
                    ssh.run_sudo_command(f"docker stop {actual_name}")
                    action = 'stopped'
                else:
                    ssh.run_sudo_command(f"docker start {actual_name}")
                    action = 'started'
                return {'status': 'success', 'action': action, 'container': actual_name}
            finally:
                ssh.disconnect()

        result = await asyncio.to_thread(_toggle)
        if 'error' in result:
            return JSONResponse({'error': result['error']}, status_code=404)
        return result
    except Exception as e:
        logger.exception("Error toggling container")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/server_config', tags=["Protocols"])
async def api_server_config(request: Request, server_id: int, req: ProtocolRequest):
    """Get the raw server-side WireGuard/Xray configuration."""
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _get_config():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                if req.protocol == 'telemt':
                    from managers.telemt_manager import TelemtManager
                    mgr = TelemtManager(ssh)
                    config = mgr._get_server_config()
                elif req.protocol == 'wireguard':
                    from managers.wireguard_manager import WireGuardManager
                    mgr = WireGuardManager(ssh)
                    config = mgr._get_server_config()
                else:
                    mgr = AWGManager(ssh)
                    config = mgr._get_server_config(req.protocol)
                return config
            finally:
                ssh.disconnect()

        config = await asyncio.to_thread(_get_config)
        return {'config': config}
    except Exception as e:
        logger.exception("Error getting server config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/server_config/save', tags=["Protocols"])
async def api_server_config_save(request: Request, server_id: int, req: ServerConfigSaveRequest):
    """Save the raw server-side WireGuard/Xray configuration and apply changes."""
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        def _save_config():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                if req.protocol == 'telemt':
                    from managers.telemt_manager import TelemtManager
                    mgr = TelemtManager(ssh)
                    mgr.save_server_config(req.protocol, req.config)
                elif req.protocol == 'wireguard':
                    from managers.wireguard_manager import WireGuardManager
                    mgr = WireGuardManager(ssh)
                    mgr.save_server_config(req.config)
                else:
                    mgr = AWGManager(ssh)
                    mgr.save_server_config(req.protocol, req.config)
            finally:
                ssh.disconnect()

        await asyncio.to_thread(_save_config)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error saving server config")
        return JSONResponse({'error': str(e)}, status_code=500)




@app.get('/api/servers/{server_id}/connections', tags=["Connections"])
async def api_get_connections(request: Request, server_id: int, protocol: str = Query(default='awg2')):
    if not protocol:
        protocol = 'awg2'
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        from managers.cache import ssh_cache
        cached_clients = await ssh_cache.get_clients(server_id, protocol)
        if cached_clients is not None:
            clients = cached_clients
        else:
            def _get_connections():
                ssh = get_ssh(server)
                ssh.connect()
                try:
                    manager = get_protocol_manager(ssh, protocol)
                    clients = _manager_call(manager, 'get_clients', protocol)
                    return clients
                finally:
                    ssh.disconnect()

            clients = await asyncio.to_thread(_get_connections)
            await ssh_cache.set_clients(server_id, protocol, clients)

        # Enrich with user info from user_connections
        user_conns = await db.get_server_connections(server_id, protocol)
        all_users = await db.get_users()
        users_map = {u['id']: u for u in all_users}
        for client in clients:
            cid = client.get('clientId', '')
            for uc in user_conns:
                if uc.get('client_id') == cid and uc.get('protocol') == protocol:
                    uid = uc.get('user_id')
                    u = users_map.get(uid)
                    if u:
                        client['assigned_user'] = u['username']
                        client['assigned_user_id'] = uid
                    break
        return {'clients': clients}
    except Exception as e:
        logger.exception("Error getting connections")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/add', tags=["Connections"])
async def api_add_connection(request: Request, server_id: int, req: AddConnectionRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')

        def _add_connection():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                
                if req.protocol == 'telemt':
                    result = manager.add_client(
                        req.protocol, req.name, server['host'], port,
                        telemt_quota=req.telemt_quota,
                        telemt_max_ips=req.telemt_max_ips,
                        telemt_expiry=req.telemt_expiry,
                        secret=req.telemt_secret,
                        user_ad_tag=req.telemt_ad_tag,
                        max_tcp_conns=req.telemt_max_conns
                    )
                elif req.protocol == 'wireguard':
                    result = manager.add_client(req.name, server['host'])
                else:
                    result = manager.add_client(req.protocol, req.name, server['host'], port)
                return result
            finally:
                ssh.disconnect()

        result = await asyncio.to_thread(_add_connection)

        if result.get('config'):
            result['vpn_link'] = generate_vpn_link(result['config'])

        # Link connection to user if specified
        if req.user_id and result.get('client_id'):
            conn = {
                'id': str(uuid.uuid4()),
                'user_id': req.user_id,
                'server_id': server_id,
                'protocol': req.protocol,
                'client_id': result['client_id'],
                'name': req.name,
                'created_at': datetime.now().isoformat(),
            }
            await db.add_connection(conn)

        # Invalidate cache
        from managers.cache import ssh_cache
        await ssh_cache.invalidate(server_id, req.protocol)

        return result
    except Exception as e:
        logger.exception("Error adding connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/remove', tags=["Connections"])
async def api_remove_connection(request: Request, server_id: int, req: ConnectionActionRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)

        def _remove_connection():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                _manager_call(manager, 'remove_client', req.protocol, req.client_id)
            finally:
                ssh.disconnect()

        await asyncio.to_thread(_remove_connection)

        # Remove from user_connections
        conns = await db.get_server_connections(server_id, req.protocol)
        for c in conns:
            if c.get('client_id') == req.client_id:
                await db.delete_connection(c['id'])

        # Invalidate cache
        from managers.cache import ssh_cache
        await ssh_cache.invalidate(server_id, req.protocol)

        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error removing connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/edit', tags=["Connections"])
async def api_edit_connection(request: Request, server_id: int, req: EditConnectionRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        
        def _edit_connection():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                
                edit_params = {}
                if req.protocol == 'telemt':
                    edit_params['telemt_quota'] = req.telemt_quota
                    edit_params['telemt_max_ips'] = req.telemt_max_ips
                    edit_params['telemt_expiry'] = req.telemt_expiry
                    edit_params['secret'] = req.telemt_secret
                    edit_params['user_ad_tag'] = req.telemt_ad_tag
                    edit_params['max_tcp_conns'] = req.telemt_max_conns
                    
                result = manager.edit_client(req.protocol, req.client_id, edit_params)
                return result
            finally:
                ssh.disconnect()

        result = await asyncio.to_thread(_edit_connection)

        # Invalidate cache
        from managers.cache import ssh_cache
        await ssh_cache.invalidate(server_id, req.protocol)

        return result
    except Exception as e:
        logger.exception("Error editing connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/config', tags=["Connections"])
async def api_get_connection_config(request: Request, server_id: int, req: ConnectionActionRequest):
    user = await get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        # Users can only view their own connections
        if user['role'] == 'user':
            owned = await db.get_connection_by_client(server_id, req.protocol, req.client_id)
            if not owned or owned.get('user_id') != user['id']:
                return JSONResponse({'error': 'Forbidden'}, status_code=403)
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')

        def _get_config():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                if req.protocol == 'wireguard':
                    config = manager.get_client_config(req.client_id, server['host'])
                else:
                    config = manager.get_client_config(req.protocol, req.client_id, server['host'], port)
                return config
            finally:
                ssh.disconnect()

        config = await asyncio.to_thread(_get_config)
        vpn_link = generate_vpn_link(config) if config else ''
        return {'config': config, 'vpn_link': vpn_link}
    except Exception as e:
        logger.exception("Error getting connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/toggle', tags=["Connections"])
async def api_toggle_connection(request: Request, server_id: int, req: ToggleConnectionRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)

        def _toggle_connection():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                _manager_call(manager, 'toggle_client', req.protocol, req.client_id, req.enable)
            finally:
                ssh.disconnect()

        await asyncio.to_thread(_toggle_connection)

        # Invalidate cache
        from managers.cache import ssh_cache
        await ssh_cache.invalidate(server_id, req.protocol)

        status = 'enabled' if req.enable else 'disabled'
        return {'status': 'success', 'enabled': req.enable, 'message': f'Connection {status}'}
    except Exception as e:
        logger.exception("Error toggling connection")
        return JSONResponse({'error': str(e)}, status_code=500)


# ======================== USER API (admin only) ========================

@app.get('/api/users', tags=["Users"])
async def api_list_users(request: Request, search: str = '', page: int = 1, size: int = 10):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    all_users = await db.get_users()
    conns = await db.get_user_connections()
    
    # Filter
    filtered = []
    search = search.lower()
    for u in all_users:
        if search:
            match = (search in u['username'].lower() or 
                     (u.get('email') and search in u['email'].lower()) or 
                     (u.get('telegramId') and search in str(u['telegramId']).lower()))
            if not match:
                continue
        filtered.append(u)
        
    total = len(filtered)
    start = (page - 1) * size
    end = start + size
    page_items = filtered[start:end]
    
    users = []
    for u in page_items:
        users.append({
            'id': u['id'], 'username': u['username'], 'role': u['role'],
            'enabled': u.get('enabled', True),
            'created_at': u.get('created_at', ''),
            'telegramId': u.get('telegramId'),
            'email': u.get('email'),
            'description': u.get('description'),
            'connections_count': sum(1 for c in conns if c['user_id'] == u['id']),
            'traffic_used': u.get('traffic_used', 0),
            'traffic_total': u.get('traffic_total', 0),
            'traffic_limit': u.get('traffic_limit', 0),
            'traffic_reset_strategy': u.get('traffic_reset_strategy', 'never'),
            'last_reset_at': u.get('last_reset_at'),
            "expiration_date": u.get("expiration_date"),
            'share_enabled': u.get('share_enabled', False),
            'share_token': u.get('share_token'),
            'has_share_password': bool(u.get('share_password_hash')),
            'source': 'Local'
        })
    return {
        'users': users,
        'total': total,
        'page': page,
        'size': size,
        'pages': (total + size - 1) // size
    }


@app.post('/api/users/add', tags=["Users"])
async def api_add_user(request: Request, req: AddUserRequest):
    cur = await get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        lang = request.cookies.get('lang', 'ru')
        # Check duplicate
        existing = await db.get_user_by_username(req.username)
        if existing:
            return JSONResponse({'error': _t('user_exists', lang)}, status_code=400)
        if req.role not in ('admin', 'support', 'user'):
            return JSONResponse({'error': 'Invalid role'}, status_code=400)
        new_user = {
            'id': str(uuid.uuid4()),
            'username': req.username,
            'password_hash': await asyncio.to_thread(hash_password, req.password),
            'role': req.role,
            'telegramId': req.telegramId,
            'email': req.email,
            'description': req.description,
            'traffic_limit': int(req.traffic_limit * 1024**3) if req.traffic_limit else 0,
            'traffic_reset_strategy': req.traffic_reset_strategy or 'never',
            'traffic_used': 0,
            'traffic_total': 0,
            'last_reset_at': datetime.now().isoformat(),
            'expiration_date': req.expiration_date,
            'enabled': True,
            'created_at': datetime.now().isoformat(),
            'share_enabled': False,
            'share_token': secrets.token_urlsafe(16),
            'share_password_hash': None,
        }
        await db.add_user(new_user)

        result = {'status': 'success', 'user_id': new_user['id']}

        # Auto-create connection if server & protocol specified
        if req.server_id is not None and req.protocol:
            server = await db.get_server(req.server_id)
            if server:
                proto_info = server.get('protocols', {}).get(req.protocol, {})
                port = proto_info.get('port', '55424')
                conn_name = req.connection_name or f"{req.username}_vpn"
                ssh = get_ssh(server)
                ssh.connect()
                manager = get_protocol_manager(ssh, req.protocol)
                if req.protocol == 'telemt':
                    conn_result = manager.add_client(
                        req.protocol, conn_name, server['host'], port,
                        telemt_quota=req.telemt_quota,
                        telemt_max_ips=req.telemt_max_ips,
                        telemt_expiry=req.telemt_expiry,
                        secret=req.telemt_secret,
                        user_ad_tag=req.telemt_ad_tag,
                        max_tcp_conns=req.telemt_max_conns
                    )
                else:
                    conn_result = manager.add_client(req.protocol, conn_name, server['host'], port)
                ssh.disconnect()

                if conn_result.get('client_id'):
                    conn = {
                        'id': str(uuid.uuid4()),
                        'user_id': new_user['id'],
                        'server_id': req.server_id,
                        'protocol': req.protocol,
                        'client_id': conn_result['client_id'],
                        'name': conn_name,
                        'created_at': datetime.now().isoformat(),
                    }
                    await db.add_connection(conn)
                    result['connection_created'] = True
                    if conn_result.get('config'):
                        result['config'] = conn_result['config']
                        result['vpn_link'] = generate_vpn_link(conn_result['config'])
        return result
    except Exception as e:
        logger.exception("Error adding user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/update', tags=["Users"])
async def api_update_user(request: Request, user_id: str, req: UpdateUserRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        user = await db.get_user(user_id)
        if not user:
            return JSONResponse({'error': 'User not found'}, status_code=404)
            
        if req.telegramId is not None:
            user['telegramId'] = req.telegramId
        if req.email is not None:
            user['email'] = req.email
        if req.description is not None:
            user['description'] = req.description
        if req.traffic_limit is not None: 
            new_limit = int(req.traffic_limit * 1024**3)
            user['traffic_limit'] = new_limit
        
        if req.traffic_reset_strategy is not None:
            user['traffic_reset_strategy'] = req.traffic_reset_strategy
            user['last_reset_at'] = datetime.now().isoformat()
            
        if req.expiration_date is not None:
            user['expiration_date'] = req.expiration_date or None

        if req.password:
            user['password_hash'] = await asyncio.to_thread(hash_password, req.password)
            
        await db.update_user(user)
        
        # Auto re-enable if traffic limit increased beyond usage
        if req.traffic_limit is not None:
            if new_limit > 0 and user.get('traffic_used', 0) < new_limit and not user.get('enabled', True):
                await perform_toggle_user(user_id, True)

        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error updating user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/delete', tags=["Users"])
async def api_delete_user(request: Request, user_id: str):
    cur = await get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    lang = request.cookies.get('lang', 'ru')
    if cur['id'] == user_id:
        return JSONResponse({'error': _t('cannot_delete_self', lang)}, status_code=400)
    try:
        success = await perform_delete_user(user_id)
        if not success:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error deleting user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/toggle', tags=["Users"])
async def api_toggle_user(request: Request, user_id: str, req: ToggleUserRequest):
    cur = await get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        success = await perform_toggle_user(user_id, req.enabled)
        if not success:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        return {'status': 'success', 'enabled': req.enabled}
    except Exception as e:
        logger.exception("Error toggling user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/connections/add', tags=["Users"])
async def api_add_user_connection(request: Request, user_id: str, req: AddUserConnectionRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        user = await db.get_user(user_id)
        if not user:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        server = await db.get_server(req.server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        await asyncio.to_thread(ssh.connect)
        manager = get_protocol_manager(ssh, req.protocol)
        
        if req.client_id:
            target_client_id = req.client_id
            config = await asyncio.to_thread(manager.get_client_config, req.protocol, req.client_id, server['host'], port)
            result = {'client_id': target_client_id, 'config': config}
        else:
            if req.protocol == 'telemt':
                result = await asyncio.to_thread(
                    manager.add_client, req.protocol, req.name, server['host'], port,
                    telemt_quota=req.telemt_quota,
                    telemt_max_ips=req.telemt_max_ips,
                    telemt_expiry=req.telemt_expiry,
                    secret=req.telemt_secret,
                    user_ad_tag=req.telemt_ad_tag,
                    max_tcp_conns=req.telemt_max_conns
                )
            else:
                result = await asyncio.to_thread(manager.add_client, req.protocol, req.name, server['host'], port)
        
        await asyncio.to_thread(ssh.disconnect)

        if result.get('client_id'):
            conn = {
                'id': str(uuid.uuid4()),
                'user_id': user_id,
                'server_id': req.server_id,
                'protocol': req.protocol,
                'client_id': result['client_id'],
                'name': req.name,
                'created_at': datetime.now().isoformat(),
            }
            await db.add_connection(conn)

        # Invalidate cache
        from managers.cache import ssh_cache
        await ssh_cache.invalidate(req.server_id, req.protocol)

        resp = {'status': 'success'}
        if result.get('config'):
            resp['config'] = result['config']
            resp['vpn_link'] = generate_vpn_link(result['config'])
        return resp
    except Exception as e:
        logger.exception("Error adding user connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/users/{user_id}/connections', tags=["Users"])
async def api_get_user_connections(request: Request, user_id: str):
    user = await get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if user['role'] == 'user' and user['id'] != user_id:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    conns = await db.get_user_connections(user_id)
    servers_map = {s['server_id']: s for s in await db.get_servers()}
    for c in conns:
        sid = c.get('server_id', 0)
        srv = servers_map.get(sid)
        c['server_name'] = srv.get('name', '') if srv else 'Unknown'
    return {'connections': conns}


# ======================== MY CONNECTIONS API (for user role) ========================

@app.get('/api/my/connections', tags=["Self-service"])
async def api_my_connections(request: Request):
    user = await get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    conns = await db.get_user_connections(user['id'])
    servers_map = {s['server_id']: s for s in await db.get_servers()}
    for c in conns:
        sid = c.get('server_id', 0)
        srv = servers_map.get(sid)
        c['server_name'] = srv.get('name', '') if srv else 'Unknown'
    return {'connections': conns}


@app.post('/api/users/{user_id}/share/setup', tags=["Users"])
async def api_user_share_setup(user_id: str, req: ShareSetupRequest, request: Request):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    user = await db.get_user(user_id)
    if not user:
        return JSONResponse({'error': 'User not found'}, status_code=404)
    
    user['share_enabled'] = req.enabled
    if not user.get('share_token'):
        user['share_token'] = secrets.token_urlsafe(16)
    if req.password:
        user['share_password_hash'] = await asyncio.to_thread(hash_password, req.password)
    elif req.password == "":
        user['share_password_hash'] = None
        
    await db.update_user(user)
    return {'status': 'success', 'share_token': user.get('share_token')}


@app.get('/share/{token}', response_class=HTMLResponse, tags=["System Templates"])
async def share_page(token: str, request: Request):
    users = await db.get_users()
    user = next((u for u in users if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        lang = request.cookies.get('lang', 'ru')
        return HTMLResponse(f"<h1>{_t('share_not_found', lang)}</h1><p>{_t('share_not_found_desc', lang)}</p>", status_code=404)
    
    auth_session_key = f'share_auth_{token}'
    need_password = bool(user.get('share_password_hash')) and not request.session.get(auth_session_key)
    
    return await tpl(request, 'user_share.html', 
               share_user=user, 
               need_password=need_password, 
               token=token)


@app.post('/api/share/{token}/auth', tags=["Sharing"])
async def api_share_auth(token: str, req: ShareAuthRequest, request: Request):
    users = await db.get_users()
    user = next((u for u in users if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Link expired or disabled'}, status_code=404)
    
    if await asyncio.to_thread(verify_password, req.password, user.get('share_password_hash', '')):
        request.session[f'share_auth_{token}'] = True
        return {'status': 'success'}
    else:
        lang = request.cookies.get('lang', 'ru')
        return JSONResponse({'error': _t('wrong_share_password', lang)}, status_code=401)


@app.get('/api/share/{token}/connections', tags=["Sharing"])
async def api_share_connections(token: str, request: Request):
    users = await db.get_users()
    user = next((u for u in users if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    
    if user.get('share_password_hash'):
        if not request.session.get(f'share_auth_{token}'):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
            
    conns = await db.get_user_connections(user['id'])
    servers_map = {s['server_id']: s for s in await db.get_servers()}
    for c in conns:
        sid = c['server_id']
        srv = servers_map.get(sid)
        c['server_name'] = (srv.get('name') or srv['host']) if srv else 'Unknown'
            
    return {'connections': conns, 'username': user['username']}


@app.post('/api/share/{token}/config/{connection_id}', tags=["Sharing"])
async def api_share_config(token: str, connection_id: str, request: Request):
    users = await db.get_users()
    user = next((u for u in users if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    
    if user.get('share_password_hash'):
        if not request.session.get(f'share_auth_{token}'):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
            
    conns = await db.get_user_connections(user['id'])
    conn = next((c for c in conns if c['id'] == connection_id), None)
    if not conn:
        return JSONResponse({'error': 'Not found'}, status_code=404)
        
    try:
        sid = conn['server_id']
        server = await db.get_server(sid)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        proto_info = server.get('protocols', {}).get(conn['protocol'], {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, conn['protocol'])
        config = manager.get_client_config(conn['protocol'], conn['client_id'], server['host'], port)
        ssh.disconnect()
        vpn_link = generate_vpn_link(config) if config else ''
        return {'config': config, 'vpn_link': vpn_link}
    except Exception as e:
        logger.exception("Error getting shared config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/my/connections/{connection_id}/config', tags=["Self-service"])
async def api_my_connection_config(request: Request, connection_id: str):
    user = await get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        conns = await db.get_user_connections(user['id'])
        conn = next((c for c in conns if c['id'] == connection_id), None)
        if not conn:
            return JSONResponse({'error': 'Connection not found'}, status_code=404)
        sid = conn['server_id']
        server = await db.get_server(sid)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        proto_info = server.get('protocols', {}).get(conn['protocol'], {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, conn['protocol'])
        config = manager.get_client_config(conn['protocol'], conn['client_id'], server['host'], port)
        ssh.disconnect()
        vpn_link = generate_vpn_link(config) if config else ''
        return {'config': config, 'vpn_link': vpn_link}
    except Exception as e:
        logger.exception("Error getting my connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/settings', tags=["System Templates"])
async def settings_page(request: Request):
    user = await _check_admin(request)
    if not user:
        return RedirectResponse('/login')
    settings = await db.get_all_settings()
    return await tpl(request, 'settings.html', settings=settings, current_version=CURRENT_VERSION)


@app.get('/api/settings', tags=["Settings"])
async def api_get_settings(request: Request):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    return await db.get_all_settings()


@app.post('/api/settings/save', tags=["Settings"])
async def save_settings(request: Request, payload: SaveSettingsRequest):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    settings = await db.get_all_settings()
    settings['appearance'] = payload.appearance.model_dump()
    settings['captcha'] = payload.captcha.model_dump()
    settings['telegram'] = payload.telegram.model_dump()
    settings['ssl'] = payload.ssl.model_dump()
    await db.set_all_settings(settings)
    logger.info("Settings saved (including captcha and telegram)")

    # Handle bot start/stop based on new telegram settings
    tg_cfg = payload.telegram
    if tg_cfg.enabled and tg_cfg.token:
        if not tg_bot.is_running():
            logger.info("Starting Telegram bot (settings save)...")
            tg_bot.launch_bot(tg_cfg.token, _get_telegram_data_fn, generate_vpn_link)
    else:
        if tg_bot.is_running():
            logger.info("Stopping Telegram bot (settings save)...")
            asyncio.create_task(tg_bot.stop_bot())

    return {"status": "success", "bot_running": tg_bot.is_running()}


@app.post('/api/settings/telegram/toggle', tags=["Settings"])
async def api_telegram_toggle(request: Request):
    """Quick enable/disable of the bot without a full settings save."""
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    tg_cfg = await db.get_setting('telegram', {})
    token = tg_cfg.get('token', '')
    if not token:
        return JSONResponse({'error': 'Telegram token not set in settings'}, status_code=400)

    if tg_bot.is_running():
        await tg_bot.stop_bot()
        tg_cfg['enabled'] = False
        await db.set_setting('telegram', tg_cfg)
        return {'status': 'stopped', 'bot_running': False}
    else:
        tg_bot.launch_bot(token, _get_telegram_data_fn, generate_vpn_link)
        tg_cfg['enabled'] = True
        await db.set_setting('telegram', tg_cfg)
        return {'status': 'started', 'bot_running': True}


@app.get('/api/servers/{server_id}/{protocol}/clients', tags=["Connections"])
async def api_get_server_clients(request: Request, server_id: int, protocol: str):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        server = await db.get_server(server_id)
        if not server:
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        clients = manager.get_clients(protocol)
        ssh.disconnect()
        
        # Filter: only show clients that are not assigned to anyone in the panel
        server_conns = await db.get_server_connections(server_id, protocol)
        assigned_ids = {c['client_id'] for c in server_conns}
        
        filtered = []
        for c in clients:
            if c['clientId'] not in assigned_ids:
                filtered.append({
                    'id': c['clientId'],
                    'name': c.get('userData', {}).get('clientName', 'Unnamed')
                })
        
        return {'clients': filtered}
    except Exception as e:
        logger.exception("Error getting server clients")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/settings/tokens', tags=["API Tokens"])
async def api_list_tokens(request: Request):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    tokens = await db.get_api_tokens()
    all_users = await db.get_users()
    users_by_id = {u['id']: u for u in all_users}
    result = []
    for t in tokens:
        owner = users_by_id.get(t.get('user_id'))
        result.append({
            'id': t.get('id'),
            'name': t.get('name', ''),
            'token_prefix': t.get('token_prefix', ''),
            'created_at': t.get('created_at'),
            'last_used_at': t.get('last_used_at'),
            'owner': owner['username'] if owner else None,
            'owner_id': t.get('user_id'),
        })
    return {'tokens': result}


@app.post('/api/settings/tokens', tags=["API Tokens"])
async def api_create_token(request: Request, req: CreateApiTokenRequest):
    cur = await _check_admin(request)
    if not cur:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    name = (req.name or '').strip()
    if not name:
        return JSONResponse({'error': 'Token name is required'}, status_code=400)

    raw = _generate_api_token()
    token_id = str(uuid.uuid4())
    token_prefix = raw[:len(API_TOKEN_PREFIX) + 4]

    entry = {
        'id': token_id,
        'name': name,
        'token_hash': _hash_api_token(raw),
        'token_prefix': token_prefix,
        'user_id': cur['id'],
        'created_at': datetime.now().isoformat(),
        'last_used_at': None,
    }
    tokens = await db.get_api_tokens()
    tokens.append(entry)
    await db.set_api_tokens(tokens)

    return {
        'status': 'success',
        'id': token_id,
        'name': name,
        'token': raw,
        'token_prefix': token_prefix,
        'created_at': entry['created_at'],
    }


@app.delete('/api/settings/tokens/{token_id}', tags=["API Tokens"])
async def api_revoke_token(request: Request, token_id: str):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    tokens = await db.get_api_tokens()
    before = len(tokens)
    tokens = [t for t in tokens if t.get('id') != token_id]
    if len(tokens) == before:
        return JSONResponse({'error': 'Token not found'}, status_code=404)
    await db.set_api_tokens(tokens)
    return {'status': 'success'}


@app.get('/api/settings/backup/download', tags=["Settings"])
async def api_backup_download(request: Request):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not os.path.exists(DB_PATH):
        return JSONResponse({'error': 'Database file not found'}, status_code=404)
    return FileResponse(DB_PATH, media_type='application/octet-stream', filename='panel.db')


@app.post('/api/settings/backup/restore', tags=["Settings"])
async def api_backup_restore(request: Request, file: UploadFile = File(...)):
    if not await _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        content = await file.read()
        if not content:
            return JSONResponse({'error': 'Empty file'}, status_code=400)

        # Validate it's a SQLite file (starts with SQLite format header)
        if content[:16] != b'SQLite format 3\x00':
            return JSONResponse({'error': 'Not a valid SQLite database file'}, status_code=400)

        # Close current connection, write new DB, reinitialize
        await db.close_db()
        with open(DB_PATH, 'wb') as f:
            f.write(content)
        await db.init_db(DB_PATH)

        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error during restore")
        return JSONResponse({'error': str(e)}, status_code=500)


if __name__ == '__main__':
    import asyncio as _asyncio
    
    async def _get_ssl_config():
        await db.init_db(DB_PATH)
        settings = await db.get_all_settings()
        return settings.get('ssl', {})
    
    ssl_conf = _asyncio.run(_get_ssl_config())
    
    cert_file = ssl_conf.get('cert_path')
    key_file = ssl_conf.get('key_path')
    
    # If text is provided, create temporary files
    temp_dir = os.path.join(os.getcwd(), 'ssl_temp')
    if ssl_conf.get('enabled'):
        if ssl_conf.get('cert_text') or ssl_conf.get('key_text'):
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            if ssl_conf.get('cert_text'):
                cert_file = os.path.join(temp_dir, 'cert.pem')
                with open(cert_file, 'w') as f:
                    f.write(ssl_conf['cert_text'].strip() + '\n')
            
            if ssl_conf.get('key_text'):
                key_file = os.path.join(temp_dir, 'key.pem')
                with open(key_file, 'w') as f:
                    f.write(ssl_conf['key_text'].strip() + '\n')

    uvicorn_kwargs = {
        "app": app,
        "host": "0.0.0.0",
        "port": ssl_conf.get('panel_port', 8000)
    }
    
    if ssl_conf.get('enabled') and cert_file and key_file:
        if os.path.exists(cert_file) and os.path.exists(key_file):
            logger.info(f"Starting panel with HTTPS enabled on domain: {ssl_conf.get('domain')} at port {uvicorn_kwargs['port']}")
            uvicorn_kwargs["ssl_certfile"] = cert_file
            uvicorn_kwargs["ssl_keyfile"] = key_file
        else:
            logger.error("SSL certificates not found at specified paths. Starting with HTTP.")

    uvicorn.run(**uvicorn_kwargs)
