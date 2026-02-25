import base64
import copy
import hashlib
import hmac
import json
import os
import threading
import uuid
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash


ADMIN_ROLE_STANDARD = 'admin'
ADMIN_ROLE_GOLD = 'gold'

ADMIN_GOLD_USERNAME_ENV = 'ADMIN_GOLD_USERNAME'
ADMIN_GOLD_NAME_ENV = 'ADMIN_GOLD_NAME'
ADMIN_GOLD_PASSWORD_ENV = 'ADMIN_GOLD_PASSWORD'

DEFAULT_GOLD_USERNAME = 'ami_nope'
DEFAULT_GOLD_NAME = 'AMIYA'
DEFAULT_GOLD_PASSWORD = 'AMIYA'
DEFAULT_GOLD_PASSWORD_LEGACY = '456789'

PIN_ADMIN_LOGIN = 'admin_login_pin'
PIN_GOLD_LOGIN = 'gold_login_pin'
DEFAULT_LOGIN_PINS = {
    PIN_ADMIN_LOGIN: '456123',
    PIN_GOLD_LOGIN: '456789',
}

_CACHE_LOCK = threading.Lock()
_NON_GOLD_CACHE = []
_CACHE_MTIME = None
_CACHE_READY = False
_STORAGE_MODE = None  # 'plain' | 'encrypted'
_STORAGE_PATH = None

_PERMANENT_CACHE_LOCK = threading.Lock()
_PERMANENT_CACHE = []
_PERMANENT_CACHE_MTIME = None
_PERMANENT_CACHE_READY = False
_PERMANENT_STORAGE_PATH = None


def _project_root():
    return Path(__file__).resolve().parent.parent


def _gold_username():
    return str(os.environ.get(ADMIN_GOLD_USERNAME_ENV, DEFAULT_GOLD_USERNAME) or DEFAULT_GOLD_USERNAME).strip() or DEFAULT_GOLD_USERNAME


def _gold_name():
    return str(os.environ.get(ADMIN_GOLD_NAME_ENV, DEFAULT_GOLD_NAME) or DEFAULT_GOLD_NAME).strip() or DEFAULT_GOLD_NAME


def _gold_password():
    return str(os.environ.get(ADMIN_GOLD_PASSWORD_ENV, DEFAULT_GOLD_PASSWORD) or DEFAULT_GOLD_PASSWORD)


def _gold_password_candidates():
    configured = str(os.environ.get(ADMIN_GOLD_PASSWORD_ENV) or '').strip()
    candidates = []
    if configured:
        candidates.append(configured)
    for fallback in (DEFAULT_GOLD_PASSWORD, DEFAULT_GOLD_PASSWORD_LEGACY):
        val = str(fallback or '')
        if val and val not in candidates:
            candidates.append(val)
    return candidates


def _admin_secret():
    src = str(
        os.environ.get('ADMIN_CREDENTIALS_SECRET')
        or os.environ.get('FLASK_SECRET')
        or 'admin-credentials-dev-secret'
    )
    return hashlib.sha256(src.encode('utf-8')).digest()


def _xor_bytes(data_bytes, key_bytes):
    key_len = len(key_bytes)
    return bytes(data_bytes[i] ^ key_bytes[i % key_len] for i in range(len(data_bytes)))


def _encrypt_payload(data_obj):
    body = json.dumps(data_obj, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    key = _admin_secret()
    cipher = _xor_bytes(body, key)
    mac = hmac.new(key, cipher, hashlib.sha256).hexdigest()
    envelope = {
        'v': 1,
        'mac': mac,
        'data': base64.b64encode(cipher).decode('ascii'),
    }
    return json.dumps(envelope, separators=(',', ':')).encode('utf-8')


def _decrypt_payload(raw_bytes):
    if not raw_bytes:
        return {'admins': []}
    envelope = json.loads(raw_bytes.decode('utf-8'))
    if not isinstance(envelope, dict):
        return {'admins': []}
    data_b64 = str(envelope.get('data') or '')
    mac = str(envelope.get('mac') or '')
    if not data_b64 or not mac:
        return {'admins': []}
    cipher = base64.b64decode(data_b64.encode('ascii'))
    key = _admin_secret()
    expected = hmac.new(key, cipher, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError('admin_credentials_integrity_check_failed')
    plain = _xor_bytes(cipher, key)
    payload = json.loads(plain.decode('utf-8'))
    return payload if isinstance(payload, dict) else {'admins': []}


def _path_exists_and_usable(path_obj):
    try:
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        probe = path_obj.parent / f'.admin_probe_{uuid.uuid4().hex}'
        probe.write_text('ok', encoding='utf-8')
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _resolve_storage():
    global _STORAGE_MODE, _STORAGE_PATH
    if _STORAGE_PATH is not None and _STORAGE_MODE is not None:
        return _STORAGE_PATH, _STORAGE_MODE

    preferred = Path('/var/data/admin_credentials.json')
    if _path_exists_and_usable(preferred):
        _STORAGE_PATH = preferred
        _STORAGE_MODE = 'plain'
        return _STORAGE_PATH, _STORAGE_MODE

    fallback = _project_root() / 'admin_credentials.enc'
    fallback.parent.mkdir(parents=True, exist_ok=True)
    _STORAGE_PATH = fallback
    _STORAGE_MODE = 'encrypted'
    return _STORAGE_PATH, _STORAGE_MODE


def _resolve_permanent_storage():
    global _PERMANENT_STORAGE_PATH
    if _PERMANENT_STORAGE_PATH is not None:
        return _PERMANENT_STORAGE_PATH
    preferred = Path('/var/data/permanent_admins.enc')
    if _path_exists_and_usable(preferred):
        _PERMANENT_STORAGE_PATH = preferred
        return _PERMANENT_STORAGE_PATH
    fallback = _project_root() / 'permanent_admins.enc'
    fallback.parent.mkdir(parents=True, exist_ok=True)
    _PERMANENT_STORAGE_PATH = fallback
    return _PERMANENT_STORAGE_PATH


def _read_payload_from_storage():
    path_obj, mode = _resolve_storage()
    if not path_obj.exists():
        return {'admins': []}
    try:
        if mode == 'plain':
            with path_obj.open('r', encoding='utf-8') as f:
                parsed = json.load(f)
                return parsed if isinstance(parsed, dict) else {'admins': []}
        with path_obj.open('rb') as f:
            return _decrypt_payload(f.read())
    except Exception:
        return {'admins': []}


def _read_permanent_payload_from_storage():
    path_obj = _resolve_permanent_storage()
    if not path_obj.exists():
        return {'admins': []}
    try:
        with path_obj.open('rb') as f:
            return _decrypt_payload(f.read())
    except Exception:
        return {'admins': []}


def _atomic_write_bytes(path_obj, body_bytes):
    tmp = path_obj.with_name(f'{path_obj.name}.{uuid.uuid4().hex}.tmp')
    with tmp.open('wb') as f:
        f.write(body_bytes)
    os.replace(str(tmp), str(path_obj))


def _write_payload_to_storage(payload):
    path_obj, mode = _resolve_storage()
    safe_payload = payload if isinstance(payload, dict) else {'admins': []}
    if mode == 'plain':
        text = json.dumps(safe_payload, indent=2, ensure_ascii=True)
        _atomic_write_bytes(path_obj, text.encode('utf-8'))
        return
    encrypted = _encrypt_payload(safe_payload)
    _atomic_write_bytes(path_obj, encrypted)


def _write_permanent_payload_to_storage(payload):
    path_obj = _resolve_permanent_storage()
    safe_payload = payload if isinstance(payload, dict) else {'admins': []}
    encrypted = _encrypt_payload(safe_payload)
    _atomic_write_bytes(path_obj, encrypted)


def _normalize_role(raw_role):
    role = str(raw_role or ADMIN_ROLE_STANDARD).strip().lower()
    return ADMIN_ROLE_GOLD if role == ADMIN_ROLE_GOLD else ADMIN_ROLE_STANDARD


def _normalize_permanent_admin_entry(raw):
    if not isinstance(raw, dict):
        return None
    username = str(raw.get('username') or '').strip()
    if not username:
        return None
    if username == _gold_username():
        return None
    display_name = str(raw.get('display_name') or username).strip() or username
    password_hash = str(raw.get('password_hash') or '').strip()
    if not password_hash:
        legacy_pw = str(raw.get('password') or raw.get('password_plain') or '').strip()
        if not legacy_pw:
            return None
        password_hash = generate_password_hash(legacy_pw)
    return {
        'username': username,
        'display_name': display_name,
        'password_hash': password_hash,
        'role': ADMIN_ROLE_GOLD,
    }


def _normalize_permanent_admins(raw_admins):
    out = []
    seen = set()
    for item in raw_admins if isinstance(raw_admins, list) else []:
        normalized = _normalize_permanent_admin_entry(item)
        if not normalized:
            continue
        key = normalized['username']
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def _refresh_permanent_cache(force=False):
    global _PERMANENT_CACHE_MTIME, _PERMANENT_CACHE, _PERMANENT_CACHE_READY
    path_obj = _resolve_permanent_storage()
    current_mtime = _get_mtime(path_obj)
    with _PERMANENT_CACHE_LOCK:
        if _PERMANENT_CACHE_READY and not force and _PERMANENT_CACHE_MTIME == current_mtime:
            return copy.deepcopy(_PERMANENT_CACHE)
    payload = _read_permanent_payload_from_storage()
    normalized = _normalize_permanent_admins(payload.get('admins'))
    with _PERMANENT_CACHE_LOCK:
        _PERMANENT_CACHE = copy.deepcopy(normalized)
        _PERMANENT_CACHE_MTIME = _get_mtime(path_obj)
        _PERMANENT_CACHE_READY = True
        return copy.deepcopy(_PERMANENT_CACHE)


def _permanent_usernames():
    return {str(a.get('username') or '') for a in _refresh_permanent_cache(force=False)}


def load_permanent_admins(force=False):
    return _refresh_permanent_cache(force=force)


def save_permanent_admins(admin_rows):
    global _PERMANENT_CACHE_MTIME, _PERMANENT_CACHE, _PERMANENT_CACHE_READY
    safe_rows = _normalize_permanent_admins(admin_rows)
    if _PERMANENT_CACHE_READY:
        with _PERMANENT_CACHE_LOCK:
            current = copy.deepcopy(_PERMANENT_CACHE)
    else:
        current = _refresh_permanent_cache(force=True)
    if current == safe_rows:
        return True
    _write_permanent_payload_to_storage({'admins': safe_rows})
    with _PERMANENT_CACHE_LOCK:
        _PERMANENT_CACHE = copy.deepcopy(safe_rows)
        _PERMANENT_CACHE_MTIME = _get_mtime(_resolve_permanent_storage())
        _PERMANENT_CACHE_READY = True
    return True


def add_permanent_admin(username, password, display_name=None):
    uname = str(username or '').strip()
    pwd = str(password or '')
    name = str(display_name or uname).strip() or uname
    if not uname or not pwd:
        raise ValueError('missing_credentials')
    if uname == _gold_username():
        raise ValueError('reserved_gold_username')
    rows = _refresh_permanent_cache(force=False)
    if any(str(row.get('username') or '') == uname for row in rows):
        raise ValueError('username_exists')
    rows.append({
        'username': uname,
        'display_name': name,
        'password_hash': generate_password_hash(pwd),
        'role': ADMIN_ROLE_GOLD,
    })
    save_permanent_admins(rows)
    return {
        'username': uname,
        'display_name': name,
        'role': ADMIN_ROLE_GOLD,
    }


def is_permanent_username(username):
    uname = str(username or '').strip()
    if not uname:
        return False
    if uname == _gold_username():
        return True
    return uname in _permanent_usernames()


def _normalize_admin_entry(raw):
    if not isinstance(raw, dict):
        return None
    username = str(raw.get('username') or '').strip()
    if not username:
        return None
    if username == _gold_username() or username in _permanent_usernames():
        return None

    display_name = str(raw.get('display_name') or username).strip() or username
    role = _normalize_role(raw.get('role'))

    password_hash = str(raw.get('password_hash') or '').strip()
    if not password_hash:
        legacy_pw = str(raw.get('password') or raw.get('password_plain') or '').strip()
        if not legacy_pw:
            return None
        password_hash = generate_password_hash(legacy_pw)

    return {
        'username': username,
        'display_name': display_name,
        'password_hash': password_hash,
        'role': role,
    }


def _normalize_admins(raw_admins):
    out = []
    seen = set()
    for item in raw_admins if isinstance(raw_admins, list) else []:
        normalized = _normalize_admin_entry(item)
        if not normalized:
            continue
        key = normalized['username']
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def _gold_record():
    return {
        'username': _gold_username(),
        'display_name': _gold_name(),
        'role': ADMIN_ROLE_GOLD,
        'password_hash': None,
    }


def _get_mtime(path_obj):
    try:
        return path_obj.stat().st_mtime
    except Exception:
        return None


def _refresh_cache(force=False):
    global _CACHE_MTIME, _NON_GOLD_CACHE, _CACHE_READY
    path_obj, _ = _resolve_storage()
    current_mtime = _get_mtime(path_obj)
    with _CACHE_LOCK:
        if _CACHE_READY and not force and _CACHE_MTIME == current_mtime:
            return copy.deepcopy(_NON_GOLD_CACHE)
    payload = _read_payload_from_storage()
    normalized = _normalize_admins(payload.get('admins'))
    with _CACHE_LOCK:
        _NON_GOLD_CACHE = copy.deepcopy(normalized)
        _CACHE_MTIME = _get_mtime(path_obj)
        _CACHE_READY = True
        return copy.deepcopy(_NON_GOLD_CACHE)


def load_admins(force=False):
    permanent = _refresh_permanent_cache(force=force)
    permanent_usernames = {str(item.get('username') or '') for item in permanent}
    non_gold = [
        row for row in _refresh_cache(force=force)
        if str(row.get('username') or '') not in permanent_usernames
    ]
    return [_gold_record()] + permanent + non_gold


def save_admins(admin_rows):
    global _CACHE_MTIME, _NON_GOLD_CACHE, _CACHE_READY
    safe_rows = _normalize_admins(admin_rows)
    if _CACHE_READY:
        with _CACHE_LOCK:
            current = copy.deepcopy(_NON_GOLD_CACHE)
    else:
        current = _refresh_cache(force=True)
    if current == safe_rows:
        return True
    _write_payload_to_storage({'admins': safe_rows})
    with _CACHE_LOCK:
        _NON_GOLD_CACHE = copy.deepcopy(safe_rows)
        _CACHE_MTIME = _get_mtime(_resolve_storage()[0])
        _CACHE_READY = True
    return True


def is_gold_username(username):
    return str(username or '').strip() == _gold_username()


def get_admin(username):
    uname = str(username or '').strip()
    if not uname:
        return None
    for admin in load_admins():
        if str(admin.get('username') or '') == uname:
            return admin
    return None


def validate_login(username, password):
    uname = str(username or '').strip()
    pwd = str(password or '')
    if not uname or not pwd:
        return {
            'ok': False,
            'error': 'missing_credentials',
            'message': 'Provide username and password.',
            'admin': None,
        }

    if is_gold_username(uname):
        for candidate in _gold_password_candidates():
            if hmac.compare_digest(pwd, candidate):
                admin = _gold_record()
                return {'ok': True, 'admin': admin, 'role': ADMIN_ROLE_GOLD, 'message': 'password_ok'}
        return {'ok': False, 'error': 'invalid_password', 'message': 'Invalid password.', 'admin': None}

    permanent_admin = next(
        (a for a in _refresh_permanent_cache(force=False) if str(a.get('username') or '') == uname),
        None
    )
    if permanent_admin:
        pw_hash = str(permanent_admin.get('password_hash') or '').strip()
        if not pw_hash:
            return {'ok': False, 'error': 'invalid_password', 'message': 'Invalid password.', 'admin': None}
        if not check_password_hash(pw_hash, pwd):
            return {'ok': False, 'error': 'invalid_password', 'message': 'Invalid password.', 'admin': None}
        admin_copy = copy.deepcopy(permanent_admin)
        admin_copy['role'] = ADMIN_ROLE_GOLD
        return {'ok': True, 'admin': admin_copy, 'role': ADMIN_ROLE_GOLD, 'message': 'password_ok'}

    non_gold = _refresh_cache(force=False)
    admin = next((a for a in non_gold if str(a.get('username') or '') == uname), None)
    if not admin:
        return {'ok': False, 'error': 'invalid_username', 'message': 'Invalid username.', 'admin': None}
    pw_hash = str(admin.get('password_hash') or '').strip()
    if not pw_hash:
        return {'ok': False, 'error': 'invalid_password', 'message': 'Invalid password.', 'admin': None}
    if not check_password_hash(pw_hash, pwd):
        return {'ok': False, 'error': 'invalid_password', 'message': 'Invalid password.', 'admin': None}
    admin_copy = copy.deepcopy(admin)
    admin_copy['role'] = _normalize_role(admin_copy.get('role'))
    return {'ok': True, 'admin': admin_copy, 'role': admin_copy['role'], 'message': 'password_ok'}


def validate_pin(role, pin_value, pin_config=None):
    role_key = ADMIN_ROLE_GOLD if _normalize_role(role) == ADMIN_ROLE_GOLD else ADMIN_ROLE_STANDARD
    pin_map = pin_config if isinstance(pin_config, dict) else {}
    required = str(pin_map.get(PIN_GOLD_LOGIN if role_key == ADMIN_ROLE_GOLD else PIN_ADMIN_LOGIN) or '').strip()
    if not required:
        required = DEFAULT_LOGIN_PINS[PIN_GOLD_LOGIN if role_key == ADMIN_ROLE_GOLD else PIN_ADMIN_LOGIN]
    pin = str(pin_value or '').strip()
    if not pin:
        return {'ok': False, 'error': 'missing_pin', 'message': 'Login pin is required.'}
    if not (pin.isdigit() and len(pin) == 6):
        return {'ok': False, 'error': 'invalid_pin_format', 'message': 'PIN must be a 6-digit numeric value.'}
    if hmac.compare_digest(pin, required):
        return {'ok': True, 'message': 'pin_ok'}
    return {'ok': False, 'error': 'invalid_pin', 'message': 'Invalid login pin.'}


def bootstrap_from_legacy(legacy_credentials_file):
    legacy_path = Path(str(legacy_credentials_file or '')).resolve() if legacy_credentials_file else None
    if not legacy_path or not legacy_path.exists():
        return False
    current = _refresh_cache(force=False)
    if current:
        return False
    try:
        with legacy_path.open('r', encoding='utf-8') as f:
            parsed = json.load(f)
    except Exception:
        return False
    if not isinstance(parsed, dict):
        return False
    legacy_admins = _normalize_admins(parsed.get('admins'))
    if not legacy_admins:
        return False
    save_admins(legacy_admins)
    return True
