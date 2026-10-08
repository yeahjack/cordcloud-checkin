import json
import secrets
from pathlib import Path
from typing import Dict, Iterable

DEFAULTS = {
    'email': '',
    'passwd': '',
    'secret': '',
    'code': '',
    'verify_method': '',
    'host': 'cordcloud.us,cordcloud.one,cordcloud.biz,c-cloud.xyz',
    'trust_device': 'false',
    'insecure_skip_verify': 'false',
    'telegram_bot_token': '',
    'telegram_chat_id': '',
    'device_fingerprint': '',
    'diagnostics': 'false',
}

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = ROOT_DIR / 'config.default.json'
LOCAL_CONFIG_PATH = ROOT_DIR / 'config.local.json'
DEFAULT_CONFIG_PATHS = (
    DEFAULT_CONFIG_PATH,
    LOCAL_CONFIG_PATH,
)


def load_config(paths: Iterable[Path] = DEFAULT_CONFIG_PATHS) -> Dict[str, str]:
    config = DEFAULTS.copy()

    for path in paths:
        if not path.is_file():
            continue

        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise RuntimeError(f'配置文件格式错误：{path}')

        for key in DEFAULTS:
            value = data.get(key)
            if value is None:
                continue
            config[key] = str(value).strip()

    return config


def save_local_config(updates: Dict[str, str], path: Path = LOCAL_CONFIG_PATH) -> bool:
    if not path.is_file():
        return False

    raw = path.read_text(encoding='utf-8').strip() if path.exists() else ''
    data = json.loads(raw) if raw else {}
    if not isinstance(data, dict):
        raise RuntimeError(f'配置文件格式错误：{path}')

    for key, value in updates.items():
        data[key] = value

    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    return True


def get_or_create_device_fingerprint(
    config: Dict[str, str],
    local_path: Path = LOCAL_CONFIG_PATH,
) -> str:
    current = str(config.get('device_fingerprint', '')).strip()
    if current:
        return current

    fingerprint = secrets.token_hex(16)
    config['device_fingerprint'] = fingerprint
    save_local_config({'device_fingerprint': fingerprint}, path=local_path)
    return fingerprint
