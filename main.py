import os
from pathlib import Path
import sys

from actions_toolkit import core

from app import log
from app.action import Action, AuthError, RetryableError
from app.config import get_or_create_device_fingerprint, load_config
from app.notify import NotifyError, TelegramNotifier

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def get_value(name: str, config: dict, required: bool = False, default: str = '') -> str:
    value = (core.get_input(name) or config.get(name) or default).strip()
    if required and not value:
        config_hint = Path('config.local.json').resolve()
        raise RuntimeError(f'缺少必填参数 {name}，请通过 Action 输入传入，或在 {config_hint} 中配置')
    return value


def get_bool_value(name: str, config: dict, default: bool = False) -> bool:
    raw = (core.get_input(name) or config.get(name) or '').strip()
    if not raw:
        return default
    lowered = raw.lower()
    if lowered in {'1', 'true', 'yes', 'on'}:
        return True
    if lowered in {'0', 'false', 'no', 'off'}:
        return False
    raise RuntimeError(f'布尔参数 {name} 的值无效：{raw}')


def mask_secret(value: str):
    if value and os.getenv('GITHUB_ACTIONS', '').lower() == 'true':
        core.set_secret(value)


def build_success_message(host: str, message: str, traffic_info: dict | None = None) -> str:
    lines = [
        'CordCloud 签到成功',
        f'时间：{log.now()}',
        f'站点：{host}',
        f'结果：{message}',
    ]
    if traffic_info:
        lines.extend([
            f'今日已用：{traffic_info.get("todayUsedTraffic", "未知")}',
            f'过去已用：{traffic_info.get("lastUsedTraffic", "未知")}',
            f'剩余流量：{traffic_info.get("unUsedTraffic", "未知")}',
        ])
    return '\n'.join(lines)


def build_failure_message(host: str, error_message: str) -> str:
    lines = [
        'CordCloud 签到失败',
        f'时间：{log.now()}',
    ]
    if host:
        lines.append(f'站点：{host}')
    lines.append(f'错误：{error_message or "未知错误"}')
    return '\n'.join(lines)


def safe_notify(notifier: TelegramNotifier | None, message: str):
    if notifier is None or not notifier.enabled() or not message:
        return
    try:
        notifier.send(message)
    except NotifyError as exc:
        log.warning(f'Telegram 推送失败，错误信息：{exc}')


notifier = None
last_host = ''
diagnostic_mode = False

try:
    config = load_config()
    diagnostic_mode = get_bool_value('diagnostics', config, default=False)

    # 获取输入
    email = get_value('email', config, required=True)
    passwd = get_value('passwd', config, required=True)
    secret = get_value('secret', config)
    code = get_value('code', config)
    verify_method = get_value('verify_method', config)
    host = get_value('host', config, default='cordcloud.us,cordcloud.one,cordcloud.biz,c-cloud.xyz')
    trust_device = get_bool_value('trust_device', config, default=False)
    insecure_skip_verify = get_bool_value('insecure_skip_verify', config, default=False)
    device_fingerprint = (config.get('device_fingerprint', '') if diagnostic_mode
                          else get_or_create_device_fingerprint(config))
    telegram_bot_token = get_value('telegram_bot_token', config)
    telegram_chat_id = get_value('telegram_chat_id', config)
    if not diagnostic_mode:
        notifier = TelegramNotifier(
            bot_token=telegram_bot_token,
            chat_id=telegram_chat_id,
        )

    mask_secret(passwd)
    mask_secret(secret)
    mask_secret(code)
    mask_secret(telegram_bot_token)
    mask_secret(telegram_chat_id)
    if diagnostic_mode and insecure_skip_verify:
        raise RuntimeError('诊断模式必须保持 TLS 证书校验')
    if insecure_skip_verify:
        log.warning('已启用 insecure_skip_verify；这会跳过 TLS 证书校验，仅建议在调试环境中临时使用')

    # host 预处理：切分、过滤空值
    hosts = [h for h in host.split(',') if h]
    if diagnostic_mode and len(hosts) != 1:
        raise RuntimeError('诊断模式只允许一个明确的 host，不自动切换域名')
    last_error = ''
    success = False

    for i, h in enumerate(hosts):
        # 依次尝试每个 host
        last_host = h
        if not diagnostic_mode:
            log.info(f'当前尝试 host：{h}')
        action = Action(
            email,
            passwd,
            secret=secret,
            code=code,
            verify_method=verify_method,
            host=h,
            trust_device=trust_device,
            verify_tls=not insecure_skip_verify,
            device_fingerprint=device_fingerprint,
            diagnostics=diagnostic_mode,
            diagnostic_logger=log.info,
        )
        try:
            # 登录
            res = action.login()
            if diagnostic_mode:
                if res.get('ret') not in (1, 2):
                    raise AuthError('登录诊断被站点拒绝；请查看固定分类诊断记录')
                log.info('登录诊断已结束；未执行设备二验、签到、流量查询或通知')
                success = True
                break
            msg = res.get('msg', '未知错误')
            log.info(f'尝试帐号登录，结果：{msg}')
            if res.get('ret') != 1:
                last_error = f'CordCloud 帐号登录失败，错误信息：{msg}'
                raise AuthError(last_error)

            # 签到
            res = action.check_in()
            msg = res.get('msg', '未知错误')
            log.info(f'尝试帐号签到，结果：{msg}')
            if res.get('ret') != 1 and '您似乎已经签到过' not in msg:
                last_error = f'CordCloud 帐号续命失败，错误信息：{msg}'
                raise RetryableError(last_error)
            if 'trafficInfo' not in res:
                try:
                    account = action.info()
                    if account:
                        today_used, last_used, unused = account
                        info = {
                            'todayUsedTraffic': today_used,
                            'lastUsedTraffic': last_used,
                            'unUsedTraffic': unused
                        }
                        res['trafficInfo'] = info
                except RetryableError as e:
                    log.warning(f'获取帐号流量信息失败，错误信息：{e}')
            if 'trafficInfo' in res:
                e = res['trafficInfo']
                log.info(
                    f'帐号流量使用情况：今日已用 {e["todayUsedTraffic"]}, 过去已用 {e["lastUsedTraffic"]}, 剩余流量 {e["unUsedTraffic"]}')

            # 成功运行，退出循环
            safe_notify(notifier, build_success_message(h, msg, res.get('trafficInfo')))
            log.info(f'CordCloud Action 成功结束运行！')
            success = True
            break
        except AuthError as e:
            last_error = '登录诊断已停止；请查看阶段和固定分类记录' if diagnostic_mode else (str(e) or last_error)
            log.warning(f'CordCloud Action 运行异常，错误信息：{last_error}')
            break
        except RetryableError as e:
            last_error = '登录诊断发生请求或响应错误；未重试' if diagnostic_mode else (str(e) or last_error)
            log.warning(f'CordCloud Action 运行异常，错误信息：{last_error}')
        except Exception as e:
            last_error = '登录诊断发生内部错误；已省略原始错误内容，未重试' if diagnostic_mode else (str(e) or last_error)
            log.warning(f'CordCloud Action 运行异常，错误信息：{last_error}')

    if not success:
        safe_notify(notifier, build_failure_message(last_host, last_error))
        log.set_failed(last_error or 'CordCloud Action 运行失败！')
except Exception as e:
    error = '诊断已停止；请检查配置和阶段记录，未输出原始错误内容' if diagnostic_mode else str(e)
    safe_notify(notifier, build_failure_message(last_host, error))
    log.set_failed(error)
