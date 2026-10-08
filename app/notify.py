from typing import Dict

import requests


class NotifyError(RuntimeError):
    pass


class TelegramNotifier:
    def __init__(
        self,
        bot_token: str = '',
        chat_id: str = '',
    ):
        self.bot_token = bot_token.strip()
        self.chat_id = chat_id.strip()
        self.timeout = 15

    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def _api_url(self, method: str) -> str:
        return f'https://api.telegram.org/bot{self.bot_token}/{method}'

    def send(self, text: str) -> bool:
        message = text.strip()
        if not message or not self.enabled():
            return False

        payload: Dict[str, str] = {
            'chat_id': self.chat_id,
            'text': message,
        }

        try:
            response = requests.post(
                self._api_url('sendMessage'),
                data=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise NotifyError('Telegram 网络请求失败；已省略包含机器人凭据的请求地址') from exc

        try:
            result = response.json()
        except ValueError as exc:
            raise NotifyError(
                f'Telegram 未返回 JSON（HTTP {response.status_code}）；已省略响应正文'
            ) from exc

        if not isinstance(result, dict):
            raise NotifyError('Telegram 返回了非对象 JSON')

        if response.status_code >= 400 or not result.get('ok'):
            description = result.get('description') or f'HTTP {response.status_code}'
            raise NotifyError(f'Telegram 推送失败：{description}')

        return True
