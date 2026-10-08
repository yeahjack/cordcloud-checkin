# CordCloud Action

<a href="./LICENSE"><img src="https://img.shields.io/github/license/yanglbme/cordcloud-action?color=42b883&style=flat-square" alt="license"></a>

CordCloud 自动签到项目，支持：

- GitHub Actions 定时签到
- Linux 服务器直接用 Python 运行
- Windows 本地直接运行
- Telegram 消息推送

## 改造基础

本仓库基于原始项目 [yanglbme/cordcloud-action](https://github.com/yanglbme/cordcloud-action) 改造。

本次改造的背景是 2026-03-23 实测发现 CordCloud 登录流程已不再兼容原版实现，站点新增了：

- `csrf_token`
- `ALTCHA`
- `device_fingerprint`
- 新版“陌生设备二步验证”接口 `/auth/login/2fa/verify`

因此当前仓库是在原版基础上，针对新版网页登录流程做的兼容修复。

## 当前支持的登录方式

当前代码支持以下两类二步验证：

- `secret`
  说明：验证器 APP 的长期密钥，程序可自行生成动态验证码
  适用：GitHub Actions、服务器定时任务、Windows 本地长期使用
- `code`
  说明：邮件验证码或设备验证码，一次性 6 位码
  适用：本地临时测试
- `verify_method`
  说明：显式指定二步验证方式，可选 `ga`、`email` 或留空自动选择
  适用：账号同时启用了验证器和邮箱验证时，强制选择其中一种

注意：

- 如果同时提供 `secret` 和 `code`，可通过 `verify_method` 明确指定使用哪一种
- 如果未设置 `verify_method`，程序会优先使用 `secret + ga`
- 如果你想避免站点先打开邮箱验证码页，建议在使用 `secret` 时显式设置 `verify_method=ga`
- 如果站点启用了“陌生设备验证”，而你又没有 `secret`，则自动化定时签到通常不可持续，只能临时手动输入 `code`

## 参数说明

| 参数 | 说明 | 是否必填 | 示例 |
| --- | --- | --- | --- |
| `email` | CordCloud 登录邮箱 | 是 | `your@email.com` |
| `passwd` | CordCloud 登录密码 | 是 | `your-password` |
| `secret` | 验证器 APP 的 TOTP 密钥 | 否 | `JBSWY3DPEHPK3PXP` |
| `code` | 邮件/设备二步验证码 | 否 | `123456` |
| `verify_method` | 指定 2FA 方式：`ga` / `email` / 留空自动 | 否 | `ga` |
| `host` | 站点域名，支持多个逗号分隔 | 否 | `cordcloud.one` |
| `trust_device` | 2FA 成功后是否信任当前设备 | 否 | `false` |
| `insecure_skip_verify` | 是否跳过 TLS 证书校验，仅调试用 | 否 | `false` |
| `telegram_bot_token` | Telegram 机器人 Token | 否 | `123456:ABC-DEF...` |
| `telegram_chat_id` | Telegram 会话 Chat ID | 否 | `123456789` |

默认 `host`：

```text
cordcloud.us,cordcloud.one,cordcloud.biz,c-cloud.xyz
```

## 各参数如何获取

### 1. `email`

就是你的 CordCloud 登录邮箱。

### 2. `passwd`

就是你的 CordCloud 登录密码。

### 3. `secret`

`secret` 不是 6 位动态验证码，而是验证器绑定时生成的“长期密钥”。

常见获取方式：

1. 登录 CordCloud 后台
2. 进入账号安全 / 两步验证 / 验证器设置页面
3. 找到验证器 APP 绑定信息
4. 页面通常会显示二维码，或一条 `otpauth://...` 链接
5. 从中提取 `secret=...` 后面的值

例如：

```text
otpauth://totp/CordCloud:xxx?secret=JBSWY3DPEHPK3PXP&issuer=CordCloud
```

真正要填的是：

```text
JBSWY3DPEHPK3PXP
```

不是整条 `otpauth://...`，只要 `secret=` 后面的那一段。

### 4. `code`

`code` 是你当前这一次登录收到的 6 位验证码，可能来自：

- 邮箱验证码
- 设备验证验证码

这个值是一次性的，会过期，不适合放到 GitHub Actions 做长期定时任务。

### 5. `verify_method`

可选值：

- `ga`：强制使用验证器 APP
- `email`：强制使用邮箱验证码
- 留空：自动选择

推荐：

- 你已经配置了 `secret`，并且账号同时支持邮箱验证和验证器验证时，设置为 `ga`
- 你只拿到了当次邮件验证码时，设置为 `email`

### 6. `host`

就是你实际登录使用的站点域名，不要带协议头。

正确示例：

```text
cordcloud.one
```

错误示例：

```text
https://cordcloud.one
```

如果你不确定，可以直接保留默认值，让程序自动依次尝试。

### 7. `telegram_bot_token`

这是 Telegram 机器人的 Token。

获取方式：

1. 在 Telegram 里打开 `@BotFather`
2. 发送 `/newbot`
3. 按提示创建机器人
4. 复制返回的 Bot Token

### 8. `telegram_chat_id`

这是 Telegram 接收消息的会话 ID。

常见获取方式：

1. 先给你的机器人发一条消息
2. 打开：

```text
https://api.telegram.org/bot<你的BotToken>/getUpdates
```

3. 在返回结果里找到 `chat.id`

说明：

- 私聊通常是正整数
- 群组通常是负数
- 如果你把机器人拉进群里，记得先给群里发一条消息，再查 `getUpdates`

## 配置文件

项目根目录提供了默认模板 [config.default.json](./config.default.json)。

本地使用时，建议复制一份为 `config.local.json`，该文件已加入 `.gitignore`，不会提交到仓库。

示例：

```json
{
  "email": "your@email.com",
  "passwd": "your-password",
  "secret": "JBSWY3DPEHPK3PXP",
  "code": "",
  "verify_method": "ga",
  "host": "cordcloud.one",
  "trust_device": "false",
  "insecure_skip_verify": "false",
  "telegram_bot_token": "",
  "telegram_chat_id": ""
}
```

如果你当前没有验证器密钥，只想临时本地测试：

```json
{
  "email": "your@email.com",
  "passwd": "your-password",
  "secret": "",
  "code": "123456",
  "verify_method": "email",
  "host": "cordcloud.one",
  "trust_device": "false",
  "insecure_skip_verify": "false",
  "telegram_bot_token": "",
  "telegram_chat_id": ""
}
```

参数读取优先级：

1. Action 输入 / 环境变量 `INPUT_*`
2. `config.local.json`
3. `config.default.json`

## GitHub Actions 使用方法

### 推荐方式

推荐只在 GitHub Actions 中使用 `secret`，不要依赖 `code`。

原因：

- `secret` 可以长期稳定自动生成动态验证码
- `code` 是临时验证码，过期后就失效，不适合定时任务
- 如果账号同时支持邮箱和验证器，建议显式设置 `verify_method: ga`
- `trust_device` 默认应保持 `false`
- `insecure_skip_verify` 默认应保持 `false`

### 先配置 GitHub Secrets

在你的 GitHub 仓库中配置：

- `CC_EMAIL`
- `CC_PASSWD`
- `CC_SECRET`
- `TG_BOT_TOKEN`（可选）
- `TG_CHAT_ID`（可选）

### Workflow 示例

如果你已经把本项目推送到你自己的 GitHub 仓库，例如：

```text
yourname/cordcloud-action
```

则可以这样用：

```yml
name: CordCloud

on:
  schedule:
    - cron: "0 0 * * *"
  workflow_dispatch:

jobs:
  checkin:
    runs-on: ubuntu-latest
    steps:
      - uses: yourname/cordcloud-action@main
        with:
          email: ${{ secrets.CC_EMAIL }}
          passwd: ${{ secrets.CC_PASSWD }}
          secret: ${{ secrets.CC_SECRET }}
          verify_method: ga
          host: cordcloud.one
          trust_device: false
          telegram_bot_token: ${{ secrets.TG_BOT_TOKEN }}
          telegram_chat_id: ${{ secrets.TG_CHAT_ID }}
```

如果你把 Action 代码和 workflow 放在同一个仓库里，也可以：

```yml
name: CordCloud

on:
  schedule:
    - cron: "0 0 * * *"
  workflow_dispatch:

jobs:
  checkin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./
        with:
          email: ${{ secrets.CC_EMAIL }}
          passwd: ${{ secrets.CC_PASSWD }}
          secret: ${{ secrets.CC_SECRET }}
          verify_method: ga
          host: cordcloud.one
          trust_device: false
          telegram_bot_token: ${{ secrets.TG_BOT_TOKEN }}
          telegram_chat_id: ${{ secrets.TG_CHAT_ID }}
```

注意：

- `cron` 使用 UTC 时间
- 如果你的账号只支持邮件验证码 `code`，则 GitHub Actions 不适合做真正的长期自动签到
- 不建议在 GitHub Actions 中启用 `trust_device`
- 不建议在 GitHub Actions 中启用 `insecure_skip_verify`

## Linux 服务器 Python 使用方法

### 1. 准备环境

```bash
git clone <your-repo-url>
cd cordcloud-action
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 配置 `config.local.json`

```bash
cp config.default.json config.local.json
```

然后填写你的账号信息。

### 3. 运行

```bash
python main.py
```

### 4. 也可以直接用环境变量运行

```bash
export INPUT_EMAIL='your@email.com'
export INPUT_PASSWD='your-password'
export INPUT_SECRET='your-totp-secret'
export INPUT_VERIFY_METHOD='ga'
export INPUT_HOST='cordcloud.one'
export INPUT_TELEGRAM_BOT_TOKEN='123456:ABC-DEF'
export INPUT_TELEGRAM_CHAT_ID='123456789'
python main.py
```

如果你只想临时测试邮件验证码：

```bash
export INPUT_EMAIL='your@email.com'
export INPUT_PASSWD='your-password'
export INPUT_CODE='123456'
export INPUT_VERIFY_METHOD='email'
export INPUT_HOST='cordcloud.one'
export INPUT_TELEGRAM_BOT_TOKEN='123456:ABC-DEF'
export INPUT_TELEGRAM_CHAT_ID='123456789'
python main.py
```

### 5. 定时运行

推荐在 Linux 服务器上配合 `crontab` 使用，并优先采用 `secret`。

## Windows 使用方法

### 方式一：直接使用本项目提供的本地脚本

项目中已提供 [local_test.ps1](./local_test.ps1)。

如果你已经配置好 `config.local.json`，直接运行：

```powershell
.\local_test.ps1
```

### 方式二：命令行传参

使用验证器密钥：

```powershell
.\local_test.ps1 -Email '你的邮箱' -Passwd '你的密码' -SiteHost 'cordcloud.one' -Secret '你的TOTP密钥' -VerifyMethod 'ga' -TelegramBotToken '123456:ABC-DEF' -TelegramChatId '123456789'
```

使用一次性验证码：

```powershell
.\local_test.ps1 -Email '你的邮箱' -Passwd '你的密码' -SiteHost 'cordcloud.one' -Code '123456' -VerifyMethod 'email' -TelegramBotToken '123456:ABC-DEF' -TelegramChatId '123456789'
```

如果你明确要信任当前本地设备：

```powershell
.\local_test.ps1 -TrustDevice
```

### 方式三：自己创建 Python/Conda 环境

```powershell
conda create -n cordcloud python=3.10 -y
conda activate cordcloud
pip install -r requirements.txt
copy config.default.json config.local.json
python .\main.py
```

## 常见问题
## 为什么原版项目现在不能用了

因为 CordCloud 的登录链路已经变化，新增了：

- `csrf_token`
- `ALTCHA`
- `device_fingerprint`
- 新版二步验证接口

原版项目仍按旧接口直接提交邮箱和密码，所以会失败。

## 本地调试验证

当前仓库已加入基础回归测试，可运行：

```bash
python -m unittest -v test.py test_diagnostics.py
```

这些测试会禁用真实 HTTP 请求，并使用固定的模拟验证结果，
不会登录账号、求解真实 ALTCHA、发送 Telegram 消息或签到。
测试通过只表示已覆盖的代码路径通过，不表示当前站点接受自动登录。

### 区分登录前验证和设备二次验证

如果首次提交登录表单时收到“系统无法接受您的验证结果”，
程序会明确报告登录前验证被拒绝，并停止该次登录。
该响应不能证明密码错误、缺少 TOTP，或具体使用了哪种验证码。
需要先核对站点当前正常登录流程；遇到访问限制时应停止并联系站点支持。

仓库自带 workflow 使用 `verify_method: auto`，不再强制无 TOTP 的账号使用 `ga`。
这不会绕过设备二次验证：若站点要求邮箱验证码而未提供本次有效的 `code`，
程序仍会停止。一次性邮箱验证码不能让定时任务长期无人值守运行。
本项目未实现自动读取邮箱，也不会自动开启 POP3、修改账号安全设置或持久化 Cookie。

邮箱设备验证现在会原样传递验证页面中的 `csrf_token`。
错误诊断不再输出非 JSON 响应正文或请求异常中的完整 URL，避免验证 token 或机器人凭据进入日志。
手动触发 workflow 不再随机等待；定时运行仍保留原有随机延迟。

### 可选的一次性登录诊断

`diagnostics` 默认关闭，定时 workflow 不会开启它。只在明确需要诊断的手动运行中设置为 `true`。

该模式只允许一个 host，保持 TLS 校验，只发起一轮登录验证请求。
它在登录成功或收到设备二次验证要求后结束，不提交二次验证码、不签到、不查询流量、不发送 Telegram，也不保存设备指纹或会话。
HTTP 403/429、跨域/非 HTTPS 地址或重定向会停止运行，不尝试其他域名。
同源重定向最多跟随 5 次；无法识别的登录表单/验证码协议也会停止。

诊断日志只输出固定阶段、HTTP 状态、Content-Type 分类、重定向次数、已知表单字段名、未知字段数量、CSRF 是否存在、widget 协议属性名、ALTCHA 算法白名单和结构/摘要自检布尔值。
不输出表单值、任意未知字段名、原始服务端消息、HTML、URL/query、邮箱、密码、验证码、Cookie、盐、签名或证明内容。
`self_check=true` 仅说明序列化和本地摘要匹配，不能验证服务端 HMAC、挑战有效期或会话绑定，也不能证明登录成功。
诊断没有改变原有 ALTCHA 搜索算法。

审阅分支并获得本次登录验证授权后，使用正常已登录的 GitHub CLI 可以指定远程分支：

```bash
gh workflow run cordcloud.yml --repo yeahjack/cordcloud-checkin --ref fix/login-protocol-safety -f diagnostics=true
```

必须新建指定分支的 dispatch；重新运行旧 job 会继续使用旧提交，无法测试本次修改。
触发后核对 run 的 branch、head SHA 和输入为 `diagnostics=true`。不要修改默认分支来启用实验，也不要提供新凭据到聊天或命令行。
诊断运行显示完成，仅代表此次诊断完成，不代表已经签到。

## 声明

请不要把真实账号、密码、`secret`、邮件验证码直接提交到仓库。

推荐做法：

- GitHub Actions 用 `Secrets`
- 本地调试用 `config.local.json`
- `config.local.json` 不提交
- `telegram_bot_token` 也应放在 `Secrets` 或本地配置里，不要写进公开仓库
