"""Private Telegram administration bot embedded in the KeyHub API service.

No admin password or long-lived KeyHub bearer token is stored in Telegram.
The webhook is authenticated with Telegram's secret_token header, and every
privileged action is further restricted to configured Telegram user IDs.
"""
import hmac
import logging
import os
import re
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import (
    Activation, DeviceAuditEvent, DeviceHeartbeat, LicenseKey,
    TelegramProcessedUpdate, User,
)
from .security import new_license, now_ts, secret_digest

router = APIRouter()
logger = logging.getLogger(__name__)
# HTTPX's default INFO request logging contains Telegram Bot API URLs, which
# embed the secret Bot Token. Never expose these URLs in Render logs.
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)
TZ = ZoneInfo('Asia/Ho_Chi_Minh')
HEX_PREFIX = re.compile(r'^[0-9A-Fa-f]{12}$')


def bot_configured() -> bool:
    cfg = get_settings()
    return bool(cfg.telegram_bot_token and cfg.telegram_webhook_secret)


def admin_ids() -> set[int]:
    result: set[int] = set()
    for item in get_settings().telegram_admin_ids.split(','):
        item = item.strip()
        if item.isdecimal():
            result.add(int(item))
    return result


def owner_email() -> str:
    cfg = get_settings()
    return (cfg.telegram_owner_email or os.getenv('ADMIN_EMAIL', '')).strip().lower()


def datestring(value: int) -> str:
    return datetime.fromtimestamp(value, tz=TZ).strftime('%d/%m/%Y %H:%M')


def button_style(callback: str) -> str | None:
    """Telegram Bot API supports primary/blue, success/green and danger/red.

    Leave neutral navigation buttons unstyled for consistent contrast.
    Older Telegram clients may ignore styles; emoji labels remain readable.
    """
    action = callback.split(':', 1)[0]
    if action in ('revoke', 'delete', 'askrevoke', 'askdel'):
        return 'danger'
    if action in ('periods', 'issue', 'renew'):
        return 'success'
    if action in ('list', 'detail', 'period', 'devices', 'askrenew'):
        return 'primary'
    return None


def keyboard(*rows: tuple[tuple[str, str], ...]) -> dict:
    def make_button(title: str, value: str) -> dict:
        item = {'text': title, 'callback_data': value}
        style = button_style(value)
        if style:
            item['style'] = style
        return item

    return {'inline_keyboard': [
        [make_button(title, value) for title, value in row]
        for row in rows
    ]}


def home_markup() -> dict:
    return keyboard(
        (('🟢 Tạo License', 'periods'), ('📋 Key còn hạn', 'list:active')),
        (('🕒 Hết hạn / thu hồi', 'list:inactive'),),
        (('ℹ️ Hướng dẫn sử dụng', 'help'),),
    )


def send(chat_id: int, text: str, markup: dict | None = None,
         sensitive: bool = False) -> dict:
    payload: dict = {'chat_id': chat_id, 'text': text}
    if markup is not None:
        payload['reply_markup'] = markup
    if sensitive:
        payload['protect_content'] = True
    return payload


def status_of(item: LicenseKey) -> str:
    if item.revoked_at is not None:
        return 'Đã thu hồi'
    if item.expires_at <= now_ts():
        return 'Hết hạn'
    return 'Đang hoạt động'


def find_key(db: Session, raw_prefix: str) -> LicenseKey | None:
    if not HEX_PREFIX.fullmatch(raw_prefix):
        return None
    return db.scalar(select(LicenseKey).where(
        LicenseKey.prefix == raw_prefix.upper()))


def lock_key(db: Session, raw_prefix: str) -> LicenseKey | None:
    if not HEX_PREFIX.fullmatch(raw_prefix):
        return None
    return db.scalar(select(LicenseKey).where(
        LicenseKey.prefix == raw_prefix.upper()).with_for_update())


def key_info(db: Session, item: LicenseKey) -> str:
    devices = db.scalar(select(func.count()).select_from(Activation).where(
        Activation.key_id == item.id)) or 0
    return (
        f'License: {item.prefix}…\n'
        f'Trạng thái: {status_of(item)}\n'
        f'Chủ sở hữu: {item.owner.email}\n'
        f'Hạn dùng: {datestring(item.expires_at)} (VN)\n'
        f'Thiết bị: {devices}/{item.device_limit}\n'
        f'Ghi chú: {item.note or "Không có"}'
    )


def key_actions(item: LicenseKey) -> dict:
    if item.revoked_at is not None or item.expires_at <= now_ts():
        return keyboard(
            (('🗑 Xóa License', f'askdel:{item.prefix}'),),
            (('📋 Danh sách', 'list:inactive'), ('🏠 Trang chính', 'home')),
        )
    return keyboard(
        (('➕ Gia hạn 7 ngày', f'askrenew:{item.prefix}:7'),
         ('➕ Gia hạn 30 ngày', f'askrenew:{item.prefix}:30')),
        (('⚠️ Thu hồi License', f'askrevoke:{item.prefix}'),),
        (('📋 Danh sách', 'list:active'), ('🏠 Trang chính', 'home')),
    )


def list_keys(db: Session, chat_id: int, inactive: bool = False) -> dict:
    predicate = or_(
        LicenseKey.revoked_at.is_not(None),
        LicenseKey.expires_at <= now_ts(),
    )
    statement = select(LicenseKey).order_by(
        LicenseKey.created_at.desc(), LicenseKey.id.desc()).limit(10)
    statement = statement.where(predicate if inactive else ~predicate)
    entries = db.scalars(statement).all()
    label = 'Key hết hạn / đã thu hồi' if inactive else 'Key còn hiệu lực'
    if not entries:
        return send(chat_id, label + ': chưa có.', home_markup())
    rows = []
    lines = [label + ' (10 Key mới nhất):']
    for item in entries:
        lines.append(f'• {item.prefix}… | {status_of(item)} | {datestring(item.expires_at)}')
        rows.append((('🔎 ' + item.prefix + '…', 'detail:' + item.prefix),))
    rows.append((('🔄 Làm mới', 'list:inactive' if inactive else 'list:active'),))
    rows.append((('🏠 Trang chính', 'home'),))
    return send(chat_id, '\n'.join(lines), keyboard(*rows))


def delete_inactive_key(db: Session, item: LicenseKey) -> None:
    """Same cleanup invariants as KeyHub's /keys/{key_id} endpoint."""
    if item.revoked_at is None and item.expires_at > now_ts():
        raise ValueError('Không thể xóa Key còn hiệu lực.')
    db.execute(delete(DeviceHeartbeat).where(DeviceHeartbeat.key_id == item.id))
    db.execute(delete(DeviceAuditEvent).where(DeviceAuditEvent.key_id == item.id))
    db.delete(item)


def process_command(db: Session, chat_id: int, text: str) -> dict:
    tokens = text.split()
    cmd = tokens[0].split('@', 1)[0].lower()
    if cmd in ('/start', '/menu', '/help'):
        return send(
            chat_id,
            'KEYHUB MANAGER\n\n'
            'Tạo Key: /taokey 30 1\n'
            'Danh sách: /danhsachkey\n'
            'Kiểm tra: /kiemtrakey PREFIX\n'
            'Gia hạn: /giakhankey PREFIX 7\n'
            'Thu hồi: /thukhoikey PREFIX\n'
            'Xóa Key hết hạn/thu hồi: /xoakey PREFIX\n\n'
            'PREFIX gồm 12 ký tự ở đầu License.\n'
            'Lệnh tạo Key dùng tài khoản chủ sở hữu đã cấu hình trên Render.',
            home_markup(),
        )
    if cmd == '/taokey':
        if len(tokens) == 1:
            return send(chat_id, '📅 Chọn thời hạn License:', keyboard(
                (('⚡ 1 ngày', 'period:1'), ('📆 7 ngày', 'period:7')),
                (('🗓 30 ngày', 'period:30'),),
                (('⬅️ Trang chính', 'home'),),
            ))
        if len(tokens) != 3 or not all(t.isdecimal() for t in tokens[1:]):
            return send(chat_id, 'Cú pháp: /taokey 30 1 (30 ngày, 1 thiết bị)')
        days, limit = map(int, tokens[1:])
        return prompt_issue(chat_id, days, limit)
    if cmd == '/danhsachkey':
        if len(tokens) > 2:
            return send(chat_id, 'Cú pháp: /danhsachkey hoặc /danhsachkey inactive')
        return list_keys(db, chat_id, inactive=len(tokens) == 2 and tokens[1] in ('inactive', 'het'))
    if cmd == '/kiemtrakey':
        if len(tokens) != 2:
            return send(chat_id, 'Cú pháp: /kiemtrakey PREFIX')
        item = find_key(db, tokens[1])
        return send(chat_id, key_info(db, item), key_actions(item)) if item else send(chat_id, 'Không tìm thấy License với PREFIX này.')
    if cmd in ('/thukhoikey', '/xoakey'):
        if len(tokens) != 2:
            return send(chat_id, 'Cú pháp: ' + cmd + ' PREFIX')
        item = find_key(db, tokens[1])
        if item is None:
            return send(chat_id, 'Không tìm thấy License.')
        action = ('askrevoke:' if cmd == '/thukhoikey' else 'askdel:') + item.prefix
        return process_callback(db, chat_id, action)
    if cmd == '/giakhankey':
        if len(tokens) != 3 or not tokens[2].isdecimal():
            return send(chat_id, 'Cú pháp: /giakhankey PREFIX 7')
        item = find_key(db, tokens[1])
        return process_callback(db, chat_id, 'askrenew:'+item.prefix+':'+tokens[2]) if item else send(chat_id, 'Không tìm thấy License.')
    return send(chat_id, 'Lệnh không hỗ trợ. Dùng /help để xem các lệnh.', home_markup())


def prompt_issue(chat_id: int, days: int, device_limit: int) -> dict:
    if not 1 <= days <= 3650 or not 1 <= device_limit <= 10:
        return send(chat_id, 'Giới hạn: 1–3650 ngày và 1–10 thiết bị.')
    return send(
        chat_id,
        f'Xác nhận tạo License:\n• Thời hạn: {days} ngày\n'
        f'• Số thiết bị: {device_limit}\n• Chủ sở hữu: {owner_email() or "Chưa cấu hình"}\n'
        'Bạn muốn tạo Key mới?',
        keyboard((('✅ Xác nhận tạo Key', f'issue:{days}:{device_limit}'),),
                 (('↩️ Hủy', 'home'),)),
    )


def process_callback(db: Session, chat_id: int, data: str) -> dict:
    parts = data.split(':')
    action = parts[0]
    if data in ('home', 'help'):
        return process_command(db, chat_id, '/start')
    if data == 'periods':
        return process_command(db, chat_id, '/taokey')
    if action == 'period' and len(parts) == 2 and parts[1].isdecimal():
        days = int(parts[1])
        return send(chat_id, f'Đã chọn {days} ngày. Chọn số lượng thiết bị:',
                    keyboard((('📱 1 thiết bị', f'devices:{days}:1'),
                              ('📱 2 thiết bị', f'devices:{days}:2')),
                             (('⬅️ Trở lại', 'periods'),)))
    if action == 'devices' and len(parts) == 3 and all(p.isdecimal() for p in parts[1:]):
        return prompt_issue(chat_id, int(parts[1]), int(parts[2]))
    if action == 'issue' and len(parts) == 3 and all(p.isdecimal() for p in parts[1:]):
        days, limit = int(parts[1]), int(parts[2])
        if not 1 <= days <= 3650 or not 1 <= limit <= 10:
            return send(chat_id, 'Thời hạn hoặc số thiết bị không hợp lệ.')
        email = owner_email()
        if not email:
            return send(chat_id, 'Chưa cấu hình TELEGRAM_OWNER_EMAIL hoặc ADMIN_EMAIL trên Render.')
        owner = db.scalar(select(User).where(
            User.email == email, User.is_active.is_(True),
            User.is_admin.is_(True)))
        if owner is None:
            return send(chat_id, 'Không tìm thấy tài khoản Admin đang hoạt động tương ứng email đã cấu hình.')
        prefix, secret = new_license()
        new_key = LicenseKey(
            owner_id=owner.id, prefix=prefix, key_digest=secret_digest(secret),
            note='Telegram KeyHub Bot', device_limit=limit,
            expires_at=now_ts() + days * 86400,
        )
        db.add(new_key)
        return send(
            chat_id,
            'ĐÃ TẠO LICENSE\n\n'
            f'{secret}\n\n'
            f'Thời hạn: {days} ngày\nThiết bị: {limit}\n'
            f'Hết hạn: {datestring(new_key.expires_at)} (VN)\n'
            'Hãy sao chép Key và chỉ gửi cho người nhận qua kênh tin cậy.',
            home_markup(), sensitive=True,
        )
    if action == 'list' and len(parts) == 2:
        return list_keys(db, chat_id, inactive=parts[1] == 'inactive')
    if action == 'detail' and len(parts) == 2:
        item = find_key(db, parts[1])
        return send(chat_id, key_info(db, item), key_actions(item)) if item else send(chat_id, 'Không tìm thấy License.')
    if action in ('askrevoke', 'askdel') and len(parts) == 2:
        item = find_key(db, parts[1])
        if item is None:
            return send(chat_id, 'Không tìm thấy License.')
        if action == 'askrevoke':
            if item.revoked_at is not None:
                return send(chat_id, 'Key đã bị thu hồi.')
            msg = 'THU HỒI Key ' + item.prefix + '…? Thao tác này làm Key mất hiệu lực.'
            callback = 'revoke:' + item.prefix
        else:
            if item.revoked_at is None and item.expires_at > now_ts():
                return send(chat_id, 'Chỉ xóa được Key hết hạn hoặc đã thu hồi.')
            msg = 'XÓA VĨNH VIỄN Key ' + item.prefix + '…?\nThiết bị và lịch sử bị xóa, KHÔNG thể hoàn tác.'
            callback = 'delete:' + item.prefix
        verb = '🗑 Xóa vĩnh viễn' if action == 'askdel' else '⚠️ Xác nhận thu hồi'
        return send(chat_id, msg, keyboard(((verb, callback),),
                                           (('↩️ Hủy', 'home'),)))
    if action == 'askrenew' and len(parts) == 3 and parts[2].isdecimal():
        item = find_key(db, parts[1])
        days = int(parts[2])
        if item is None:
            return send(chat_id, 'Không tìm thấy License.')
        if item.revoked_at is not None:
            return send(chat_id, 'Không gia hạn được Key đã thu hồi.')
        if not 1 <= days <= 3650:
            return send(chat_id, 'Thời gian gia hạn phải từ 1–3650 ngày.')
        return send(chat_id, f'Xác nhận gia hạn {days} ngày cho {item.prefix}…?',
                    keyboard((('✅ Xác nhận gia hạn', f'renew:{item.prefix}:{days}'),),
                             (('↩️ Hủy', 'home'),)))
    if action in ('revoke', 'delete', 'renew') and len(parts) in (2, 3):
        item = lock_key(db, parts[1])
        if item is None:
            return send(chat_id, 'Không tìm thấy License.')
        if action == 'revoke':
            if len(parts) != 2:
                return send(chat_id, 'Thao tác không hợp lệ.')
            if item.revoked_at is None:
                item.revoked_at = now_ts()
            return send(chat_id, f'Đã thu hồi License {item.prefix}…', home_markup())
        if action == 'delete':
            if len(parts) != 2:
                return send(chat_id, 'Thao tác không hợp lệ.')
            if item.revoked_at is None and item.expires_at > now_ts():
                return send(chat_id, 'Không thể xóa License còn hiệu lực.')
            prefix = item.prefix
            delete_inactive_key(db, item)
            return send(chat_id, f'Đã xóa vĩnh viễn License {prefix}…', home_markup())
        if len(parts) != 3 or not parts[2].isdecimal():
            return send(chat_id, 'Dữ liệu gia hạn không hợp lệ.')
        days = int(parts[2])
        if not 1 <= days <= 3650:
            return send(chat_id, 'Giới hạn gia hạn: 1–3650 ngày.')
        if item.revoked_at is not None:
            return send(chat_id, 'Không gia hạn được License đã thu hồi.')
        # Never extend an expired key from its already-past expiry.
        start = max(now_ts(), item.expires_at)
        if start + days * 86400 > now_ts() + 3650 * 86400:
            return send(chat_id, 'Tổng thời hạn vượt quá 3650 ngày.')
        item.expires_at = start + days * 86400
        return send(chat_id,
                    f'Đã gia hạn License {item.prefix}… thêm {days} ngày.\n'
                    f'Hạn mới: {datestring(item.expires_at)} (VN)', home_markup())
    return send(chat_id, 'Nút này không còn hợp lệ. Hãy chọn /start.', home_markup())


async def telegram_api_call(method: str, payload: dict) -> dict:
    """Send Telegram Bot API requests; never log the bot token or License secret."""
    token = get_settings().telegram_bot_token
    url = 'https://api.telegram.org/bot' + token + '/' + method
    async with httpx.AsyncClient(timeout=12.0) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        result = response.json()
        if not result.get('ok'):
            raise RuntimeError('Telegram Bot API returned an error')
        return result


async def register_webhook() -> None:
    """Register the callback only when all webhook configuration is present."""
    cfg = get_settings()
    base = cfg.telegram_webhook_base_url.rstrip('/')
    if not bot_configured() or not base:
        return
    if not base.startswith('https://'):
        logger.warning('Telegram webhook skipped: provide an HTTPS base URL')
        return
    try:
        await telegram_api_call('setWebhook', {
            'url': base + '/api/v1/telegram/webhook',
            'secret_token': cfg.telegram_webhook_secret,
            'allowed_updates': ['message', 'callback_query'],
        })
        logger.info('Telegram KeyHub webhook registration successful')
    except Exception:
        logger.warning('Telegram webhook registration failed; check bot configuration')


@router.post('/api/v1/telegram/webhook')
async def telegram_webhook(request: Request, db: Session = Depends(get_db)):
    cfg = get_settings()
    if not bot_configured():
        raise HTTPException(404, 'Telegram bot not configured')
    provided_secret = request.headers.get('X-Telegram-Bot-Api-Secret-Token', '')
    if not hmac.compare_digest(provided_secret, cfg.telegram_webhook_secret):
        raise HTTPException(403, 'Telegram webhook secret invalid')
    raw = await request.body()
    if len(raw) > 65536:
        raise HTTPException(413, 'Update too large')
    try:
        import json
        update = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, 'Invalid JSON') from None
    if not isinstance(update, dict):
        raise HTTPException(400, 'Invalid update')
    update_id = update.get('update_id')
    if type(update_id) is not int or not (0 <= update_id < 2**63):
        raise HTTPException(400, 'Invalid update ID')

    message = update.get('message')
    callback = update.get('callback_query')
    source = callback if isinstance(callback, dict) else message
    callback_id = callback.get('id') if isinstance(callback, dict) else None

    if not isinstance(source, dict):
        return {'ok': True}
    sender = source.get('from', {})
    chat = source.get('message', {}).get('chat', {}) if callback else source.get('chat', {})
    if not isinstance(sender, dict) or not isinstance(chat, dict):
        return {'ok': True}
    telegram_user_id = sender.get('id')
    chat_id = chat.get('id')
    if type(telegram_user_id) is not int or type(chat_id) is not int:
        return {'ok': True}
    # Telegram bot actions are never accepted in groups/channels or on behalf of users.
    if chat.get('type') != 'private' or telegram_user_id != chat_id:
        return {'ok': True}

    # Claim each Telegram update transactionally. Retried webhooks cannot create
    # extra keys even when Telegram attempts to redeliver the same update.
    dialect = db.get_bind().dialect.name
    if dialect == 'postgresql':
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == 'sqlite':
        from sqlalchemy.dialects.sqlite import insert
    else:
        insert = None
    if insert is not None:
        result = db.execute(insert(TelegramProcessedUpdate).values(
            update_id=update_id, created_at=now_ts()
        ).on_conflict_do_nothing(index_elements=['update_id']))
        if not result.rowcount:
            db.rollback()
            return {'ok': True}
    elif db.get(TelegramProcessedUpdate, update_id) is not None:
        return {'ok': True}
    else:
        db.add(TelegramProcessedUpdate(update_id=update_id))
        db.flush()

    authorized = telegram_user_id in admin_ids()
    if not authorized:
        reply = send(chat_id, f'Bạn chưa có quyền Admin.\nTelegram ID: {telegram_user_id}\n'
                     'Hãy thêm ID này vào TELEGRAM_ADMIN_IDS trên Render.')
    elif callback:
        reply = process_callback(db, chat_id, str(callback.get('data', ''))[:128])
    else:
        body = str(message.get('text', '')).strip()
        if body.lower().split(' ', 1)[0].split('@', 1)[0] in ('/id', '/myid'):
            reply = send(chat_id, f'Telegram ID của bạn: {telegram_user_id}')
        else:
            reply = process_command(db, chat_id, body or '/help')

    # Send before committing, so failed Telegram deliveries can be retried
    # without issuing an un-delivered new license. The transaction also holds
    # the update_id claim until the response has been delivered.
    try:
        await telegram_api_call('sendMessage', reply)
        db.commit()
    except Exception:
        db.rollback()
        logger.warning('Telegram message delivery failed; update will be retried')
        raise HTTPException(502, 'Telegram message delivery failed') from None

    if isinstance(callback_id, str) and callback_id:
        try:
            await telegram_api_call('answerCallbackQuery', {'callback_query_id': callback_id})
        except Exception:
            logger.warning('Telegram callback acknowledgement failed')
    return {'ok': True}
