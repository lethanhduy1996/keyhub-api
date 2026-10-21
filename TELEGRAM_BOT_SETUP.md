# KeyHub Telegram Manager Bot

Bot Telegram **riêng** cho Admin, sử dụng chung backend Render và database Neon của KeyHub. Không cần cài thêm server và không thay đổi API kích hoạt iOS.

## 1. Tạo bot qua @BotFather

1. Vào Telegram, tìm tài khoản đã xác minh **@BotFather**.
2. Gửi `/newbot`, tạo tên hiển thị và username kết thúc bằng `bot`.
3. Lưu Bot Token vào trình quản lý mật khẩu. **Không gửi token vào chat, GitHub hoặc ảnh chụp màn hình.**
4. Đây là bot riêng (không tích hợp bot nạp tiền đã có).

## 2. Cấu hình trên Render

Trong Render > service API KeyHub > **Environment**, khai báo:

| Biến | Giá trị |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Token mới cấp bởi BotFather |
| `TELEGRAM_WEBHOOK_SECRET` | Chuỗi ngẫu nhiên dài khoảng 32 ký tự, chỉ chữ/số/dấu `_` và `-` |
| `TELEGRAM_WEBHOOK_BASE_URL` | URL HTTPS **gốc** của API Render, ví dụ `https://keyhub-api-s6t3.onrender.com` |
| `TELEGRAM_ADMIN_IDS` | Telegram user ID số nguyên của Admin; nhiều ID cách nhau bằng dấu phẩy |
| `TELEGRAM_OWNER_EMAIL` | Email tài khoản Admin KeyHub đang hoạt động; Key mới sẽ thuộc tài khoản này |

- Không dùng mã License, mật khẩu Admin hoặc API KeyHub thay cho Bot Token.
- Nếu bạn chưa biết Telegram ID, có thể để `TELEGRAM_ADMIN_IDS` trống **tạm thời**, lưu/deploy, nhắn `/start` cho bot: bot sẽ trả Telegram ID của bạn, nhưng **không cho quản lý Key**. Sau đó điền đúng ID vào Render và deploy lại.
- Nếu bỏ trống `TELEGRAM_OWNER_EMAIL`, hệ thống thử dùng `ADMIN_EMAIL` đã có trên Render. Nên cấu hình rõ để dễ quản lý.
- Nếu thiếu `TELEGRAM_BOT_TOKEN` hoặc `TELEGRAM_WEBHOOK_SECRET`, endpoint webhook trả 404 và toàn bộ KeyHub vẫn hoạt động bình thường.
- Sau khi triển khai, webhook tự đăng ký với Telegram. Xem log Render: `Telegram KeyHub webhook registration successful`. Nếu thất bại, kiểm tra các biến môi trường và mạng.
- Không đưa Bot Token vào URL trên trình duyệt hoặc GitHub.

## 3. Sử dụng bot (nhắn riêng)

| Lệnh | Ví dụ |
|---|---|
| Trang chính | `/start` |
| Tạo Key | `/taokey 30 1` – Key 30 ngày/1 máy |
| Xem Key còn hạn | `/danhsachkey` |
| Xem Key hết hạn/thu hồi | `/danhsachkey inactive` |
| Kiểm tra Key | `/kiemtrakey ABC123DEF456` |
| Gia hạn | `/giakhankey ABC123DEF456 7` |
| Thu hồi | `/thukhoikey ABC123DEF456` |
| Xóa Key hết hạn/đã thu hồi | `/xoakey ABC123DEF456` |

Mọi thao tác thay đổi trạng thái bắt đầu bằng màn hình **Xác nhận/Hủy** (nút Telegram). Lệnh xử lý dựa trên **PREFIX 12 ký tự**, không phải toàn bộ chuỗi License bí mật. Bạn cũng có thể sử dụng giao diện nút từ `/start`.

### Bảo mật và lưu ý

- Chỉ xử lý quản lý Key trong **cuộc trò chuyện riêng** với Telegram Admin ID được cấu hình.
- Telegram gửi webhook kèm header `X-Telegram-Bot-Api-Secret-Token`; server xác minh bằng so sánh hằng thời gian.
- Mỗi Telegram `update_id` chỉ được xử lý một lần: tránh việc Telegram thử gửi lại webhook tạo trùng Key.
- Tin nhắn chứa License mới sử dụng `protect_content`, nhưng không thể chống chụp màn hình. Chỉ gửi Key cho người đáng tin cậy.
- Telegram lưu tin nhắn; người quản trị nên xóa tin nhắn chứa License sau khi đã cấp cho khách.
- Bot không cung cấp đường dẫn xem lại nguyên vẹn License đã cấp vì KeyHub chỉ lưu mã băm của License.
- Không xóa Key đang hoạt động. Key hết hạn hoặc bị thu hồi khi xóa sẽ mất lịch sử và thiết bị đi kèm.
- Khi Telegram không nhận được tin nhắn, transaction được rollback để không phát hành Key thất lạc. Một trường hợp hiếm có thể xảy ra: Telegram đã nhận tin nhưng commit database thất bại; nếu gặp phải phải kiểm tra trạng thái Key trước khi gửi cho khách.
- Trên Render Free, lần gọi webhook khi service đang ngủ có thể bị trễ. Telegram thường gửi lại callback khi thất bại.

Tài liệu Telegram: https://core.telegram.org/bots/api#setwebhook

## 4. Kiểm thử

Bộ test SQLite độc lập (không chạm Neon):

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p 'test_device_management_v2.py' -v
```

## 5. Gỡ bot

Xóa `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET` và cấu hình webhook từ Telegram qua công cụ quản trị an toàn; sau đó redeploy Render. Các Key hiện có vẫn giữ nguyên trong Neon.
