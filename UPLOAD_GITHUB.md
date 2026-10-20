# Backend KeyHub - upload GitHub bằng iPhone

Đây là backend FastAPI độc lập, sử dụng PostgreSQL của bạn, không gọi API PPAPIKey.

## Các tệp cần đưa lên GitHub

Ở thư mục gốc của repo phải có:

- `render.yaml`
- `requirements.txt`
- `app/__init__.py`
- `app/bootstrap_admin.py`
- `app/config.py`
- `app/db.py`
- `app/main.py`
- `app/models.py`
- `app/schemas.py`
- `app/security.py`

Không upload file `.env`, password hay URL kết nối cơ sở dữ liệu vào GitHub.

## Render (qua Blueprint)

Truy cập Render Dashboard > Blueprints > New Blueprint Instance > kết nối repo.
Trong màn hình yêu cầu biến môi trường, nhập:

- DATABASE_URL: URL Neon, đổi tiền tố `postgresql://` thành `postgresql+psycopg://`, GIỮ nguyên phần còn lại và `?sslmode=require`.
- ADMIN_EMAIL: email admin bạn sẽ đăng nhập.
- ADMIN_PASSWORD: mật khẩu mạnh >= 12 ký tự, riêng với các dịch vụ khác.
- ALLOWED_ORIGINS: địa chỉ web Pages đã triển khai, ví dụ `https://keyhub-myname.pages.dev`, không có dấu gạch chéo cuối.

JWT_SECRET và KEY_PEPPER được Render tạo ngẫu nhiên (không điền tay).

Lưu ý: `bootstrap_admin` chạy khi server khởi động, tạo admin lần đầu hoặc nâng quyền email đã tồn tại; KHÔNG đổi mật khẩu admin hiện có. Bảo vệ tài khoản Render.

## Kiểm thử sau deploy

Mở `https://TEN-RENDER-CUA-BAN.onrender.com/api/v1/health` trên Safari.
Phải trả về `{ "status": "ok" }`.

## Giới hạn an toàn

Bản này chỉ cho thử nghiệm có kiểm soát. Trước khi bán key / mở đăng ký công khai cần rate limits, backup, migrations, monitoring, MFA admin, email recovery, bảo vệ thiết bị, quy trình vận hành và kiểm tra an ninh.
