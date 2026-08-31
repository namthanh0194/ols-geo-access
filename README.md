# OLS Geo Access

Plugin aaPanel cho OpenLiteSpeed giúp áp dụng chính sách truy cập theo quốc gia trên từng website, đồng thời cho phép các bot đã được xác minh bằng IP chính thức tiếp tục truy cập an toàn.

> Plugin là third-party plugin. Không sửa file core aaPanel trong `class/` hoặc `class_v2/`.

## Tính năng

- Chính sách `VN_ONLY` theo từng website OpenLiteSpeed.
- GeoIP MaxMind GeoLite2 Country, cấu hình Account ID và License Key từ UI.
- Tự tải và cập nhật database GeoIP.
- Allow `GET`/`HEAD` cho bot có IP thuộc feed chính thức:
  - Googlebot
  - Bingbot
  - Applebot
  - DuckDuckBot
  - OAI-SearchBot và ChatGPT-User
  - PerplexityBot
  - UptimeRobot
- Tự cập nhật feed IP bot hằng ngày bằng cron.
- Tự thêm IP public của VPS vào allowlist khi cài plugin.
- Chỉ allow bot đã xác minh theo IP; `User-Agent` không được dùng làm bằng chứng xác thực.
- Audit, staging, kiểm tra cấu hình OpenLiteSpeed và rollback khi không thể áp dụng rule website.
- UI tiếng Việt: trạng thái feed, lịch sử bot, nguồn `403`, trạng thái triển khai và cấu hình theo domain.

## Nguyên tắc bảo mật

- Bot chỉ bypass với `GET` và `HEAD`.
- `POST`, `PUT`, `PATCH` và `DELETE` của bot vẫn chịu chính sách chặn.
- CDN/proxy như Cloudflare, Fastly, BunnyCDN hoặc image CDN không được coi là bot để bypass toàn website.
- Stripe, Mollie và webhook tương tự phải được allow theo endpoint cụ thể, sau đó ứng dụng tự kiểm tra chữ ký.
- Không trust `User-Agent`; mọi bot trong UI phải khớp IP thuộc snapshot đã tải.
- Dữ liệu runtime, snapshot, secrets, logs và artifact đóng gói không được commit vào Git.

## Yêu cầu

- aaPanel đã cài OpenLiteSpeed.
- Quyền `root` để aaPanel cài plugin, tạo cron và ghi cấu hình OpenLiteSpeed.
- Python 3 có sẵn trên server.
- Tài khoản MaxMind khi muốn tự tải `GeoLite2-Country.mmdb`.

## Cài đặt

### 1. Đóng gói plugin

```sh
cd /root/ols-geo-access
sh scripts/package.sh
```

File ZIP được tạo tại:

```text
dist/ols_geo_access-0.1.0.zip
```

### 2. Import vào aaPanel

Trong UI aaPanel, import file ZIP như một third-party plugin. Plugin được cài tại:

```text
/www/server/panel/plugin/ols_geo_access
```

Khi cài, plugin tự tạo các thư mục runtime, cấu hình mặc định, cron cập nhật feed và allowlist IP VPS.

## Thiết lập ban đầu trên UI

1. Mở plugin **Quản lý truy cập Geo OLS** trong aaPanel.
2. Vào **Trạng thái hệ thống** và nhập MaxMind **Account ID** cùng **License Key**.
3. Bấm **Tải / cập nhật GeoIP ngay** và kiểm tra database ở trạng thái sẵn sàng.
4. Vào tab **Website**, chọn `VN_ONLY` cho website cần bảo vệ, chọn đúng luồng truy cập và bật rule.
5. Bấm **Lưu và áp dụng**.
6. Vào tab **Bot tìm kiếm** để kiểm tra trạng thái feed và lịch sử request thực tế.

### Luồng truy cập website

- `Truy cập trực tiếp`: client kết nối thẳng tới OpenLiteSpeed.
- `Cloudflare`: chỉ chọn khi website thực sự đi qua Cloudflare và IP client đã được cấu hình tin cậy đúng cách.
- `Proxy/CDN khác`: chỉ chọn khi đã xác minh cách proxy truyền IP client.

## Tab Bot tìm kiếm

Tab này hiển thị:

- IPv4/IPv6, nguồn và thời điểm cập nhật của từng feed bot.
- Trạng thái feed: sẵn sàng, quá hạn, chưa tải hoặc không hợp lệ.
- Lần truy cập gần nhất của bot có IP đã xác minh.
- Phân loại `403`:
  - **Lịch sử trước khi áp dụng**: request cũ hơn release hiện hành.
  - **Plugin chặn đúng**: bot dùng method không được bypass, ví dụ `POST`.
  - **Website/WAF trả 403**: bot `GET`/`HEAD` đã qua Geo Access nhưng lớp phía sau trả lỗi.
  - **Có thể lỗi rule**: checksum feed hoặc file rule triển khai không khớp release.
  - **Chủ ý chặn bot index**: website được đánh dấu không cho bot index.

Nếu một website chủ ý chặn index, tick **Chặn index** tại tab **Website**. Tùy chọn này chỉ giúp phân loại lịch sử bot; không tự sửa `robots.txt`, WordPress, Cloudflare hoặc rule OpenLiteSpeed.

## Cập nhật tự động

Plugin tạo cron chạy mỗi ngày lúc `03:17`:

```text
/etc/cron.d/ols-geo-access
```

Cron tải feed bot mới. Nếu feed thay đổi và có website đang bảo vệ, plugin tạo release mới và áp dụng lại rule.

## Cấu trúc dự án

```text
.
├── src/ols_geo_access/     # Mã nguồn plugin
│   ├── data/               # Default configuration files
│   ├── lib/                # Business logic, validation, deploy, feed updater
│   ├── index.html          # UI aaPanel
│   ├── install.sh          # Lifecycle khi cài plugin
│   ├── upgrade.sh          # Migration khi nâng cấp
│   └── update_feeds.py     # Cron cập nhật feed bot
├── scripts/package.sh      # Đóng gói ZIP
├── docs/                   # Thiết kế và kế hoạch triển khai
└── AGENTS.md               # Quy tắc source và production
```

## Phát triển và triển khai

Mã nguồn duy nhất nằm tại:

```text
/root/ols-geo-access
```

Không sửa trực tiếp plugin đang chạy trong:

```text
/www/server/panel/plugin/ols_geo_access
```

Quy trình:

1. Sửa source trong `/root/ols-geo-access`.
2. Kiểm tra và đóng gói ZIP.
3. Đồng bộ hoặc import plugin vào aaPanel.
4. Đối chiếu source và production bằng `cmp`.

## Dữ liệu không commit

`.gitignore` loại trừ các dữ liệu nhạy cảm và runtime như:

- `tmp/`, `dist/`, Python cache.
- MaxMind credentials và mọi secrets.
- Snapshot IP bot, logs, release state, generated rules.
- Configuration riêng của server: domain, allowlist, exception và state.

## Lưu ý vận hành

- Hãy bật `VN_ONLY` từng website và theo dõi UptimeRobot/bot activity sau khi áp dụng.
- Không mở allowlist theo dải IP thu thập không rõ nguồn.
- Trước khi dùng Cloudflare với rule quốc gia, cần đảm bảo OpenLiteSpeed nhận đúng IP client thay vì IP proxy.
- Nếu ứng dụng cần webhook, tạo ngoại lệ endpoint nhỏ nhất có thể và dùng kiểm tra chữ ký ở ứng dụng.
