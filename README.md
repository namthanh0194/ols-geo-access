# OLS Geo Access

Plugin aaPanel cho OpenLiteSpeed giúp áp dụng chính sách truy cập theo quốc gia trên từng website, đồng thời cho phép các bot đã được xác minh bằng IP chính thức tiếp tục truy cập an toàn.

> Plugin là third-party plugin. Không sửa file core aaPanel trong `class/` hoặc `class_v2/`.

## Tính năng

- Chính sách `VN_ONLY` theo từng website OpenLiteSpeed.
- GeoIP MaxMind GeoLite2 Country, cấu hình Account ID và License Key từ UI.
- Tự tải và cập nhật database GeoIP.
- Allow `GET`/`HEAD` cho bot có IP thuộc feed chính thức:
  - Anthropic / Claude
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
- Uninstall transactional: chỉ xóa file rule đúng checksum, kiểm tra cấu hình và rollback nếu reload lỗi.
- Cập nhật crawler và Jetpack trong một transaction, một lần reload.
- Banner recovery khi deployment bị gián đoạn.
- Tự cấu hình OpenLiteSpeed `useIpInProxyHeader 2` và Cloudflare Trusted Proxy khi cài hoặc nâng cấp.
- Tự kiểm tra CIDR Cloudflare mỗi 6 giờ, có transaction, rollback và UI kiểm tra/sửa chữa.
- UI tiếng Việt: trạng thái feed, lịch sử bot, nguồn `403`, trạng thái triển khai và cấu hình theo domain.

## Nguyên tắc bảo mật

- Bot chỉ bypass với `GET` và `HEAD`.
- `POST`, `PUT`, `PATCH` và `DELETE` của bot vẫn chịu chính sách chặn.
- CDN/proxy như Cloudflare, Fastly, BunnyCDN hoặc image CDN không được coi là bot để bypass toàn website.
- Stripe, Mollie và webhook tương tự phải được allow theo endpoint cụ thể, sau đó ứng dụng tự kiểm tra chữ ký.
- Không trust `User-Agent`; mọi bot trong UI phải khớp IP thuộc snapshot đã tải.
- Dữ liệu runtime, snapshot, secrets, logs và artifact đóng gói không được commit vào Git.
- CIDR Cloudflare chỉ được ghi vào global Trusted Proxy của OpenLiteSpeed, không được thêm vào Geo Access bypass allowlist.
- Hai IP quản trị nội bộ `45.33.54.225/32` và `51.79.248.182/32` được giữ trong allowlist mặc định theo quyết định vận hành của chủ plugin.

## Yêu cầu

- aaPanel đã cài OpenLiteSpeed.
- Quyền `root` để aaPanel cài plugin, tạo cron và ghi cấu hình OpenLiteSpeed.
- Python 3.10 trở lên tại `/usr/bin/python3`.
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

Khi cài, plugin tự tạo các thư mục runtime, cấu hình mặc định, cron cập nhật feed, allowlist IP VPS và Trusted Proxy Cloudflare. Plugin lấy CIDR từ endpoint công khai `https://api.cloudflare.com/client/v4/ips`; không cần Cloudflare API token.

Nếu lần tải trực tiếp lúc cài đặt thất bại, plugin dùng snapshot runtime hoặc snapshot đóng gói hợp lệ mới nhất. Fallback vẫn cấu hình Trusted Proxy nhưng không được tính là lần kiểm tra live thành công. Cài đặt thất bại nếu không còn snapshot fallback hợp lệ hoặc OpenLiteSpeed không vượt qua config test/reload.

## Thiết lập ban đầu trên UI

1. Mở plugin **Quản lý truy cập Geo OLS** trong aaPanel.
2. Vào **Trạng thái hệ thống** và nhập MaxMind **Account ID** cùng **License Key**.
3. Bấm **Tải / cập nhật GeoIP ngay** và kiểm tra database ở trạng thái sẵn sàng.
4. Vào tab **Website**, chọn `VN_ONLY` cho website cần bảo vệ, chọn đúng luồng truy cập và bật rule.
5. Bấm **Lưu và áp dụng**.
6. Vào tab **Bot tìm kiếm** để kiểm tra trạng thái feed và lịch sử request thực tế.

### Luồng truy cập website

- `Truy cập trực tiếp`: client kết nối thẳng tới OpenLiteSpeed.
- `Cloudflare`: plugin tự quản lý CIDR Trusted Proxy; chỉ chọn khi website thực sự đi qua Cloudflare.
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

Plugin tạo hai lịch trong:

```text
/etc/cron.d/ols-geo-access
```

- `03:17` mỗi ngày: tải feed bot và Jetpack.
- Phút `23`, mỗi 6 giờ: tải và xác minh CIDR Cloudflare.

Cloudflare updater không reload OpenLiteSpeed khi ETag/prefix và cấu hình hiệu lực không thay đổi. Khi nguồn tải lỗi hoặc candidate bị từ chối, snapshot và cấu hình đang chạy được giữ nguyên; lần cron lỗi trả nonzero và lần sau tự thử lại.

Sau 24 giờ chưa có lần kiểm tra live thành công, UI chuyển sang cảnh báo. Sau 72 giờ, rule hiện tại vẫn hoạt động nhưng plugin chặn publication mới cho website Cloudflare cho đến khi nguồn được kiểm tra thành công. Website `direct` và `external_origin` không bị freshness gate này ảnh hưởng.

Mọi thay đổi Trusted Proxy dùng cùng deployment lock với rule website, lưu backup và checksum trong `data/proxy-trust-transactions/`, chạy config test, graceful reload khi cần, rồi commit. Config-test hoặc reload lỗi sẽ rollback chính xác; checksum thay đổi ngoài transaction hoặc nhiều transaction chưa hoàn tất sẽ chuyển sang `recovery_required` để tránh ghi đè.

Trong tab **Trạng thái hệ thống**:

- **Kiểm tra Cloudflare ngay** chỉ tải và đánh giá candidate, không ghi cấu hình.
- **Tự động sửa Trusted Proxy** áp dụng snapshot runtime đã xác minh qua transaction và chỉ reload khi cấu hình thay đổi.

Cron feed bot tạo release mới khi dữ liệu thay đổi và có website đang bảo vệ.
Crawler và Jetpack được chuẩn bị trước rồi commit cùng nhau; apply lỗi không làm thay đổi snapshot hoặc allowlist canonical.

Lịch sử bot chỉ quét tối đa 64 MiB dữ liệu log mới nhất và trả tối đa 200 event. UI báo rõ khi kết quả bị cắt ngắn.

Plugin giữ tối đa 10 release, release transaction và operation journal hoàn tất không còn được tham chiếu. Lịch sử GeoIP và proxy-trust giữ tối đa 5 transaction hoàn tất. State hiện tại, state trước đó và mọi recovery chưa hoàn tất không bị prune.

## Cấu trúc dự án

```text
.
├── src/ols_geo_access/     # Mã nguồn plugin
│   ├── data/               # Default configuration files
│   ├── lib/                # Business logic, validation, deploy, feed updater
│   ├── index.html          # UI aaPanel
│   ├── install.sh          # Lifecycle khi cài plugin
│   ├── upgrade.sh          # Migration khi nâng cấp
│   ├── update_feeds.py     # Cron cập nhật feed bot
│   └── update_cloudflare.py # Cron/CLI Cloudflare Trusted Proxy
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
- Snapshot Cloudflare runtime, proxy-trust state và transaction journals.
- Configuration riêng của server: domain, allowlist, exception và state.

## Lưu ý vận hành

- Hãy bật `VN_ONLY` từng website và theo dõi UptimeRobot/bot activity sau khi áp dụng.
- Không mở allowlist theo dải IP thu thập không rõ nguồn.
- Trước khi dùng Cloudflare với rule quốc gia, kiểm tra mục **Cloudflare Trusted Proxy** trong tab **Trạng thái hệ thống**.
- Plugin chặn apply mới nếu Trusted Proxy thiếu CIDR, không ở chế độ Trusted IP Only, quá 72 giờ chưa kiểm tra live thành công hoặc cần recovery; rule đang chạy không bị tự thay đổi.
- Khi uninstall, plugin gỡ rule Geo Access được quản lý nhưng chủ động giữ nguyên global Cloudflare Trusted Proxy để website không mất IP client thật. Muốn xóa các CIDR này phải thực hiện như một thay đổi vận hành riêng.
- Nếu ứng dụng cần webhook, tạo ngoại lệ endpoint nhỏ nhất có thể và dùng kiểm tra chữ ký ở ứng dụng.
- Các khóa cũ `auto_reload`, `blocked_status` và `emergency_disable` trong file runtime được bỏ qua và không còn tác dụng.
