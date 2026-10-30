# OLS Geo Access

Plugin aaPanel cho OpenLiteSpeed và Nginx giúp áp dụng chính sách truy cập theo quốc gia trên từng website, đồng thời cho phép các bot đã được xác minh bằng IP chính thức tiếp tục truy cập an toàn.

> Plugin là third-party plugin. Không sửa file core aaPanel trong `class/` hoặc `class_v2/`.

## Bảo vệ Nginx — từ v0.3.0

- Nginx có đường lưu/áp dụng policy, staging, rollback và khôi phục giao dịch riêng; không dùng cơ chế cấu hình OpenLiteSpeed. Tệp JSON và snapshot thay đổi cùng cấu hình trong giao dịch có backup/checksum.
- Chỉ mở thao tác khi xác minh đúng runtime, module RealIP, module GeoIP2 đã nạp, MMDB hợp lệ và HTTP include phù hợp. Mỗi website phải có extension include ở vị trí an toàn; không tự sửa vhost không đủ điều kiện.
- Hỗ trợ phân tích Lua block ACME, `proxy_cache_path` và rewrite include của aaPanel. Lua rewrite phase hoặc vị trí guard không an toàn vẫn bị từ chối.
- Chạy `nginx -t`, reload có xác minh worker và xác nhận generation qua Unix socket riêng trước khi báo thành công. Khi lỗi, khôi phục cấu hình/settings; từ chối ghi đè file đã bị sửa bên ngoài.
- Cài/nâng cấp chuẩn bị plugin, cron và điều kiện GeoIP2, không tự bật rule. Nếu module đã được nạp thì dùng lại, không build/reload; nếu thiếu, tự biên dịch module từ source có checksum đã ghim, đối chiếu ABI với binary đang chạy, sao lưu cấu hình rồi kiểm tra/reload có xác minh. Không thay binary hoặc nâng cấp Nginx. Cron bỏ qua backend chưa sẵn sàng/chưa kích hoạt. Domain chọn **Tự động** được kiểm tra lúc **03:00 hằng ngày theo giờ máy chủ**, không truy vấn DNS trên từng request.
- CIDR Cloudflare không đổi: cập nhật metadata trong giao dịch, không reload. Uninstall chỉ gỡ artifact do plugin sở hữu, kiểm tra cấu hình và xác minh worker trước khi xóa mã nguồn.
- Tự biên dịch hiện hỗ trợ **Nginx 1.28.3 trên Debian/Ubuntu**; installer chỉ cài thêm dependency build bằng apt khi thiếu, chạy mô phỏng và từ chối nếu cần nâng cấp/gỡ package đang có. Phiên bản chưa có checksum đã ghim bị từ chối, không thử nạp module đoán tương thích. Gói nguồn, archive apt riêng và thư mục build tự xóa sau thành công hoặc lỗi; giữ tối đa 5 backup/giao dịch đã hoàn tất, không xóa giao dịch cần khôi phục.
- Database GeoLite2-Country hợp lệ có sẵn được dùng lại. Nếu thiếu và đã có credentials, installer tự tải từ MaxMind; nếu chưa có, nhập Account ID/License Key một lần trong UI. Thiết lập GeoIP không yêu cầu bật rule trước. Bản này từ chối thay database khi đang có release bảo vệ Nginx, để không làm lệch dữ liệu của runtime.
- Dashboard phân biệt “Chưa kiểm tra” với “Chưa có”; lỗi xác minh hiển thị mã lỗi và lý do từ bộ nhận diện, không kết luận thiếu GeoIP khi chưa kiểm tra runtime.
- Installer khởi tạo feed crawler đang bật theo đường snapshot-only, không triển khai rule hoặc đổi phân nhóm domain. Nếu nguồn feed lỗi, dashboard giữ trạng thái chờ; cron feed tiếp tục thử khi chưa kích hoạt Nginx, tránh vòng lặp “chưa có feed nên không bật được, chưa bật nên không tải feed”. Khi có bảo vệ đang chạy, vẫn dùng cập nhật có giao dịch như trước.

Tag `v0.2.9` chỉ hỗ trợ chẩn đoán Nginx; từ `v0.3.0` có cơ chế bảo vệ Nginx nêu trên. Việc phát hành mã nguồn không tự cập nhật production; người quản trị chủ động cập nhật qua giao diện plugin.

### Sửa lỗi cập nhật OLS & Nhật ký truy cập Nginx — v0.3.5

- Khắc phục lỗi `upgrade.sh` văng `FileNotFoundError` khi cập nhật plugin trên OpenLiteSpeed nếu thư mục release lịch sử trong `generated/releases/` đã bị dọn dẹp hoặc thiếu manifest.

- Tab **Nhật ký truy cập** dùng chung cho Nginx và OpenLiteSpeed. Trên Nginx, API chỉ đọc yêu cầu runtime đã xác minh; vẫn xem được log khi điều kiện bật bảo vệ/GeoIP chưa đầy đủ.
- Đọc log Nginx dạng `combined`, với `access_log /www/wwwlogs/<domain>.log;` hoặc khai báo rõ `combined` trong vhost/include của website. Không tự bật log hoặc thay cấu hình Nginx. Đường dẫn tùy chỉnh, log dùng chung/kế thừa, định dạng tùy chỉnh và log bị tắt đều được báo rõ; không diễn giải thành website an toàn.
- Hỗ trợ IPv4/IPv6 và file xoay vòng chưa nén (`.1`, `.2026-10-29`, `-20261029`). Không đọc log nén, error log, symlink hoặc file đặc biệt. Mỗi lần tải quét tối đa 64 MiB, hiển thị tối đa 200 request của các website đang bật bảo vệ; số liệu là mẫu, không phải tổng lưu lượng.
- Bộ lọc hỗ trợ 24 giờ/7 ngày, website, nguồn IP, quốc gia, HTTP và đối chiếu dự kiến. Quốc gia chưa xác định không bị xem là nước ngoài; bot được nhận diện bằng IP feed, không dựa riêng User-Agent. Thông tin hoạt động crawler lấy từ cùng mẫu đã quét, không quét thêm một lượt log cho bảng feed.
- Đối soát Nginx dùng xác minh release/checksum/runtime hiện có, chỉ lấy request sau lần áp dụng hiện tại làm bằng chứng. Thiếu log, thiếu mẫu VN/quốc tế hoặc cấu hình chưa xác minh được hiển thị riêng. HTTP 403 không chứng minh plugin đã chặn: website/WAF có thể trả cùng mã; GeoIP/feed hiện tại cũng không chứng minh quyết định lịch sử. IP từ `$remote_addr` phụ thuộc cấu hình Trusted Proxy/RealIP đúng.

## Phiên bản 0.2.9 — Nginx chẩn đoán

- Tự xác minh webserver aaPanel đang thực sự phục vụ HTTP/HTTPS và lưu định danh backend; từ chối cài/nâng cấp khi runtime không rõ hoặc khác backend đã lưu.
- OpenLiteSpeed giữ chức năng bảo vệ và lịch cập nhật hiện có. Nâng cấp từ bản cũ tự tạo định danh, không cần template mới trong `data/`.
- aaPanel + Nginx có thể cài để xem dashboard, khả năng module và danh sách website. **Chưa cho phép lưu/áp dụng rule Nginx**, chưa bảo vệ truy cập trên Nginx.
- Chế độ Nginx không cài cron feed/Cloudflare/traffic, không thay cấu hình webserver, không reload Nginx và không cài module GeoIP2. Scheduler cũ chạy vào bản này sẽ bỏ qua backend Nginx.
- Gỡ bản chẩn đoán không can thiệp webserver. Nếu phát hiện state/rule của một bản Nginx khác, installer/upgrader/uninstaller dừng để tránh xóa cấu hình chưa được xác minh.
- Transaction Nginx có kiểm tra xung đột và giữ file phục hồi nhưng chưa được nối vào API ghi; không coi tính năng này là đã sẵn sàng production.

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

- aaPanel chạy OpenLiteSpeed; hoặc Nginx nếu chỉ sử dụng chế độ chẩn đoán.
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

### Luồng truy cập tự động

- Trong tab **Website**, chọn **Tự động (hằng đêm)** ở cột Luồng truy cập rồi **Lưu và áp dụng**. Website đã cấu hình giữ lựa chọn thủ công cũ; website chưa cấu hình mặc định chọn Tự động trên UI.
- Cron kiểm tra DNS A và AAAA lúc **03:00 mỗi ngày theo múi giờ máy chủ**, chỉ cho domain chọn Tự động, độc lập với lượt truy cập website và việc mở aaPanel. Cài đặt mới và nâng cấp đều ghi lịch `0 3 * * *`, thay thế lịch 15 phút cũ. DNS được hỏi qua Google Public DNS HTTPS (mỗi truy vấn timeout 5 giây); máy chủ cần truy cập được `dns.google:443`. Kết quả có thể chậm theo cache/TTL DNS.
- Chỉ nhận diện **Cloudflare** khi toàn bộ IP DNS thuộc snapshot Cloudflare đã xác minh và còn hạn. Chỉ nhận diện **Trực tiếp** khi toàn bộ IP DNS trùng IP công khai đang gán trên interface máy chủ. Không xem mọi IP ngoài Cloudflare là truy cập trực tiếp.
- DNS hỗn hợp, CDN khác, lỗi DNS, thiếu dải Cloudflare hoặc origin sau NAT không có IP công khai trên interface: ghi rõ **chưa xác định** và giữ luồng đang áp dụng. Với NAT/CDN khác, dùng lựa chọn thủ công sau khi xác minh.
- Hai lần kiểm tra hằng đêm nhất quán mới xác nhận luồng mới; có thể mất gần **48 giờ** sau khi DNS thay đổi nếu các lượt kiểm tra thành công. Ngưỡng xác nhận tối thiểu 23 giờ cho phép sai lệch thời gian chạy/DST; kết quả trước quá 36 giờ không được dùng để xác nhận. Mọi lần đổi luồng vẫn qua Trusted Proxy preflight, config-test và transaction/rollback hiện có; không tự nới Trusted Proxy hay sửa policy/chặn index. Khi kiểm tra thất bại, UI hiển thị lý do và giữ cấu hình trước.
- UI hiển thị **Tự động → Cloudflare**, **Tự động → Trực tiếp**, **Chờ nhận diện**, kết quả DNS đang chờ xác nhận, lỗi chưa áp dụng và thời điểm kiểm tra. Khi tab Website đang mở, UI đọc lại kết quả mỗi phút, không chạy DNS và không ghi đè form chưa lưu.
- Website mới chưa có luồng được xác minh: plugin quét DNS ngay khi lưu Tự động lần đầu và cho phép bật bảo vệ nếu nhận diện rõ Cloudflare/Trực tiếp và vượt qua kiểm tra an toàn. Nếu không xác định được, không tự bật bảo vệ; có thể chọn luồng thủ công sau khi xác minh. Với luồng đã lưu nhưng thiếu bản ghi DNS tương ứng, UI báo rõ chưa xác định thời điểm nhận diện, không tự tạo kết quả DNS.
- Trên Nginx, **Đã xác minh cấu hình** yêu cầu bản triển khai đang hoạt động, không có giao dịch chờ khôi phục, HTTP/snippet khớp checksum và metadata quyền quản lý, chính sách website khớp bản triển khai, kiểm tra cấu hình hợp lệ và runtime probe đúng generation. Nhãn này không xác nhận kết quả truy cập thực tế từ Việt Nam/quốc tế. File tồn tại nhưng chưa đủ bằng chứng vẫn là **Có snippet, chưa xác minh quyền quản lý**. Kết quả DNS quá 36 giờ mới bị cảnh báo cũ, phù hợp lịch hằng đêm.
- Trạng thái nhận diện lưu tại `data/traffic_detection.json`; job dùng audit log có rotation hiện có, không tạo thêm file log vô hạn. Gỡ plugin sẽ xóa cron chung như trước.

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
3. Tăng `versions` trong `src/ols_geo_access/info.json`, commit/push và tạo tag mới; không di chuyển tag đã phát hành.
4. Người dùng bấm cập nhật trong aaPanel. Không tự đồng bộ source sang production trong quá trình phát triển.

### Cập nhật thủ công và icon (từ v0.2.2)

- Mỗi lần mở plugin sẽ kiểm tra GitHub trực tiếp, không chờ cache 6 giờ. Khi có bản mới, banner và nút **Cập nhật** xuất hiện; plugin không tự cài đặt.
- Nếu GitHub không truy cập được, giao diện báo lỗi kiểm tra thay vì khẳng định đang dùng phiên bản mới nhất.
- Khi nâng từ v0.2.0/v0.2.1, vào **Trạng thái hệ thống → Kiểm tra ngay → Cập nhật** để bỏ qua cache của bản cũ.
- `sync_icon.py` chạy trong cài đặt/nâng cấp để đồng bộ `icon.png` sang `BTPanel/static/img/soft_ico/ico-ols_geo_access.png`. Giao diện thêm version vào URL icon của plugin khi mở để tránh dùng ảnh cũ từ cache.
- Sau cập nhật, mở lại plugin để nạp giao diện và icon mới. Các thao tác cài/nâng cấp chỉ được kiểm thử với `OLS_GEO_ACCESS_PREFIX` trỏ vào môi trường tạm khi phát triển.

### Xác nhận và kết quả cập nhật (v0.2.3)

- Cập nhật/khôi phục dùng popup `layer` của aaPanel, không dùng hộp thoại xác nhận của trình duyệt. Popup mới chỉ xuất hiện sau khi giao diện v0.2.3 đã được tải.
- Script nâng cấp không restart aaPanel. Plugin đã nạp lại module updater khi backend được tải; giao diện tải lại sau khi nhận kết quả thành công.
- Backend dùng khóa để từ chối cập nhật/khôi phục đồng thời. `data/update-operation.json` lưu mã thao tác và kết quả; chỉ ghi thành công khi luồng cập nhật và dọn tệp tạm đã trả về.
- Nếu mất phản hồi, giao diện chỉ truy vấn `get_update_status` tối đa 30 lần, không tự gửi lại lệnh cài. Số version trong `info.json` riêng lẻ không được dùng làm bằng chứng hoàn tất.
- Nếu vẫn không xác định được kết quả, các nút thao tác được giữ khóa và giao diện yêu cầu kiểm tra lại. Không bấm cài lại liên tục.
- Khôi phục trả lại mã nguồn backup và giữ cấu hình hiện tại; không chạy script nâng cấp của bản cũ vì script đó có thể restart aaPanel.

### Sửa tương thích nâng cấp (v0.2.6)

- Updater cũ giữ nguyên thư mục `data/`, nên nâng cấp không được phụ thuộc vào template mới trong thư mục này. Script nâng cấp tự tạo `traffic_detection.json` rỗng bằng cơ chế ghi atomic hiện có nếu chưa có file, với quyền `0600`.
- Trạng thái nhận diện đã có được giữ nguyên và sao lưu trước migration. Nếu migration hoặc bước khởi tạo Cloudflare thất bại, khôi phục trạng thái cũ hoặc xóa riêng file trạng thái vừa tạo; không reset cấu hình website, dữ liệu riêng hay log.
- Backend nạp lại bảng đường dẫn dữ liệu khi hot reload để nhận diện file trạng thái mới, không cần khởi động lại aaPanel.
- Kiểm thử tương thích dùng mã nguồn và updater thật từ các tag phiên bản cũ, bao gồm trường hợp thiếu cả file trạng thái lẫn template nhận diện.

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
