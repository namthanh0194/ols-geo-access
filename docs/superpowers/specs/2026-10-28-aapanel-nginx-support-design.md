# Thiết kế hỗ trợ aaPanel + Nginx

Ngày: 2026-10-28. Trạng thái: bản đề xuất chờ duyệt; chưa cho phép triển khai.

## 1. Mục tiêu và giới hạn

Mở rộng cùng plugin để hỗ trợ OpenLiteSpeed (OLS) và Nginx do aaPanel quản lý, giữ chính sách truy cập và trải nghiệm cập nhật thống nhất. Không tạo bản fork Nginx với vòng đời phát hành riêng.

Lượt thiết kế chỉ viết tài liệu trong repository. Không sửa runtime, cài module, chạy config-test trên VPS, reload webserver, phát hành hay bật bảo vệ website. VPS khảo sát đang phục vụ website thật, không phải sandbox mặc định.

Giữ ID/thư mục `ols_geo_access`, tên hiển thị hiện tại, backend entrypoint và định dạng gói để updater hiện tại tiếp tục tìm thấy plugin. UI bổ sung thông tin webserver; đổi tên thương hiệu không thuộc phạm vi bản đầu.

## 2. Dữ kiện khảo sát và điểm chưa biết

- VPS khảo sát: Ubuntu 22.04.5, aaPanel khai báo 8.0.7, Nginx aaPanel 1.28.3 đang lắng nghe 80/443; múi giờ UTC+7.
- Inventory có 27 website (8 PHP, 19 proxy). Có thêm Nginx/OpenResty trong Docker, không thuộc phạm vi plugin.
- Binary mục tiêu: `/www/server/nginx/sbin/nginx`. Main config và prefix phải được xác minh từ tiến trình đang chạy, không chỉ suy ra từ tên binary.
- Có Real IP trong build; chưa thấy GeoIP2 trong build/module nạp hoặc memory maps. Có thư viện libmaxminddb, nhưng đó không phải module Nginx GeoIP2.
- 24/33 file config cấp đầu có include extension; số file config không đồng nghĩa số website. Không giả định mọi website đều có điểm chèn hợp lệ.
- Chưa kiểm chứng ABI của module GeoIP2, MMDB đọc được bởi runtime, toàn bộ chuỗi include, các override Real IP hoặc rewrite/location đặc biệt của từng site. Đây là điều kiện triển khai cần kiểm tra, không phải khả năng đã xác nhận.

## 3. Phương án và quyết định đề xuất

### Cấu trúc plugin

1. Hai plugin/fork độc lập: giảm giao thoa ban đầu nhưng nhân đôi updater, feeds, giao diện và sửa lỗi. Không chọn.
2. Một plugin với bộ xử lý riêng từng webserver: dùng chung tính năng nghiệp vụ, cách sinh và vận hành config tách riêng. Chọn làm hướng thiết kế.
3. Chèn nhiều nhánh `if nginx` rải rác vào mã OLS: ít thay đổi ban đầu nhưng khó kiểm chứng rollback và đường uninstall. Không chọn.

### GeoIP trên Nginx — đề xuất chờ người dùng duyệt

Chọn GeoIP2 + cùng cơ sở dữ liệu MaxMind Country MMDB cho phiên bản Nginx đầu tiên, để không thay nguồn xác định quốc gia giữa hai backend. Module Nginx GeoIP2 và MMDB hợp lệ là điều kiện bật bảo vệ, không là điều kiện mở giao diện chẩn đoán.

Phương án `geo` + danh sách CIDR Việt Nam tránh phụ thuộc module GeoIP2 nhưng cần thêm nguồn/chuyển đổi dữ liệu, freshness, kiểm thử tương đương và vận hành riêng. Không làm đồng thời hai cơ chế ở bản đầu. Nếu không thể cung cấp module tương thích mà không thay binary Nginx, dừng để người dùng chọn lại, không âm thầm chuyển sang CIDR.

Plugin không tự build, tải `.so`, thay binary hoặc thêm `load_module` trong install/upgrade. Việc chuẩn bị module trên VPS là tác vụ riêng, phải có phê duyệt riêng. Hiện chưa khẳng định VPS khảo sát có thể nạp module động mà không build lại Nginx.

## 4. Ranh giới mã nguồn

### Dùng chung

- Validation chính sách, nguồn IP crawler/dịch vụ, ngoại lệ WooCommerce, IP tin cậy.
- Tải/kiểm tra MMDB, snapshot feeds, giới hạn log và audit.
- DNS auto detection: 03:00 theo giờ máy chủ, hai kết quả nhất quán, ngưỡng 23–36 giờ hiện có; không truy vấn DNS theo mỗi request.
- UI, cập nhật GitHub, checksum, backup gói và dọn rác.

### Tách theo backend

- Phát hiện runtime, inventory và đường dẫn website, sinh rule và kiểm tra context.
- Cài cấu hình GeoIP, Trusted Proxy/Real IP, kiểm tra config, reload và xác nhận hiệu lực.
- Bộ đọc access log nếu định dạng khác OLS; UI không báo số liệu suy đoán khi parser không hỗ trợ.
- Danh sách file được sở hữu, trạng thái triển khai, backup/recovery và uninstall.

Giữ `OLSAdapter` và hành vi hiện tại; bổ sung bộ xử lý Nginx. Không tái cấu trúc toàn bộ parser OLS hay viết framework webserver tổng quát. Rà đủ các entrypoint: backend UI, install/upgrade/uninstall, update feeds, update Cloudflare, cập nhật MMDB và update traffic; không để cron Nginx gọi lệnh OLS còn hardcode.

## 5. Nhận diện runtime và inventory

Đối chiếu cấu hình aaPanel, executable/master PID, main config/prefix và tiến trình phục vụ listener. Loại trừ container bằng namespace/cgroup; không coi tên `nginx` hoặc cài binary là bằng chứng đủ. Apache, runtime mơ hồ, nhiều ứng viên hoặc webserver đã đổi => chế độ chẩn đoán, không ghi cấu hình.

Đọc database aaPanel bằng kết nối read-only; xác minh schema/site records ở vị trí thực tế. Nếu có nhiều DB không nhất quán, báo xung đột thay vì lấy danh sách trống để dọn rule. Ánh xạ site ID với vhost, aliases và server blocks HTTP/HTTPS; không tạo rule theo Host header do client tự khai báo.

Mọi entrypoint dùng cùng runtime context và khóa triển khai. Kiểm tra lại identity/checksum trước ghi và trước reload. Không tự chuyển OLS sang Nginx hoặc ngược lại. Khi đổi webserver, chặn áp dụng tự động cho đến khi có luồng chuyển đổi được người dùng xác nhận.

Persist backend identity sau lần xác nhận đầu tiên. Với cài đặt cũ, chỉ gán OLS ownership khi manifest/đường dẫn legacy và cấu hình khớp provenance OLS; thiếu hoặc mâu thuẫn bằng chứng thì vào chẩn đoán. Phát hiện Nginx đang chạy không được dùng để chuyển ownership của state OLS. Cài mới không có state phải đi qua preflight trước khi ghi identity.

## 6. Bố trí cấu hình Nginx

- Một file chỉ thuộc plugin ở context `http` chứa GeoIP2 và các biến `geo`/`map` cần dùng, tên dự kiến `00-ols-geo-access-http.conf`. Chỉ dùng glob include vhost hiện có nếu đã xác minh context và thứ tự nạp; gặp file trùng tên không do plugin quản lý thì từ chối.
- Mỗi site dùng snippet `extension/<site>/00-ols-geo-access.conf` ở context `server`, chỉ tác động site được bật. Snippet tham chiếu biến quyết định và trả 403 khi bị chặn; không thay PHP handler, proxy upstream, SSL, redirect hay location của người dùng.
- Không đặt `map`/`geoip2` trong include ở context `server`. Đảm bảo thứ tự khai báo biến đúng khi chạy config-test toàn bộ cây cấu hình.
- Site thiếu include, include sai context, chỉ bao phủ một server block, hoặc config quá phức tạp để xác minh an toàn: hiển thị `Chưa hỗ trợ áp dụng` và lý do. Không tự chèn include vào vhost của người dùng trong bản đầu.
- Phân tích token/braces/includes có giới hạn; không dùng regex thay hàng loạt file Nginx. Từ chối symlink, traversal, vòng include và file ngoài danh sách sở hữu.
- Uninstall gỡ snippet site trước, rồi cấu hình dùng chung khi hết tham chiếu; chỉ xóa file khớp checksum đã ghi nhận. Không gỡ module do quản trị viên cài.

## 7. IP thật, GeoIP và thứ tự chính sách

Với site Cloudflare, chỉ tin `CF-Connecting-IP` nếu peer trực tiếp nằm trong snapshot Cloudflare đã xác minh. Không tin header từ nguồn tùy ý; không đặt `set_real_ip_from 0.0.0.0/0` hay `::/0`. CIDR Cloudflare dùng để xác minh proxy, không phải allowlist cho toàn bộ khách truy cập.

Phân biệt peer gốc và client IP sau Real IP. Dùng cùng client IP đã xác minh cho GeoIP, bot và ngoại lệ. Kiểm tra Real IP kế thừa/override ở http/server/location; xung đột thì báo và dừng, không tự ghi đè cấu hình đang dùng. Site trực tiếp không được bỏ qua kiểm soát chỉ vì nhận header Cloudflare giả. Proxy/CDN khác chưa xác minh vẫn bị chặn kích hoạt tự động như hiện tại.

Trust do plugin tạo chỉ nằm trong các server block Cloudflare đang bật bảo vệ, không ghi Real IP ở http dùng chung. Chỉ chấp nhận cấu hình kế thừa nếu chứng minh cùng header, tập proxy được tin và không có override làm mở rộng quyền; trường hợp khác bị chặn preflight. Peer Cloudflare nhưng header thiếu, không phải một IP hợp lệ hoặc không được Real IP xử lý đúng => không coi địa chỉ edge là client để cấp ngoại lệ bot/GeoIP; từ chối request đó. Test kiểm tra cả site tắt bảo vệ và site trực tiếp không bị thay đổi cách xử lý IP.

Giữ thứ tự nghiệp vụ OLS đang có:

1. Ngoại lệ WooCommerce đúng site, IP/CIDR, path và method.
2. IP tin cậy thủ công, đúng phạm vi và điều kiện.
3. Cron nội bộ được giới hạn nguồn/path/method.
4. ACME challenge và health-check được khai báo.
5. Crawler đã xác minh bằng snapshot IP, chỉ GET/HEAD, gồm HTML và tài nguyên preview theo chính sách hiện hành; User-Agent không tự cấp quyền.
6. Client thuộc VN được đi tiếp; còn lại trả 403.

Không biến việc allow thành `return 200`; request được phép phải tiếp tục qua xử lý website. Giữ ý nghĩa tùy chọn chặn index, robots/header hiện tại; không đồng nhất nó với chặn mọi bot. Định nghĩa rõ path chuẩn hóa, query string, phân biệt hoa thường, encoded path, internal redirect và alias trong bộ test tương đương hai backend. Một domain không được dùng ngoại lệ của domain khác.

Không tra cứu quốc gia qua HTTP API trên mỗi request. MMDB lỗi/thiếu hoặc module thiếu => không bật rule mới, báo rõ nguyên nhân. Khi cập nhật dữ liệu thất bại giữ snapshot/MMDB hợp lệ trước; không tự mở toàn bộ truy cập.

## 8. Transaction, recovery và reload

Các đường thao tác đều qua cùng quy trình:

1. Khóa deployment; xác minh runtime, inventory, module, MMDB, trust và tình trạng recovery.
2. Dựng candidate ngoài include đang hoạt động; validate đường dẫn, cú pháp và semantic fixtures.
3. Sao lưu byte/checksum/quyền của mọi file bị thay đổi; ghi journal trước mutation. Kiểm tra lại baseline để phát hiện sửa bên ngoài.
4. Ghi từng file bằng atomic replace theo thứ tự phụ thuộc. Nhiều file không phải một transaction filesystem nguyên tử; journal và recovery phải bao phủ từng điểm dừng.
5. Chạy đúng binary Nginx, main config và prefix của aaPanel để kiểm tra toàn bộ cấu hình; chưa reload nếu không đạt.
6. Reload đúng master đã xác minh, không `killall nginx` hoặc `systemctl restart nginx` chung. Kiểm tra thế hệ worker mới, lỗi sau reload và probe site canary phù hợp; exit code của lệnh gửi signal không đủ để báo thành công.
7. Thành công mới commit state. Thất bại khôi phục toàn bộ file/state, config-test lại và reload bản trước nếu cần; nếu không chứng minh recovery an toàn, đánh dấu `recovery_required`, dừng cron mutation.

Journal/release/backup/trust state của Nginx tách khỏi OLS. Để tương thích rollback gói cũ, giữ đường dẫn legacy OLS và chỉ nhận manifest không có backend là OLS khi xác minh được provenance theo mục 5; backend Nginx có namespace riêng và identity rõ ràng. Không dùng release OLS để áp dụng/khôi phục lên Nginx.

Journal ghi bền vững trước mỗi bước có side effect, với các mốc prepared/files-written/config-validated/reload-requested/verified/committed và rollback/recovery-required. Nếu reload đã thành công nhưng probe thất bại, phải khôi phục file, kiểm tra, reload bản trước và xác minh lại runtime; không chỉ restore disk. Khi tiến trình chết giữa các bước, phân loại file thực tế bằng checksum và đối chiếu runtime trước khi chọn finalize/rollback. Không chứng minh được trạng thái worker, hoặc khôi phục/config-test/reload lại thất bại => `runtime_unknown/recovery_required`; giữ bằng chứng và chặn mọi mutation cron.

Phân biệt cài mới thiếu khả năng với deployment đang bật nhưng bị suy giảm. Trường hợp thứ hai giữ nguyên state/backup và báo cần khôi phục, không tự uninstall. Một thao tác cleanup riêng được người dùng xác nhận có thể gỡ các file sở hữu còn nguyên checksum và tham chiếu GeoIP bị hỏng, dù preflight bật bảo vệ không đạt; phải cảnh báo bảo vệ sẽ tắt và config-test/reload đúng runtime trước khi báo thành công. Backend identity đã đổi hoặc file bị sửa bên ngoài => không cleanup tự động, giữ state và yêu cầu phục hồi thủ công. Uninstall không được xóa journal/backup khi cleanup chưa được xác minh.

Không nới checksum chỉ vì file mất. Chỉ thu hồi ownership của site đã xóa khi xác nhận cả inventory và cấu hình tương ứng không còn; site còn tồn tại mà mất rule vẫn là lỗi. Rollback release lịch sử không được tự tạo lại vhost cho site đã xóa.

## 9. Giao diện và lifecycle

- Thể hiện webserver, phiên bản, GeoIP2/MMDB, trust, khả năng áp dụng từng site và nguyên nhân bị chặn.
- Domain thủ công giữ nguyên; auto tiếp tục hằng đêm. UI báo rõ dữ liệu cũ, chờ xác nhận hoặc lỗi DNS, không đổi thành công khi chỉ mới lưu mong muốn.
- Preview thay đổi và popup xác nhận kiểu aaPanel; giữ dark/light theo aaPanel, không thêm công tắc theme.
- Cài trên Nginx chưa đủ module chỉ mở chẩn đoán; không sinh rule, không tải module hay reload. Cron không đủ điều kiện phải trả trạng thái có cấu trúc, không tự sửa để vượt preflight.
- Upgrade OLS bảo toàn data và template migration tương thích updater cũ; không ghi lại rule chỉ do cập nhật mã plugin. Upgrade Nginx kiểm tra backend trước mọi tác vụ lifecycle.
- Updater cần chặn rollback về gói chỉ hỗ trợ OLS khi đang dùng Nginx; ghi capability/backend tối thiểu, không đánh giá chỉ theo tên version. Gói cũ có thể chứa cron/uninstall chỉ dành cho OLS.
- Rollback mã plugin không đồng nghĩa rollback schema/config/cron. Trước khi thay code phải xác minh tương thích state và lưu đủ trạng thái lifecycle để khôi phục khi upgrade thất bại; không báo rollback thành công chỉ vì đã chép lại file Python. Kiểm thử việc hot reload backend sau nâng cấp, gồm registry/module backend mới.
- Log 10MB × 5 bản, quyền 0600; backup retention và dọn zip/thư mục tạm giữ cơ chế hiện tại. Không commit log, DB, key SSH hoặc cấu hình thực tế chứa thông tin riêng của VPS.

## 10. Tiêu chí nghiệm thu

Tất cả test/script/fixture/artifact kỹ thuật nằm trong `tmp/`, không commit/deploy mặc định.

- Hồi quy toàn bộ OLS trước/sau refactor; đường nâng cấp dùng updater thật từ tag cũ.
- Detection chọn đúng aaPanel Nginx dù có Nginx/OpenResty trong Docker; đổi runtime/mơ hồ phải dừng.
- Thiếu GeoIP2/MMDB/include chỉ hiện chẩn đoán, không ghi vhost, không reload.
- Request matrix: VN/ngoài VN/unknown, IPv4/IPv6, client thật qua CF, header giả từ peer không tin, GET/HEAD/POST, bot thật/UA giả, static preview, WooCommerce đúng/sai điều kiện, ACME, PHP/proxy, alias, HTTP/HTTPS và site không bật.
- GeoIP và allowlist sử dụng IP thật đúng giai đoạn xử lý, kể cả Real IP kế thừa và internal redirects; không allow toàn bộ IP edge Cloudflare.
- Fault injection ở ghi file, config-test, reload bị từ chối/không có worker mới, probe thất bại, process chết, recovery, external edit, symlink/path traversal và site bị xóa.
- Cấu hình shared còn tham chiếu không bị xóa; không đụng Nginx container; uninstall chỉ tác động file sở hữu.
- Auto vẫn 03:00, đủ hai lần nhận diện; feed/MMDB/trust updates dùng đúng backend, cleanup/rotation vẫn đạt.

## 11. Trình tự triển khai sau khi duyệt thiết kế

1. Lập kế hoạch mã nguồn theo các ranh giới trên, bao gồm kiểm thử tái hiện trước thay đổi.
2. Phát triển và kiểm thử trong môi trường cô lập; giữ OLS chạy như trước.
3. Đánh giá riêng khả năng bổ sung GeoIP2 tương thích; nếu cần thay binary, dừng xin quyết định khác.
4. Chỉ sau phê duyệt triển khai riêng: chuẩn bị module nếu phù hợp và chọn một website canary do người dùng chỉ định trên VPS. Không tự chọn website đang kinh doanh để thử.
5. Chứng minh policy, reload và rollback trên canary; sau đó mới đề xuất tăng version/phát hành. Người dùng cập nhật thủ công, không tự deploy production OLS.

Phê duyệt tài liệu này không phải phê duyệt cài module hoặc thử chặn request trên VPS. Cần quyết định riêng cho các hành động đó.

## 12. Nguồn đối chiếu

Tài liệu gốc đã đọc ngày 2026-10-28; URL ghi dạng code để tra cứu:

- Nginx Real IP: `https://nginx.org/en/docs/http/ngx_http_realip_module.html`.
- Nginx map và context http: `https://nginx.org/en/docs/http/ngx_http_map_module.html`.
- Module GeoIP2, MMDB/libmaxminddb, build/load: `https://github.com/leev/ngx_http_geoip2_module`.
- Nginx reload/master/worker: `https://nginx.org/en/docs/control.html`.
- Nguồn dự án đã đối chiếu: `ols_geo_access_main.py`, `lib/ols_adapter.py`, `lib/config_generator.py`, `lib/config_validator.py`, `lib/domain_inventory.py`, `lib/paths.py`, `update_cloudflare.py`, lifecycle scripts.
