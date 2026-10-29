# Hoàn thiện bảo vệ Nginx — phạm vi đã duyệt

Chỉ sửa source `/root/ols-geo-access`, kiểm thử trong `tmp/`, SSH VPS 51.79.248.182 chỉ đọc. Không cài module, không sửa/reload production, không tăng version, commit hoặc push trong đợt này.

1. Preflight VPS, MMDB, module, include và định danh; tái hiện bất tương thích bằng fixture.
2. Nối chính sách vào transaction Nginx, journal cả cấu hình và settings; probe thế hệ cấu hình đã nạp; chặn endpoint chưa hỗ trợ.
3. Hoàn thiện gỡ/nâng cấp/cron đúng backend, giữ lịch 03:00; rollback bảo toàn quyền sở hữu và dữ liệu.
4. Kiểm thử Nginx thật cô lập, failpoints/rollback, migration updater cũ và hồi quy OLS, review cuối.

## Ledger
- Preflight chỉ đọc: Nginx aaPanel đúng runtime; RealIP có, GeoIP2 chưa có, MMDB `/www/server/panel/data/GeoLite2-Country.mmdb` chưa có. 27 website: 24 gặp parser với Lua trong include well-known aaPanel, 3 thiếu include extension hợp lệ. Đây là các chặn triển khai thật, không tự sửa VPS.
- Ruling: hỗ trợ lexer cho block Lua như khối opaque có giới hạn, không diễn giải Lua thành cấu hình Nginx. Lua chạy trước guard hoặc có phase không chứng minh được phải bị từ chối bảo vệ.
- Ruling: HTTP artifact dùng wildcard include HTTP đã có của aaPanel trong vhost root, không tự sửa nginx.conf. Phải xác minh đúng một include ở HTTP scope; giữ khả năng đọc target cũ cho test và transaction cũ.
- Ruling: probe dùng HTTP trên Unix socket riêng dưới thư mục plugin, không mở cổng mạng công khai, không dựa vào URL tùy ý bên ngoài.
- Ruling: thiếu GeoIP2/MMDB tiếp tục khóa áp dụng và hiển thị điều kiện thiếu; không hứa VPS có thể bật bảo vệ trước khi được duyệt cài các điều kiện này.

## Kết quả triển khai source

- Audit lại chỉ đọc: parser mới nhận diện được 24/27 website; 3 website còn thiếu extension include đúng vị trí. Không sửa vhost. Nginx master vẫn PID 3053376, chưa nạp GeoIP2. Đính chính đường dẫn MMDB mặc định thực tế là `/usr/local/share/GeoIP/GeoLite2-Country.mmdb`, đã kiểm tra và chưa có.
- Đã nối policy với transaction Nginx, release settings bất biến, backup/restore settings, probe generation, recovery API khi thiếu điều kiện, lifecycle và cron theo backend. Giữ nguyên version 0.2.9.
- Recovery ưu tiên nhận diện journal chưa hoàn tất trước khi so checksum file ghi dở. UI vẫn cho kiểm tra/khôi phục khi thiếu module/MMDB; khóa các chức năng chỉ dành cho OLS.
- Transaction chỉ thay metadata không reload và không làm mất parent rollback. Kiểm tra settings precondition trước khi tạo thư mục transaction.
- Kiểm thử manager trên Nginx thật cô lập: HTTP 200 → bảo vệ 403 → allowlist 200 → rollback 403 → gỡ rule 200; kiểm tra Unix socket, phục hồi settings và gỡ lặp không thay đổi.
- Kiểm thử updater thật từ tag `v0.2.9` trên fixture Nginx, nâng lên archive trong bộ nhớ mang nhãn 0.2.10. Nhãn này chỉ nằm trong test, không đổi version/tag source. Settings giữ nguyên byte, nginx.conf không đổi, cron được tạo nhưng không bật rule.
- Artifact kiểm thử đều ở `tmp/`. Kết quả hồi quy cuối và review độc lập được cập nhật sau kiểm tra; không cài module, deploy production, commit hoặc push trong đợt này.
