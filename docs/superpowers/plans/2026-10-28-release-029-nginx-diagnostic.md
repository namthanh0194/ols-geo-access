# Phát hành 0.2.9 và cài chẩn đoán Nginx

Phạm vi được duyệt: commit/push bản 0.2.9, cài trên VPS 51.79.248.182; không cập nhật production OLS hiện tại. Không mở API ghi Nginx, không reload hay thay rule Nginx, không cài module.

1. Xác minh runtime trước cài/nâng cấp, persist backend và migration từ bản cũ không phụ thuộc template data mới.
2. Nhánh Nginx chỉ cài code, dữ liệu mặc định, icon; không cron hoặc sửa cấu hình. Scheduler bỏ qua Nginx; gỡ từ chối nếu có managed state không thuộc bản chẩn đoán.
3. Kiểm thử lifecycle Nginx, hồi quy OLS, updater thật từ tag 0.2.8 và các tag cũ; chạy self-check và kiểm tra gói.
4. Commit, tag v0.2.9 và push sau khi kiểm tra đạt. Không đưa tmp, dữ liệu runtime hoặc SSH key vào Git.
5. SSH đích, ghi snapshot/checksum trước cài; xác minh SHA256 gói trước giải nén, cài và kiểm tra API đọc/khóa API ghi; so sánh cấu hình và runtime Nginx trước/sau, dọn staging. Nếu đã có plugin, phải sao lưu trước ghi đè.

Ruling: Đây chỉ là nhánh lifecycle chẩn đoán phục vụ bản 0.2.9; không đánh dấu Nhiệm vụ 7 (lifecycle triển khai rule đầy đủ) đã hoàn thành.

## Ledger
- SSH bằng khóa hiện có thành công; VPS chưa có plugin, cron hay icon của plugin. Nginx `-t` trước triển khai đạt.
- Test lifecycle mới đã tái hiện việc installer cũ từ chối Nginx và upgrader chưa chặn backend mismatch trước sửa dữ liệu.
- Bổ sung migration trạng thái OLS rỗng sau gỡ: `release_id=null, managed_files={}` không phải lỗi provenance; không dùng trạng thái rỗng làm bằng chứng định danh OLS.
- Các fixture OLS cũ được bổ sung runtime `/proc` giả và provenance release để thử preflight thật; không bypass kiểm tra runtime trong mã production.
- Kiểm chứng trước phát hành: 264 unit test, self-check, JavaScript/Python/shell syntax và package-check đạt. Package-check đọc version động thay vì kiểm tra nhầm ZIP 0.1.0 cũ.
- Updater thật từ tag 0.2.8 (cùng 0.2.2/0.2.4/0.2.5) nâng cấp thành công, bảo toàn settings và tự tạo backend identity; file tải/giải nén được dọn sau update.
- Preflight gói trên VPS xác minh được Nginx aaPanel host dù có nhiều Nginx/container khác; ghi nhận 149 file cấu hình để đối chiếu sau cài. Chưa kích hoạt rule Nginx.
- Final review phát hiện hai API reload cũ chưa có backend gate. Đã tái hiện bằng test, bổ sung gate cho cả cấp token và reload, kiểm tra lại runtime giữa hai lời gọi; không cho Nginx hoặc runtime đã thay đổi gọi OLS adapter.
- Sau sửa review: toàn bộ 265 unit test và self-check đạt; reviewer không còn phản đối phát hành trong phạm vi chẩn đoán. Fixture reload-audit được bổ sung định danh/runtime hợp lệ để tiếp tục kiểm tra lỗi reload thực sự, thay vì bị chặn ở preflight.
