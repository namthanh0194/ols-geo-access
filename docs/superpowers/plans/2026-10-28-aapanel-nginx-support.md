# Kế hoạch triển khai hỗ trợ aaPanel + Nginx

> **Hướng dẫn thực thi:** Kế hoạch được chia thành các nhiệm vụ độc lập, áp dụng TDD (viết kiểm thử trước). Tất cả các artifact kiểm thử tạm phải nằm trong `tmp/`. Không sửa trực tiếp production OLS hoặc VPS Nginx trong quá trình phát triển mã nguồn.

**Mục tiêu:** Mở rộng plugin hiện tại để hỗ trợ cả OpenLiteSpeed và Nginx trên aaPanel, dùng chung toàn bộ logic chính sách, crawler, Cloudflare, updater, UI nhưng tách biệt tầng sinh cấu hình và thao tác webserver.

**Kiến trúc:** Bổ sung lớp trừu tượng webserver adapter và backend detector; thêm `NginxAdapter`, `NginxConfigGenerator` và module quản lý lifecycle/journal riêng cho Nginx. OLS backend hiện tại được bảo toàn 100% không bị hồi quy.

**Công nghệ:** Python 3.10+, SQLite3, Nginx config syntax (map, geoip2, real_ip), Bash, aaPanel API conventions.

**Tài liệu thiết kế:** `docs/superpowers/specs/2026-10-28-aapanel-nginx-support-design.md`

## Ràng buộc toàn cục

- Không sửa trực tiếp `/www/server/panel/plugin/ols_geo_access` trên bất kỳ máy chủ nào.
- Mọi sửa đổi thực hiện tại `/root/ols-geo-access`.
- Tất cả script/test tạm đặt trong `tmp/`, không commit nội dung trong `tmp/`.
- Không tự ý compile lại Nginx hay cài module binary đè lên VPS production.
- Không làm suy giảm độ tin cậy và bộ test hiện có của OpenLiteSpeed.

## Trọng tâm kiểm tra rủi ro (Review Focus)

1. Phát hiện runtime nhầm lẫn khi có Nginx trong Docker container.
2. Thiếu module GeoIP2 hoặc file MMDB bị lỗi nhưng hệ thống vẫn cố reload Nginx.
3. Cấu hình Real IP cấp `http` ảnh hưởng tới các website không bật bảo vệ hoặc website truy cập trực tiếp.
4. Website không có include extension hợp lệ bị can thiệp file cấu hình gốc.
5. Tiến trình Nginx chết hoặc reload thất bại nhưng trạng thái journal không khôi phục về release trước.

---

### Nhiệm vụ 1: Bộ nhận diện Runtime Backend & Lưu trữ Danh tính (Backend Detector & Identity Storage)

**Tệp tin:**
- Tạo mới: `src/ols_geo_access/lib/backend_detector.py`
- Kiểm thử: `tmp/test_backend_detector.py`

**Giao diện:**
- Cung cấp: `detect_webserver_environment(prefix="") -> dict`, `load_persisted_backend(paths) -> str`, `persist_backend_identity(paths, backend: str) -> None`
- Đầu ra: Trả về trạng thái chuẩn hóa: `{"backend": "openlitespeed"|"nginx"|"unknown", "binary": Path, "main_config": Path, "is_container": bool, "confidence": str}`

**Các bước thực hiện:**
- [ ] Bước 1: Viết test `tmp/test_backend_detector.py` kiểm tra các trường hợp: OLS chuẩn, Nginx aaPanel chuẩn, tiến trình Docker bị bỏ qua, và trường hợp không xác định.
- [ ] Bước 2: Chạy test để xác nhận test thất bại (RED).
- [ ] Bước 3: Cài đặt logic trong `src/ols_geo_access/lib/backend_detector.py` đọc `/proc`, đối chiếu cgroup Docker, kiểm tra listener 80/443 và các binary tại `/www/server/nginx/sbin/nginx` hoặc `/usr/local/lsws/bin/openlitespeed`.
- [ ] Bước 4: Chạy lại test để xác nhận đạt (GREEN).
- [ ] Bước 5: Tối ưu và dọn dẹp mã nguồn.

---

### Nhiệm vụ 2: Bộ sinh cấu hình Nginx (Nginx Config Generator & Snippets)

**Tệp tin:**
- Tạo mới: `src/ols_geo_access/lib/nginx_config_generator.py`
- Kiểm thử: `tmp/test_nginx_config_generator.py`

**Giao diện:**
- Cung cấp: `generate_nginx_http_conf(mmdb_path, cloudflare_prefixes, *, assignments=None, snapshots=None, exceptions=(), allowlist=(), health_paths=None, origin_prefixes=None) -> str`
- Cung cấp: `generate_nginx_server_snippet(domain, assignment, *, cloudflare_prefixes=()) -> str`
- Các policy đầu vào thuộc bộ sinh `http` vì `map`/`geo` chỉ hợp lệ trong context này. `health_paths` và `origin_prefixes` là dict theo domain. Hai bộ sinh phải nhận cùng assignment và danh sách Cloudflare; Nhiệm vụ 5 triển khai cặp artifact trong cùng transaction.

**Các bước thực hiện:**
- [x] Bước 1: Viết test `tmp/test_nginx_config_generator.py` kiểm tra sinh cấu hình http-level (`geoip2`, `map`) và server-level (`extension/<domain>/00-ols-geo-access.conf`).
- [x] Bước 2: Xác nhận test thất bại (RED).
- [x] Bước 3: Cài đặt đúng thứ tự WooCommerce -> Manual IP allowlist -> Internal cron -> ACME -> Health -> Crawlers -> VN GeoIP -> Deny 403. Mỗi domain/mode/trust có biến `$oga_<digest>_deny` riêng; không tra policy qua `$host`, không thay PHP/proxy handlers.
- [x] Bước 4: Chạy lại test xác nhận đạt (GREEN).
- [x] Bước 5: Validate input, kiểm tra whitespace và cấu trúc block bằng Nginx thật trong sandbox.

**Xác minh Nhiệm vụ 2 (28/10/2026):**
- 20 test generator; toàn bộ 119 unit test và `tmp/self_check.py` đạt.
- Nginx 1.18.0 + GeoIP2 chạy trong chroot dưới `tmp/`, chỉ bind loopback cổng cao: `nginx -t`, 2 ca cấu hình âm (snippet lệch mode, MMDB hỏng), 56 ca HTTP đạt. Bao gồm alias, IPv4/IPv6, path/method, tài nguyên crawler, header giả, trust kế thừa và internal rewrite. Exact path dùng PCRE `\z` để không cấp ngoại lệ cho URI có newline mã hóa ở cuối.
- Có warning tối ưu `variables_hash` với mặc định sandbox nhưng config-test vẫn đạt. Khi tích hợp cần kiểm tra cấu hình hash hiện hữu, không tự thêm directive trùng vào core.
- Chưa chứng minh tương thích runtime Nginx 1.28.3 của VPS; không SSH, cài module, reload production, tăng version hoặc publish trong nhiệm vụ này.
- Generator kiểm tra file MMDB đọc được và không qua symlink; nội dung MMDB phải được kiểm tra qua `nginx -t` trước triển khai. Header Cloudflare không hợp lệ hoặc peer tin cậy không có RealIP rewrite bị từ chối kể cả ngoại lệ. Client IP bằng chính IP peer cũng bị từ chối theo nguyên tắc fail-closed.
- `bot_indexing_disabled` giữ nguyên ý nghĩa metadata của OLS; không bổ sung luật chặn crawler hoặc robots/header mới.

---

### Nhiệm vụ 3: Nginx Adapter (Kiểm tra cú pháp & Reload an toàn)

**Tệp tin:**
- Tạo mới: `src/ols_geo_access/lib/nginx_adapter.py`
- Kiểm thử: `tmp/test_nginx_adapter.py`

**Giao diện:**
- Cung cấp: `NginxAdapter(binary_path, conf_path)` với các phương thức `test_config() -> ConfigTestResult`, `reload_service() -> bool`, `check_geoip2_support() -> bool`, `check_realip_support() -> bool`
- Keyword tùy chọn: `prefix`, `runner`, `environment_reader`, `proc_root`, `timeout=30`, `reload_timeout=10`. `prefix` phải khớp runtime; nếu không truyền thì đối chiếu prefix biên dịch từ `-V`. Các boundary thay thế chỉ dùng để cô lập kiểm thử. `last_error` chứa nguyên nhân lỗi gần nhất.

**Các bước thực hiện:**
- [x] Bước 1: Viết test mô phỏng `nginx -t` trả về exit code 0/1 và bắt lỗi parser.
- [x] Bước 2: Xác nhận test thất bại (RED).
- [x] Bước 3: Hoàn thiện `nginx_adapter.py` gọi subprocess không qua shell, xác minh runtime/master và gửi `HUP` qua pidfd; chờ worker mới ổn định và không còn worker cũ đang nhận request.
- [x] Bước 4: Chạy test xác nhận đạt (GREEN).
- [x] Bước 5: Hoàn thiện xử lý timeout, lỗi subprocess/process identity và đóng pidfd.

**Xác minh Nhiệm vụ 3 (28/10/2026):**
- 29 test adapter và 3 test bổ sung từ review; toàn bộ 151 unit test và `tmp/self_check.py` đạt. Bộ runtime generator trước đó vẫn đạt 56 ca HTTP và 2 ca cấu hình âm. Review giới hạn trong Task 3 không ghi nhận lỗi quan trọng còn tồn tại.
- Chroot Nginx 1.18.0 dưới `tmp/` với master/worker thật và cổng loopback cao: xác nhận `nginx -t`, RealIP, GeoIP2 đang map, reload bằng pidfd/HUP và HTTP đổi `204 -> 200 -> 204` qua hai lần reload. Config lỗi bị chặn; cố ý làm hỏng config sau config-test khiến HUP bị Nginx từ chối, adapter trả thất bại và service cũ vẫn trả 200.
- Runtime fixture cung cấp identity và chuyển đường dẫn khi chạy lệnh trong chroot; không khẳng định đã kiểm thử detector trên VPS hoặc Nginx 1.28.3. Không SSH, cài module, chạy config-test/reload production, tích hợp API, tăng version, commit/push.

**Quyết định và giới hạn của adapter:**
- Dùng lại `ConfigTestResult` nhưng parser riêng cho Nginx và thêm lỗi khi exit code khác 0; không thay parser/adapter OLS.
- Không dùng PID file, `systemctl` hay `nginx -s reload`. Nếu kernel/Python không hỗ trợ pidfd thì từ chối reload, không fallback sang PID có nguy cơ tái sử dụng.
- GeoIP2 được xác nhận từ build tĩnh có tên thư mục `ngx_http_geoip2_module`, hoặc file `ngx_http_geoip2_module.so` đang map trên master đã xác minh, khớp inode/device. Chỉ có cờ build dynamic hoặc file `.so` trên đĩa không đủ. Build tĩnh đặt tên thư mục khác có thể bị coi là chưa xác minh; không tự suy đoán hỗ trợ.
- Khả năng module là của runtime đang chạy, không đảm bảo mọi candidate config đều nạp module/MMDB đúng. Cấu hình candidate vẫn bắt buộc qua `nginx -t`.
- Reload thành công ở đây chỉ xác nhận master và thế hệ worker; worker cũ được phép còn sống để drain. Khóa triển khai, checksum toàn cây cấu hình, chống chỉnh sửa đồng thời và HTTP policy probe thuộc Nhiệm vụ 5, chưa tích hợp ở bước này.

---

### Nhiệm vụ 4: Kiểm kê Website Nginx (Nginx Domain Inventory)

**Tệp tin:**
- Sửa đổi: `src/ols_geo_access/lib/domain_inventory.py`
- Kiểm thử: `tmp/test_domain_inventory_nginx.py`

**Giao diện:**
- Cung cấp: `collect_domains_nginx(database_path, vhost_root, traffic_modes=None, managed_domains=None, *, config_prefix=None, include_roots=()) -> list[NginxDomainRecord]`
- `NginxDomainRecord` kế thừa `DomainRecord`, bổ sung `site_id`, `aliases`, `vhost_path`, `snippet_path`, `server_blocks`, `supported_for_protection`, `unsupported_reason`. Không thay các field hoặc serialization của record OLS.
- `config_prefix` là **thư mục chứa main config**, không phải runtime `-p` hay thư mục của file đang include. Không truyền thì include tương đối chưa được xác minh. Chỉ đọc include dưới `vhost_root` và các root được truyền tường minh qua `include_roots`/`config_prefix`.

**Các bước thực hiện:**
- [x] Bước 1: Viết test giả lập thư mục `/www/server/panel/vhost/nginx` với các file `.conf` có và không có `include extension/`.
- [x] Bước 2: Xác nhận test thất bại (RED).
- [x] Bước 3: Bổ sung logic kiểm tra điểm include extension trong `domain_inventory.py`, đánh dấu cờ `supported_for_protection` cho từng website.
- [x] Bước 4: Chạy test xác nhận đạt (GREEN).
- [x] Bước 5: Đảm bảo tương thích ngược với OLS `collect_domains`; giữ nguyên field/serialization và chạy toàn bộ kiểm thử hồi quy hiện có.

**Xác minh Nhiệm vụ 4 (28/10/2026):**
- 33 test inventory Nginx; toàn bộ 184 unit test và `tmp/self_check.py` đạt. `git diff --check` không báo lỗi whitespace.
- 12 ca đối chiếu trong chroot Nginx 1.18.0 dưới `tmp/`: quyết định inventory khớp với `nginx -t` và HTTP thật về alias, include cấp server/location, comment/chuỗi giả, thứ tự glob, file ẩn, quote nhiều dòng và đường dẫn include tương đối qua file con.
- Review độc lập phát hiện glob phụ có thể che điểm include thứ hai; đã tái hiện bằng 3 subtest thất bại, sửa theo hướng diagnostic-only và chạy lại toàn bộ suite/runtime.
- Không gọi production/VPS, không tạo/sửa include trong vhost thực tế, không tăng version hoặc commit/push. Chưa chứng minh runtime Nginx 1.28.3 hay schema/config thực tế trên VPS; đây là code inventory, chưa tích hợp luồng deploy/UI.

**Quyết định và giới hạn của inventory:**
- Database được mở `mode=ro`, đọc `sites(id,name,status,path,project_type)` và `domain(pid,name)` trong cùng transaction. Sai schema, site ID/name trùng, alias thuộc nhiều site hoặc binding mồ côi gây lỗi rõ ràng, không trả danh sách rỗng giả thành công. Caller chọn DB chính xác; không tự chọn giữa nhiều DB.
- Tokenizer bỏ qua comment và phân biệt chuỗi quote; mở rộng include có giới hạn, không dùng regex để sửa vhost. Từ chối symlink, traversal, include cycle và include ngoài phạm vi cho phép. Giới hạn mỗi site: 64 lượt đọc file, 512 KiB/file, tổng 2 MiB, 16 tầng include, 64 tầng block; mỗi file tối đa 50.000 token.
- Mỗi server block phải có đúng một điểm extension ở cấp server, bao phủ cả HTTP/HTTPS và các alias DB. Không chấp nhận điểm chỉ trong location/if, include thiếu/trùng hoặc `return/rewrite/if` chạy trước guard; xét cả thứ tự file trong glob extension. Chỉ hỗ trợ tên DNS chính xác; wildcard/regex/biến và các cấu trúc chưa chứng minh an toàn hiển thị lý do chưa hỗ trợ.
- Alias dạng `*.example.com` trong DB vẫn được liệt kê nhưng site chỉ ở chế độ chẩn đoán, không làm mất inventory các site khác. Trong thư mục extension của site, chỉ glob `*`/`*.conf` được xác minh; glob khác như `00-*.conf` hoặc `[0-9]*.conf` bị đánh dấu cần kiểm tra thủ công để không bỏ sót điểm nạp snippet thứ hai/nằm sai context.
- Chặn share snippet và claim alias chéo giữa các site aaPanel đã phân tích. `supported_for_protection` chỉ là điều kiện cấu hình cục bộ; Nhiệm vụ 5 vẫn phải xác minh main-config thực sự nạp vhost, toàn bộ ownership/routing (kể cả file không thuộc DB), checksum, lock và `nginx -t` trước ghi/reload.
- Snippet có sẵn chỉ được đánh dấu `present-unverified`, không suy ra quyền sở hữu/healthy từ việc file tồn tại. Không tự tạo thư mục, thêm include hoặc sửa bất kỳ vhost nào.

---

### Nhiệm vụ 5: Quản lý Triển khai, Giao dịch & Rollback Nginx (Nginx Rollback & Journal)

**Tệp tin:**
- Tạo mới: `src/ols_geo_access/lib/nginx_rollback.py`
- Kiểm thử: `tmp/test_nginx_rollback.py`

**Giao diện:**
- Cung cấp: `apply_nginx_release(...)`, `restore_nginx_release_transaction(...)`, `deactivate_nginx_managed_release(...)`

**Các bước thực hiện:**
- [x] Bước 1: Viết test mô phỏng quy trình apply -> config test lỗi -> tự động khôi phục bản backup cũ trên Nginx.
- [x] Bước 2: Xác nhận test thất bại (RED).
- [x] Bước 3: Cài đặt `nginx_rollback.py` ghi nhận metadata vào `data/nginx-release-state/current.json`, kiểm tra checksum trước khi ghi đè, và quản lý transaction cô lập với OLS.
- [x] Bước 4: Chạy test xác nhận đạt (GREEN).
- [x] Bước 5: Rà soát đảm bảo các file mồ côi (website đã bị xóa) được bỏ qua an toàn tương tự như bản vá OLS v0.2.7.

**Xác minh Nhiệm vụ 5 (28/10/2026):**
- 15 test rollback/transaction đạt; toàn bộ 199 unit test và `tmp/self_check.py` đạt.
- Kết quả sandbox trước đây có bước sửa HTTP config/reload bổ sung sau deactivate; không đủ chứng minh đường deactivate tự hoạt động hoàn chỉnh.
- Các kiểm thử đã bao phủ một số lỗi checksum, domain traversal và orphan, nhưng **chưa đủ điều kiện nối vào API ghi Nginx**. Rà soát khi tích hợp Nhiệm vụ 6 còn thấy:
  - Chưa ràng buộc runtime/backend và quyền sở hữu vào release/journal; chưa chặn transaction mới khi recovery chưa hoàn tất.
  - Restore chưa xác minh đầy đủ đường dẫn transaction, checksum backup, thay đổi từ bên ngoài và metadata quyền tệp.
  - Kiểm tra symlink/ownership, inventory toàn cấu hình và canary còn thiếu; kiểm tra vhost bằng file/thư mục không chứng minh website đã bị xóa trong DB.
  - Deactivate còn ghi current state ngoài transaction và để HTTP placeholder nhưng bỏ ownership.
- Không coi các bản vá cục bộ hoặc thao tác nhiều file là giao dịch filesystem nguyên tử. Cần harden và kiểm thử riêng trước khi bật thay đổi cấu hình Nginx.

**Gia cố sau review (28/10/2026):**
- File mới dùng `renameat2(RENAME_NOREPLACE)`; thay file hiện hữu dùng `RENAME_EXCHANGE` để giữ lại inode bị thay thế và kiểm tra nội dung/quyền của chính file đó. Xóa file cũng chuyển sang tên giữ tạm bằng `RENAME_NOREPLACE` rồi mới kiểm tra, thay vì unlink trực tiếp sau checksum.
- Nếu phát hiện xung đột sau đổi tên, giữ file `.ols-geo-*` cùng thư mục, ghi đường dẫn trong `recovery_error`, đánh dấu `write_conflict` và `recovery_required`. Không reload thêm, không tự rollback/restore đè lên trạng thái xung đột. Cần đối chiếu file được giữ, backup và cấu hình thực tế trước khi phục hồi thủ công; không coi file giữ phục hồi là rác để tự xóa.
- Đường thành công dọn staging/file cũ sau xác minh. Nếu libc/kernel/filesystem không hỗ trợ thao tác rename yêu cầu thì dừng, không fallback sang `os.replace` không an toàn. Chưa xác minh hỗ trợ này trên VPS Nginx thật.
- Xác minh lại bằng chứng vhost mồ côi trước các bước ghi/xóa, thao tác dịch vụ và commit state, cả khi apply và restore. Vhost xuất hiện lại dù chưa có dòng DB cũng làm giao dịch dừng ở trạng thái cần phục hồi.
- Giới hạn: đây không phải compare-and-swap theo checksum hay giao dịch nguyên tử nhiều file. Không khóa được editor bên ngoài không hợp tác hoặc writer giữ file descriptor cũ; cần tránh chỉnh cấu hình đồng thời. Khi xung đột, file mới có thể đã nằm tại đích nhưng chưa được plugin reload, file bị thay được giữ để đối chiếu.
- Kiểm thử hồi quy tại `tmp/test_nginx_race_regressions.py`; vẫn giữ API ghi Nginx bị khóa, chưa triển khai lifecycle Nhiệm vụ 7 hoặc cập nhật production.
- Xác minh sau gia cố: 11 ca hồi quy mới đạt; toàn bộ 258 unit test, `tmp/self_check.py` và `git diff --check` đạt. Các thao tác webserver trong bộ test dùng fixture/mock, không chứng minh triển khai Nginx thật đã hoàn tất.

---

### Nhiệm vụ 6: Tích hợp Backend vào Plugin Core & Điều phối Giao diện

**Tệp tin:**
- Sửa đổi: `src/ols_geo_access/ols_geo_access_main.py`
- Sửa đổi: `src/ols_geo_access/index.html`
- Kiểm thử: `tmp/test_plugin_main_multi_backend.py`

**Giao diện:**
- Tự động định tuyến các API: `get_dashboard`, `get_domains`, `save_domains`, `check_cloudflare_ranges`, `repair_cloudflare_trust` theo backend đang hoạt động.

**Các bước thực hiện:**
- [x] Bước 1: Viết test API giả lập cả 2 môi trường OLS và Nginx, kiểm tra payload trả về có kèm trường `webserver_type`.
- [x] Bước 2: Xác nhận test thất bại (RED).
- [x] Bước 3: Khởi tạo Adapter và Inventory theo `load_persisted_backend()`, đồng thời xác minh runtime. Giá trị backend chuẩn là `openlitespeed` hoặc `nginx`.
- [x] Bước 4: UI hiển thị badge, cảnh báo include extension, lý do chỉ chẩn đoán và vô hiệu hóa thao tác chưa hỗ trợ; dùng màu theo theme sẵn có.
- [x] Bước 5: Chạy toàn bộ kiểm thử xác nhận đạt (GREEN) cho phạm vi đọc/chẩn đoán và chặn ghi đã tích hợp.
- [ ] Hoàn tất đường ghi Nginx sau khi khắc phục các điều kiện an toàn của Nhiệm vụ 5 và lifecycle liên quan.

**Phạm vi tích hợp hiện tại:** `get_dashboard` và `get_domains` đọc đúng backend; `check_cloudflare_ranges` chỉ kiểm tra nguồn IP. `save_domains`, `repair_cloudflare_trust`, cron qua API và các API phụ thuộc OLS từ chối chạy trên Nginx, không fallback sang OLS. Backend thiếu định danh, không rõ runtime, container, thay đổi định danh hoặc runtime đều bị chặn thay đổi. Không tự ghi backend identity hoặc tự chuyển backend.

**Giới hạn:** Nginx vẫn chỉ chẩn đoán kể cả khi có GeoIP2/RealIP. Không công bố số website đang bảo vệ hoặc release Nginx là đã xác minh. Chưa đủ để phát hành hỗ trợ Nginx hoàn chỉnh. Chưa triển khai Nhiệm vụ 7.

**Xác minh Nhiệm vụ 6 (28/10/2026):**
- 18 test API mới: chọn adapter, định tuyến inventory, SQLite/include fixture, module thiếu, identity/runtime thay đổi, không fallback OLS và không tạo state từ đường ghi riêng trên Nginx.
- Toàn bộ 217 unit test và `tmp/self_check.py` đạt. Các fixture OLS cũ được bổ sung identity/runtime giả lập; không chạy config test/reload trên production.
- Node kiểm tra cú pháp JavaScript, badge, khóa điều khiển, escape cảnh báo và hồi quy UI nhận diện luồng; đạt. Chưa kiểm tra hình ảnh bằng trình duyệt aaPanel thật.
- `git diff --check` đạt; không đổi version, commit, push, SSH, cài package hoặc triển khai production.

---

### Nhiệm vụ 7: Lifecycle Scripts (Cài đặt, Nâng cấp, Xoá & Cron)

**Tệp tin:**
- Sửa đổi: `src/ols_geo_access/install.sh`
- Sửa đổi: `src/ols_geo_access/upgrade.sh`
- Sửa đổi: `src/ols_geo_access/uninstall_cleanup.py`
- Sửa đổi: `src/ols_geo_access/update_traffic.py`
- Sửa đổi: `src/ols_geo_access/update_cloudflare.py`
- Kiểm thử: `tmp/test_lifecycle_nginx.py`

**Các bước thực hiện:**
- [ ] Bước 1: Viết test kiểm tra `install.sh` và `upgrade.sh` chạy trên cả hệ thống có OLS và hệ thống chỉ có Nginx.
- [ ] Bước 2: Xác nhận test thất bại (RED).
- [ ] Bước 3: Cập nhật các script không hardcode đường dẫn OLS binary; cron 03:00 hằng đêm tự gọi lệnh reload tương ứng với backend hiện tại.
- [ ] Bước 4: Chạy test xác nhận đạt (GREEN).
- [ ] Bước 5: Đảm bảo uninstall cleanup gỡ sạch rule Nginx khi được yêu cầu.

---

### Nhiệm vụ 8: Kiểm thử Toàn diện, Hồi quy OLS & Đóng gói

**Tệp tin:**
- Toàn bộ suite trong `tmp/`
- Đóng gói: `scripts/package.sh`

**Các bước thực hiện:**
- [ ] Bước 1: Chạy lại toàn bộ 65+ unit tests hiện có để khẳng định OLS không bị bất kỳ hồi quy nào.
- [ ] Bước 2: Chạy toàn bộ các test mới cho Nginx.
- [ ] Bước 3: Kiểm tra thử nghiệm đường nâng cấp từ v0.2.8 lên phiên bản mới bằng updater cô lập.
- [ ] Bước 4: Đóng gói bản zip thử nghiệm trong `dist/`.
- [ ] Bước 5: Báo cáo kết quả và đợi phê duyệt bước tiếp theo từ người dùng.
