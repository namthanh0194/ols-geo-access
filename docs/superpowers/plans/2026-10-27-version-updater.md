# Kế hoạch triển khai cơ chế kiểm tra và cập nhật phiên bản cho OLS Geo Access

> **Mục tiêu:** Hiển thị nút Update khi có version mới từ GitHub Releases (`namthanh0194/ols-geo-access`), hỗ trợ cập nhật an toàn theo semantic version, tự động dọn rác (tệp tải về tạm thời và các thư mục giải nén tạm), lưu bản sao lưu trước khi cập nhật để có thể rollback khi cần.

---

## 1. Thiết kế kiến trúc

### 1.1. Luồng kiểm tra phiên bản (`check_update`)
- **Nguồn:** GitHub Releases API `https://api.github.com/repos/namthanh0194/ols-geo-access/releases/latest`.
- **Cache:** Lưu tại `data/update-cache.json` với khóa `checked_at`, `version`, `has_update`, `release_notes`, `download_url`.
  - Cache TTL: 6 giờ đối với lần kiểm tra thành công, 15 phút nếu gặp lỗi mạng/GitHub API limit.
  - Hỗ trợ tham số `force=True` khi người dùng bấm nút "Kiểm tra ngay".
- **So sánh phiên bản:** Chuẩn Semantic Versioning `(major, minor, patch)`. Nếu `latest > current` -> `has_update = True`.

### 1.2. Luồng thực hiện cập nhật (`update`)
1. **Kiểm tra khóa và phiên bản:** Khóa file `data/update.lock` để tránh chạy song song. Xác nhận version yêu cầu lớn hơn version đang cài.
2. **Tải về an toàn:** Tải tệp zip vào thư mục tạm `tmp/download-<uuid>.zip` với giới hạn dung lượng tối đa (30MB).
3. **Xác minh gói cài (Archive Validation):**
   - Không cho phép symlink, file đặc biệt hoặc path traversal (`..`, đường dẫn tuyệt đối).
   - Kiểm tra các tệp bắt buộc: `info.json`, `ols_geo_access_main.py`, `upgrade.sh`, `lib/`, `index.html`.
4. **Sao lưu trước khi nâng cấp (Pre-update Backup):**
   - Lưu trạng thái hiện tại vào `data/backups/release-backup-previous` để phục vụ Rollback.
   - Dọn dẹp các thư mục backup cũ hơn, chỉ giữ 1 bản sao lưu rollback gần nhất.
5. **Cài đặt và Migrate:**
   - Giải nén ghi đè các tệp mã nguồn vào thư mục plugin.
   - Chạy `upgrade.sh` để migrate dữ liệu và cấp quyền thực thi `0755` cho các script `.sh`, `.py`.
6. **Dọn rác (Garbage Collection):**
   - Xóa ngay tệp zip tạm tải về và thư mục tạm giải nén (dùng block `finally`).
   - Xóa các file `.tmp`, file cache tạm phát sinh trong quá trình cập nhật.
7. **Kiểm tra tự phục hồi (Health Check):**
   - Kiểm tra `py_compile` và load module mới. Nếu lỗi nghiêm trọng, tự động kích hoạt rollback.

### 1.3. Luồng Rollback (`rollback`)
- Khôi phục mã nguồn từ `data/backups/release-backup-previous`.
- Kiểm tra tính toàn vẹn và cấp lại quyền file.

---

## 2. Danh sách tệp thay đổi

1. **Tạo mới:** `src/ols_geo_access/lib/updater.py`
   - Quản lý API GitHub, cache, validate archive, tải zip, backup, extract, dọn rác, rollback.
2. **Sửa đổi:** `src/ols_geo_access/ols_geo_access_main.py`
   - Khai báo endpoint aaPanel: `check_update`, `update`, `rollback`.
3. **Sửa đổi:** `src/ols_geo_access/index.html`
   - Header: Thêm nhãn version `v0.1.0` và nút "Cập nhật" (ẩn mặc định, hiện khi có bản mới).
   - Banner: Hiển thị thông báo khi có update.
   - Tab "Trạng thái": Thêm khu vực Quản lý phiên bản (Kiểm tra ngay, Cập nhật, Rollback).
4. **Kiểm thử:** `tmp/test_updater.py`
   - Bộ kiểm thử độc lập cho semver, cache, validate zip, download/extract/cleanup, rollback.

---

## 3. Các bước thực hiện

- [ ] **Bước 1:** Viết test `tmp/test_updater.py` mô phỏng kiểm tra version, cache, validate archive, tải zip, dọn dẹp file tạm và rollback.
- [ ] **Bước 2:** Xây dựng module `src/ols_geo_access/lib/updater.py`.
- [ ] **Bước 3:** Tích hợp endpoint vào `src/ols_geo_access/ols_geo_access_main.py`.
- [ ] **Bước 4:** Cập nhật giao diện `src/ols_geo_access/index.html` (Nút Update, banner, tab quản lý).
- [ ] **Bước 5:** Chạy kiểm thử `tmp/test_updater.py` và toàn bộ suite `tmp/self_check.py`.
- [ ] **Bước 6:** Đồng bộ sang production `/www/server/panel/plugin/ols_geo_access`, đối soát `cmp` và kiểm tra hoạt động trên aaPanel.
