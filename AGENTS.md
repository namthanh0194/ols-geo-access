# Quy tắc source và production

- `/root/ols-geo-access` là mã nguồn duy nhất của plugin. Khi người dùng hỏi vị trí file hoặc yêu cầu sửa plugin, luôn nêu và sửa đường dẫn trong thư mục này trước.
- Không sửa trực tiếp `/www/server/panel/plugin/ols_geo_access` trong quá trình phát triển. Khi người dùng yêu cầu cập nhật qua giao diện, sửa xong không update trực tiếp vào production mà người dùng sẽ ấn nút Cập nhật / cập nhật thủ công khi có version mới trong aaPanel.
- Không sửa file core aaPanel dưới `/www/server/panel/class` hoặc `/www/server/panel/class_v2`.
- File kiểm thử, script chẩn đoán và artifact tạm chỉ đặt trong `tmp/`. Không lưu tạm ở root hay lẫn vào source code production.

# Quy tắc Versioning & Update Cơ chế Dọn rác

- Phiên bản được định nghĩa chuẩn tại `src/ols_geo_access/info.json` (trường `versions`). Script đóng gói `scripts/package.sh` và API cập nhật luôn đọc động phiên bản từ file này.
- Updater cũ bảo toàn `data/` và không chép template mới vào đó. Migration phải tự khởi tạo trạng thái mới khi cần, không phụ thuộc vào template chỉ có trong gói mới và không ghi đè dữ liệu đang dùng.
- Kiểm thử đường nâng cấp phải tạo bản cài từ mã nguồn/tag cũ và chạy updater thật của bản đó; không chỉ chép source hiện tại rồi sửa số version để giả lập bản cũ.
- Cơ chế Update plugin từ GitHub repository (ví dụ `namthanh0194/ols-geo-access`):
  - Phải kiểm tra checksum/tính toàn vẹn trước khi giải nén.
  - Phải sao lưu phiên bản hiện tại trước khi ghi đè để hỗ trợ rollback tức thì nếu có lỗi.
  - Khi update xong phải có cơ chế dọn rác tự động: xóa sạch file zip tải về, thư mục giải nén tạm thời và các bản sao lưu cũ quá hạn, tránh để file thừa chiếm dụng ổ đĩa.

# Quy tắc Cào dữ liệu & Chia sẻ Mạng Xã Hội (Facebook, Messenger, OpenAI)

- Đối với các dịch vụ mạng xã hội và bot cào dữ liệu:
  - Cho phép các crawler phục vụ tạo preview link / Open Graph: Meta / Facebook (`facebookexternalhit`, `Facebot`), Messenger, Zalo, Telegram, Twitter/X, LinkedIn.
  - Phân biệt rõ giữa crawler đọc HTML preview và crawler tải tài nguyên tĩnh (hình ảnh, video, css). Lưu ý crawler Messenger có thể dùng dải IP và User-Agent tương tự Facebook nhưng cần đảm bảo không bị chặn bởi các quy tắc geo-block hoặc chặn bot nghiêm ngặt.
  - Với OpenAI bot (`GPTBot`, `OAI-SearchBot`, `ChatGPT-User`): luôn cập nhật đúng URL và nguồn cấp IP chính thức (`https://openai.com/gptbot.json`, `https://openai.com/searchbot.json`, `https://openai.com/chatgpt-user.json`), đảm bảo parser hoạt động chuẩn xác với cấu trúc JSON của nhà cung cấp.

# Quy tắc Giao diện & Dark Mode

- Giao diện plugin phải hỗ trợ Dark mode và Light mode tự động theo theme của aaPanel (`html.dark`, `[theme-mode="dark"]`, `[data-theme="dark"]`, `body.dark-theme`) và prefers-color-scheme của trình duyệt.
- Tự động đồng bộ theme qua `MutationObserver`, không thêm nút chuyển đổi theme thủ công (tránh làm rối thanh điều hướng và giao diện quản trị aaPanel).
- Icon plugin sử dụng icon vector chất lượng cao (ví dụ Lucide Globe Lock 128x128 RGBA), ghi rõ bản quyền/giấy phép sử dụng tại `THIRD_PARTY_LICENSES.md`.

# Quy tắc Quản lý Log & Retention

- Mọi file log của plugin (`audit.log`, `feed-update.log`, `cloudflare-update.log`) phải có cơ chế giới hạn dung lượng và xoay vòng (log rotation):
  - Ngưỡng xoay vòng mặc định: tối đa `10MB` cho mỗi file log.
  - Số lượng bản lưu trữ lịch sử: tối đa `5` file (`.log.1` đến `.log.5`), các bản log cũ hơn sẽ bị tự động xóa để tránh đầy dung lượng đĩa.
  - Xử lý log phải an toàn: phân quyền `0600`, từ chối symlink và path traversal.
