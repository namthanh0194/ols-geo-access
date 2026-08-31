# Quy tắc source và production

- `/root/ols-geo-access` là mã nguồn duy nhất của plugin. Khi người dùng hỏi vị trí file hoặc yêu cầu sửa plugin, luôn nêu và sửa đường dẫn trong thư mục này trước.
- Không sửa trực tiếp `/www/server/panel/plugin/ols_geo_access` trong quá trình phát triển. Chỉ đồng bộ source sang đó sau khi kiểm thử đạt.
- Không sửa file core aaPanel dưới `/www/server/panel/class` hoặc `/www/server/panel/class_v2`.
- Sau khi đồng bộ, xác minh source và production giống nhau bằng `cmp`.
- File kiểm thử, script chẩn đoán và artifact tạm chỉ đặt trong `tmp/`.
