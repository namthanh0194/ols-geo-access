import io
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import uuid
from pathlib import Path, PurePosixPath

PLUGIN_NAME = "ols_geo_access"
REPOSITORY = "namthanh0194/ols-geo-access"
MAX_ARCHIVE = 30 * 1024 * 1024
MAX_EXPANDED = 80 * 1024 * 1024
UPDATE_INTERVAL = 6 * 60 * 60
UPDATE_RETRY_INTERVAL = 15 * 60

MANDATORY_FILES = {
    "info.json",
    "ols_geo_access_main.py",
    "upgrade.sh",
    "index.html",
}

def parse_version(value):
    if not isinstance(value, str):
        raise ValueError("Version phải là chuỗi ký tự.")
    cleaned = value.strip().lstrip("v")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-.*)?", cleaned)
    if not match:
        raise ValueError(f"Định dạng version không hợp lệ: {value}")
    return tuple(int(x) for x in match.groups())

def compare_versions(v1, v2):
    t1 = parse_version(v1)
    t2 = parse_version(v2)
    if t1 > t2:
        return 1
    if t1 < t2:
        return -1
    return 0

def validate_archive(archive):
    entries = archive.infolist()
    if len(entries) > 200:
        raise ValueError("Gói cập nhật có quá nhiều file.")
    total = 0
    found_files = set()

    for entry in entries:
        path = PurePosixPath(entry.filename)
        parts = path.parts
        if not parts:
            continue
        # Support root folder like "ols_geo_access/..." or "ols-geo-access-.../src/ols_geo_access/..."
        # Find prefix where ols_geo_access starts
        if PLUGIN_NAME in parts:
            idx = parts.index(PLUGIN_NAME)
            rel_parts = parts[idx + 1 :]
        else:
            rel_parts = parts

        if not rel_parts:
            continue

        rel_path = "/".join(rel_parts)
        if any(part in {"..", "", "."} for part in rel_parts) or rel_path.startswith("/"):
            raise ValueError(f"Đường dẫn không an toàn trong gói cập nhật: {entry.filename}")

        if entry.is_dir():
            continue

        mode = entry.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not stat.S_ISREG(mode)):
            raise ValueError(f"Không chấp nhận symlink hoặc file đặc biệt: {entry.filename}")

        total += entry.file_size
        if total > MAX_EXPANDED or entry.flag_bits & 1:
            raise ValueError("Gói cập nhật vượt quá giới hạn dung lượng giải nén.")

        found_files.add(rel_parts[0])

    for req in MANDATORY_FILES:
        if req not in found_files and not any(p.endswith(req) for p in [e.filename for e in entries]):
            raise ValueError(f"Gói cập nhật thiếu tệp bắt buộc: {req}")

    return found_files


class PluginUpdater:
    def __init__(self, plugin_dir=None, repository=REPOSITORY):
        self.plugin_dir = Path(plugin_dir).resolve() if plugin_dir else Path(__file__).resolve().parents[1]
        self.data_dir = self.plugin_dir / "data"
        self.backups_dir = self.data_dir / "backups"
        self.repository = repository
        self.lock_path = self.data_dir / "update.lock"
        self.cache_path = self.data_dir / "update-cache.json"
        self.status_path = self.data_dir / "update-operation.json"

    def get_update_status(self):
        operation = None
        if self.status_path.is_file():
            operation = json.loads(self.status_path.read_text(encoding="utf-8"))
        return {"status": True, "current_version": self.get_current_version(), "operation": operation}

    def _write_operation(self, operation):
        descriptor, temporary = tempfile.mkstemp(prefix="update-operation-", dir=self.data_dir)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(operation, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.status_path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _run_operation(self, action, operation_id, callback):
        operation_id = operation_id or uuid.uuid4().hex
        if not isinstance(operation_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", operation_id):
            raise ValueError("Mã thao tác cập nhật không hợp lệ.")
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "r+") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("Một thao tác cập nhật/khôi phục đang chạy. Vui lòng chờ.") from None
            operation = {"operation_id": operation_id, "action": action, "state": "running", "started_at": int(time.time())}
            self._write_operation(operation)
            try:
                result = callback()
            except Exception as error:
                operation.update(state="failed", msg=str(error), finished_at=int(time.time()))
                self._write_operation(operation)
                raise
            operation.update(state="succeeded" if result.get("status") else "failed", version=result.get("version"), msg=result.get("msg", ""), finished_at=int(time.time()))
            self._write_operation(operation)
            return result

    def get_current_version(self):
        info_path = self.plugin_dir / "info.json"
        if not info_path.is_file():
            return "0.0.0"
        try:
            info = json.loads(info_path.read_text(encoding="utf-8"))
            return str(info.get("versions", "0.0.0"))
        except Exception:
            return "0.0.0"

    def _fetch_github_latest(self):
        url = f"https://api.github.com/repos/{self.repository}/releases/latest"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "ols-geo-access-updater/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
                if len(data) > 1024 * 1024:
                    raise ValueError("Dữ liệu GitHub Release quá lớn.")
                return json.loads(data.decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                # Fallback to tags endpoint if formal Release has not been drafted
                tags_url = f"https://api.github.com/repos/{self.repository}/tags"
                tags_req = urllib.request.Request(
                    tags_url,
                    headers={
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "ols-geo-access-updater/1.0",
                    },
                )
                try:
                    with urllib.request.urlopen(tags_req, timeout=15) as tags_resp:
                        tags_data = json.loads(tags_resp.read().decode("utf-8"))
                        if tags_data and isinstance(tags_data, list):
                            latest_tag = tags_data[0]
                            tag_name = latest_tag.get("name", "").strip()
                            return {
                                "tag_name": tag_name,
                                "body": f"Bản phát hành {tag_name}",
                                "html_url": f"https://github.com/{self.repository}/releases/tag/{tag_name}",
                                "zipball_url": latest_tag.get("zipball_url"),
                                "assets": [],
                            }
                except Exception:
                    pass
                raise ValueError("Chưa có bản phát hành Release hoặc Tag công khai trên GitHub.") from None
            if error.code in {403, 429}:
                raise ValueError("GitHub API bị giới hạn tần suất truy cập. Vui lòng thử lại sau.") from None
            raise ValueError(f"GitHub API trả về lỗi HTTP {error.code}.") from None

    def check_for_updates(self, force=False):
        now = int(time.time())
        current = self.get_current_version()

        if not force and self.cache_path.is_file():
            try:
                cached = json.loads(self.cache_path.read_text(encoding="utf-8"))
                ttl = UPDATE_RETRY_INTERVAL if cached.get("error") else UPDATE_INTERVAL
                if 0 <= now - cached.get("checked_at", 0) < ttl:
                    cached["current_version"] = current
                    latest = cached.get("latest_version") or cached.get("version", current)
                    cached["has_update"] = compare_versions(latest, current) > 0
                    return cached
            except Exception:
                pass

        try:
            doc = self._fetch_github_latest()
            tag = doc.get("tag_name", "").strip().lstrip("v")
            parse_version(tag)
            notes = str(doc.get("body", ""))[:3000]
            html_url = doc.get("html_url", "")

            # Look for asset zip: ols_geo_access-*.zip or ols-geo-access-*.zip
            download_url = None
            for asset in doc.get("assets", []):
                name = asset.get("name", "")
                if (name.startswith("ols_geo_access") or name.startswith("ols-geo-access")) and name.endswith(".zip"):
                    download_url = asset.get("browser_download_url")
                    break

            if not download_url:
                # Fallback to zipball_url
                download_url = doc.get("zipball_url")

            has_update = compare_versions(tag, current) > 0
            payload = {
                "status": True,
                "current_version": current,
                "latest_version": tag,
                "version": tag,
                "has_update": has_update,
                "release_notes": notes,
                "html_url": html_url,
                "download_url": download_url,
                "checked_at": now,
                "error": None,
            }
            self._write_cache(payload)
            return payload
        except Exception as error:
            error_msg = str(error)
            payload = {
                "status": False,
                "current_version": current,
                "latest_version": current,
                "version": current,
                "has_update": False,
                "release_notes": "",
                "html_url": "",
                "download_url": None,
                "checked_at": now,
                "error": error_msg,
            }
            self._write_cache(payload)
            return payload

    def _write_cache(self, data):
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.cache_path)
        except Exception:
            pass

    def _download_bytes(self, url):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ols-geo-access-updater/1.0"},
        )
        chunks = []
        total = 0
        with urllib.request.urlopen(req, timeout=30) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_ARCHIVE:
                    raise ValueError("Gói tải về vượt quá giới hạn 30MB.")
        return b"".join(chunks)

    def _cleanup_temp_artifacts(self, temp_paths):
        """Xóa sạch mọi file zip, file tạm và thư mục tạm phát sinh khi update."""
        for p in temp_paths:
            if not p:
                continue
            try:
                path_obj = Path(p)
                if path_obj.is_dir():
                    shutil.rmtree(path_obj, ignore_errors=True)
                elif path_obj.is_file() or path_obj.is_symlink():
                    path_obj.unlink(missing_ok=True)
            except Exception:
                pass

        # Dọn sạch các file .tmp tồn đọng trong plugin_dir và data/
        try:
            for pattern in ("*.tmp", "*.zip.tmp", "*.zip"):
                for leftover in self.plugin_dir.glob(pattern):
                    if leftover.is_file():
                        leftover.unlink(missing_ok=True)
                for leftover in self.data_dir.glob(pattern):
                    if leftover.is_file():
                        leftover.unlink(missing_ok=True)
        except Exception:
            pass

    def _prune_old_backups(self):
        """Dọn dẹp các thư mục backup cũ, chỉ giữ lại release-backup-previous."""
        if not self.backups_dir.is_dir():
            return
        preserved = {"release-backup-previous"}
        for item in self.backups_dir.iterdir():
            if item.name not in preserved and item.is_dir():
                shutil.rmtree(item, ignore_errors=True)

    def apply_update(self, target_version, download_url=None, operation_id=None):
        return self._run_operation("update", operation_id, lambda: self._apply_update(target_version, download_url))

    def _apply_update(self, target_version, download_url=None):
        current_version = self.get_current_version()
        if compare_versions(target_version, current_version) <= 0:
            raise ValueError(f"Phiên bản cập nhật ({target_version}) không lớn hơn phiên bản hiện tại ({current_version}).")

        if not download_url:
            check = self.check_for_updates(force=True)
            if not check.get("has_update") or not check.get("download_url"):
                raise ValueError("Không tìm thấy đường link tải về của bản phát hành.")
            download_url = check["download_url"]

        temp_artifacts = []
        extract_dir = None
        zip_path = None

        try:
            # 1. Tải zip về
            zip_bytes = self._download_bytes(download_url)
            archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
            validate_archive(archive)

            # 2. Tạo thư mục tạm giải nén
            temp_extract = Path(tempfile.mkdtemp(prefix="ols-update-extract-"))
            temp_artifacts.append(temp_extract)
            archive.extractall(temp_extract)

            # Tìm root của source trong temp_extract
            candidate_roots = [
                temp_extract / PLUGIN_NAME,
                temp_extract,
            ]
            for child in temp_extract.iterdir():
                if child.is_dir() and (child / "info.json").is_file():
                    candidate_roots.insert(0, child)
                if child.is_dir() and (child / "src" / PLUGIN_NAME / "info.json").is_file():
                    candidate_roots.insert(0, child / "src" / PLUGIN_NAME)

            source_root = None
            for cand in candidate_roots:
                if cand.is_dir() and (cand / "info.json").is_file():
                    source_root = cand
                    break

            if not source_root:
                raise ValueError("Không tìm thấy cấu trúc mã nguồn plugin hợp lệ trong gói cập nhật.")
            package_info = json.loads((source_root / "info.json").read_text(encoding="utf-8"))
            if package_info.get("versions") != target_version:
                raise ValueError("Phiên bản trong gói tải về không khớp bản cập nhật đã chọn.")

            # 3. Tạo bản backup phiên bản hiện tại vào release-backup-previous
            self.backups_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            previous_backup = self.backups_dir / "release-backup-previous"
            if previous_backup.exists():
                shutil.rmtree(previous_backup, ignore_errors=True)
            previous_backup.mkdir(parents=True, mode=0o700)

            # Sao lưu các file code cần thiết
            for item in self.plugin_dir.iterdir():
                if item.name in {"data", "logs", "__pycache__", "tmp"}:
                    continue
                target = previous_backup / item.name
                if item.is_dir():
                    shutil.copytree(item, target, symlinks=False)
                else:
                    shutil.copy2(item, target)

            # 4. Copy mã nguồn mới vào plugin_dir
            for item in source_root.iterdir():
                if item.name in {"data", "logs", "__pycache__", "tmp"}:
                    continue
                target = self.plugin_dir / item.name
                if item.is_dir():
                    if target.exists():
                        shutil.rmtree(target, ignore_errors=True)
                    shutil.copytree(item, target, symlinks=False)
                else:
                    shutil.copy2(item, target)
                    # Set permissions
                    if item.name.endswith(".sh") or item.name.endswith(".py"):
                        try:
                            os.chmod(target, 0o755)
                        except Exception:
                            pass

            # 5. Chạy upgrade.sh nếu có
            upgrade_script = self.plugin_dir / "upgrade.sh"
            if upgrade_script.is_file():
                try:
                    os.chmod(upgrade_script, 0o755)
                    subprocess.run(
                        ["/bin/sh", str(upgrade_script)],
                        cwd=str(self.plugin_dir),
                        check=True,
                        capture_output=True,
                        timeout=60,
                    )
                except Exception as error:
                    # Tự động rollback nếu upgrade.sh thất bại
                    self._restore_from_backup(previous_backup)
                    details = getattr(error, "stderr", b"") or str(error)
                    if isinstance(details, bytes):
                        details = details.decode("utf-8", errors="replace")
                    raise ValueError(f"Chạy upgrade.sh thất bại: {details[-2000:]}") from error

            # 6. Cập nhật cache
            self._write_cache({
                "status": True,
                "current_version": target_version,
                "latest_version": target_version,
                "version": target_version,
                "has_update": False,
                "checked_at": int(time.time()),
            })

            # 7. Dọn rác bản backup cũ
            self._prune_old_backups()

            return {
                "status": True,
                "msg": f"Cập nhật thành công lên phiên bản {target_version}.",
                "version": target_version,
            }

        finally:
            # Luôn dọn rác tệp zip và thư mục giải nén tạm
            self._cleanup_temp_artifacts(temp_artifacts)

    def _restore_from_backup(self, backup_dir):
        if not backup_dir.is_dir():
            raise ValueError("Không tìm thấy bản sao lưu để khôi phục.")
        for item in backup_dir.iterdir():
            target = self.plugin_dir / item.name
            if item.is_dir():
                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
                shutil.copytree(item, target, symlinks=False)
            else:
                shutil.copy2(item, target)
                if item.name.endswith(".sh") or item.name.endswith(".py"):
                    try:
                        os.chmod(target, 0o755)
                    except Exception:
                        pass

    def rollback(self, operation_id=None):
        return self._run_operation("rollback", operation_id, self._rollback)

    def _rollback(self):
        backup_dir = self.backups_dir / "release-backup-previous"
        if not backup_dir.is_dir() or not (backup_dir / "info.json").is_file():
            return {
                "status": False,
                "msg": "Không có bản sao lưu trước đó để khôi phục.",
            }
        try:
            prev_info = json.loads((backup_dir / "info.json").read_text(encoding="utf-8"))
            prev_version = str(prev_info.get("versions", "0.0.0"))
            self._restore_from_backup(backup_dir)

            self._write_cache({
                "status": True,
                "current_version": prev_version,
                "latest_version": prev_version,
                "has_update": False,
                "checked_at": int(time.time()),
            })
            return {
                "status": True,
                "msg": f"Đã khôi phục thành công về phiên bản {prev_version}.",
                "version": prev_version,
            }
        except Exception as error:
            return {
                "status": False,
                "msg": f"Khôi phục thất bại: {error}",
            }
