import os
import re
import shlex
import signal
import subprocess
import time
from pathlib import Path

from lib.backend_detector import detect_webserver_environment
from lib.ols_adapter import ConfigTestResult


def parse_config_test(output, exit_code):
    lines = output.splitlines()
    errors = [line for line in lines if re.search(r"\[(?:emerg|alert|crit|error)\]|configuration file .*test failed", line)]
    if exit_code != 0 and not errors:
        errors.append("Nginx config test exited with code " + str(exit_code))
    return ConfigTestResult(exit_code, tuple(errors), tuple(line for line in lines if "[warn]" in line), output)


def _safe_path(value):
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts or any(ord(char) < 32 for char in str(path))
            or any(part.is_symlink() for part in (path, *path.parents))):
        raise ValueError("Nginx paths must be absolute and must not contain symlinks or traversal")
    return path


def _process_stat(process):
    fields = (process / "stat").read_text().rsplit(")", 1)[1].split()
    return fields[0], int(fields[1]), fields[19]


def _command(process):
    return (process / "cmdline").read_bytes().split(b"\0", 1)[0].decode().strip()


class NginxAdapter:
    def __init__(self, binary_path, conf_path, *, prefix=None, runner=None, environment_reader=None,
                 proc_root="/proc", timeout=30, reload_timeout=10):
        self.binary_path = _safe_path(binary_path)
        self.conf_path = _safe_path(conf_path)
        self.prefix = _safe_path(prefix) if prefix is not None else None
        if timeout <= 0 or reload_timeout <= 0:
            raise ValueError("Nginx timeouts must be positive")
        self._runner = runner or subprocess.run
        self._environment_reader = environment_reader or detect_webserver_environment
        self._proc = Path(proc_root)
        self.timeout = timeout
        self.reload_timeout = reload_timeout
        self.last_error = ""

    def _run(self, arguments):
        if not _safe_path(self.binary_path).is_file() or not os.access(self.binary_path, os.X_OK):
            raise ValueError("Nginx executable is unavailable")
        return self._runner([str(self.binary_path), *arguments], capture_output=True, text=True,
                            timeout=self.timeout, check=False, shell=False)

    def test_config(self):
        self.last_error = ""
        try:
            if not _safe_path(self.conf_path).is_file():
                raise ValueError("Nginx config is unavailable")
            arguments = ["-t", "-c", str(self.conf_path)]
            if self.prefix is not None:
                if not _safe_path(self.prefix).is_dir():
                    raise ValueError("Nginx prefix is unavailable")
                arguments.extend(["-p", str(self.prefix)])
            result = self._run(arguments)
            parsed = parse_config_test("\n".join(part for part in (result.stdout, result.stderr) if part), result.returncode)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            parsed = parse_config_test(str(error), -1)
        if not parsed.valid:
            self.last_error = "\n".join(parsed.errors)
        return parsed

    def _build_flags(self):
        result = self._run(["-V"])
        if result.returncode != 0:
            raise ValueError("Unable to read Nginx build metadata")
        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        match = re.search(r"^configure arguments:\s*(.*)$", output, re.M)
        return shlex.split(match.group(1)) if match else []

    def _master(self, identity):
        process = self._proc / str(identity[0])
        state, parent, start_time = _process_stat(process)
        if state in {"Z", "X"} or start_time != identity[1]:
            raise ValueError("Nginx master identity changed")
        if not _command(process).startswith("nginx: master process "):
            raise ValueError("Process is not a Nginx master")
        if (process / "exe").resolve(strict=True) != self.binary_path:
            raise ValueError("Nginx master executable changed")
        executable = (process / "exe").stat()
        expected = _safe_path(self.binary_path).stat()
        if (executable.st_dev, executable.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError("Nginx executable inode changed")
        for namespace in ("net", "mnt"):
            if os.readlink(process / "ns" / namespace) != os.readlink(self._proc / "self/ns" / namespace):
                raise ValueError("Nginx namespace does not match the panel")
        return process

    def _runtime(self, *, details=False):
        runtime = self._environment_reader()
        if (runtime.get("backend") != "nginx" or runtime.get("confidence") != "verified"
                or runtime.get("is_container") is not False
                or runtime.get("binary") != self.binary_path or runtime.get("main_config") != self.conf_path):
            raise ValueError("No verified matching aaPanel Nginx runtime")
        expected_prefix = self.prefix
        if expected_prefix is None:
            prefixes = [value.split("=", 1)[1] for value in self._build_flags() if value.startswith("--prefix=")]
            if len(prefixes) != 1:
                raise ValueError("Unable to verify Nginx runtime prefix")
            expected_prefix = _safe_path(prefixes[0])
        if runtime.get("prefix") != expected_prefix:
            raise ValueError("Nginx runtime prefix mismatch")
        master_pid = runtime.get("master_pid")
        start_time = runtime.get("start_time")
        if type(master_pid) is not int or master_pid <= 1 or not isinstance(start_time, str) or not start_time.isdigit():
            raise ValueError("Invalid Nginx master identity")
        identity = (master_pid, start_time)
        self._master(identity)
        return dict(runtime) if details else identity

    def get_runtime_identity(self):
        return self._runtime(details=True)

    def check_realip_support(self):
        self.last_error = ""
        try:
            identity = self._runtime()
            supported = "--with-http_realip_module" in self._build_flags()
            self._master(identity)
            if not supported:
                self.last_error = "Nginx RealIP module is unavailable"
            return supported
        except (OSError, ValueError, IndexError, subprocess.SubprocessError) as error:
            self.last_error = str(error)
            return False

    def check_geoip2_support(self):
        self.last_error = ""
        try:
            identity = self._runtime()
            flags = self._build_flags()
            supported = any(value.startswith("--add-module=")
                            and Path(value.split("=", 1)[1]).name == "ngx_http_geoip2_module" for value in flags)
            if not supported:
                for line in (self._master(identity) / "maps").read_text().splitlines():
                    fields = line.split(None, 5)
                    if len(fields) != 6 or "x" not in fields[1] or not fields[5].endswith("/ngx_http_geoip2_module.so"):
                        continue
                    module = _safe_path(fields[5])
                    metadata = module.stat()
                    major, minor = (int(value, 16) for value in fields[3].split(":"))
                    if (metadata.st_ino == int(fields[4]) and metadata.st_dev == os.makedev(major, minor)
                            and module.is_file()):
                        supported = True
                        break
            self._master(identity)
            if not supported:
                self.last_error = "Nginx GeoIP2 module is not verified in the running runtime"
            return supported
        except (OSError, ValueError, IndexError, subprocess.SubprocessError) as error:
            self.last_error = str(error)
            return False

    def _workers(self, identity):
        workers = set()
        for process in self._proc.iterdir():
            if not process.name.isdigit():
                continue
            try:
                state, parent, start_time = _process_stat(process)
                if parent != identity[0] or state in {"Z", "X"} or _command(process) != "nginx: worker process":
                    continue
                if (process / "exe").resolve(strict=True) != self.binary_path:
                    continue
                workers.add((int(process.name), start_time))
            except (OSError, ValueError, IndexError):
                continue
        return workers

    def reload_service(self):
        self.last_error = ""
        descriptor = None
        try:
            identity = self._runtime()
            if not self.test_config().valid:
                return False
            if self._runtime() != identity:
                raise ValueError("Nginx runtime changed during config test")
            previous = self._workers(identity)
            if not previous:
                raise ValueError("Nginx has no active workers before reload")
            if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
                raise ValueError("Safe Nginx reload requires pidfd support")
            descriptor = os.pidfd_open(identity[0], 0)
            if self._runtime() != identity:
                raise ValueError("Nginx runtime changed before signaling")
            signal.pidfd_send_signal(descriptor, signal.SIGHUP, None, 0)
            deadline = time.monotonic() + self.reload_timeout
            stable_workers = set()
            stable_since = None
            while time.monotonic() < deadline:
                self._master(identity)
                current = self._workers(identity)
                if current and not current.intersection(previous):
                    if current != stable_workers:
                        stable_workers = current
                        stable_since = time.monotonic()
                    elif time.monotonic() - stable_since >= 0.2:
                        return True
                else:
                    stable_workers = set()
                    stable_since = None
                time.sleep(0.1)
            raise ValueError("Nginx reload timed out waiting for stable new workers")
        except (OSError, ValueError, IndexError, subprocess.SubprocessError) as error:
            self.last_error = str(error)
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)
