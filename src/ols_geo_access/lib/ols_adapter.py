import secrets
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigTestResult:
    exit_code: int
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    output: str

    @property
    def valid(self):
        return not self.errors


def parse_config_test(output, exit_code):
    lines = output.splitlines()
    return ConfigTestResult(
        exit_code=exit_code,
        errors=tuple(line for line in lines if "[ERROR]" in line),
        warnings=tuple(line for line in lines if "[WARN]" in line),
        output=output,
    )


class OLSAdapter:
    CONFIG_TEST_COMMAND = ("/usr/local/lsws/bin/openlitespeed", "-t")
    RELOAD_COMMAND = ("/usr/local/lsws/bin/lswsctrl", "reload")

    def __init__(self, runner=subprocess.run, token_factory=None):
        self._runner = runner
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._reload_token = None

    def _run(self, command, timeout):
        return self._runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )

    def run_config_test(self):
        result = self._run(self.CONFIG_TEST_COMMAND, timeout=30)
        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        return parse_config_test(output, result.returncode)

    def issue_reload_token(self):
        result = self.run_config_test()
        if not result.valid:
            raise RuntimeError("OpenLiteSpeed configuration contains errors")
        self._reload_token = self._token_factory()
        return self._reload_token

    def reload_gracefully(self, token):
        if not self._reload_token or not secrets.compare_digest(token, self._reload_token):
            raise ValueError("invalid reload confirmation token")
        self._reload_token = None
        result = self.run_config_test()
        if not result.valid:
            raise RuntimeError("OpenLiteSpeed configuration contains errors")
        return self._run(self.RELOAD_COMMAND, timeout=60)
