"""Explicit native-user backend. Never selected as an isolation fallback."""
from __future__ import annotations

from containment import CODE_FILES, LIBRARY_ROOT, WORKER_CAP, launch_path_problems
from execution_policy import NATIVE, execution_mode, require_protected_file
from policy import PolicyError
from runner import SudoRunner


class NativeUserRunner(SudoRunner):
    execution_mode = NATIVE
    unavailable_code = 'native_worker_unavailable'

    def _require_native(self) -> None:
        if execution_mode() != NATIVE:
            raise PolicyError('native_worker_unavailable', 'Owner has not enabled native-user execution.')
        require_protected_file(WORKER_CAP, executable=True)
        require_protected_file(LIBRARY_ROOT / 'worker.json')
        for name in CODE_FILES:
            require_protected_file(LIBRARY_ROOT / name)
        if launch_path_problems(LIBRARY_ROOT):
            raise PolicyError('unsafe_executor', 'Worker modules are missing or writable.')

    def installed(self) -> bool:
        try:
            self._require_native()
        except (PolicyError, OSError):
            return False
        return True

    def _call(self, payload: dict, timeout: int) -> dict:
        # Recheck on every operation, including booted/shutdown. A changed policy
        # never leaves a previously created native runner authorized.
        self._require_native()
        return super()._call(payload, timeout)
