"""Identify, recover and reap only core processes using this client's config."""
import os
import signal
import subprocess
import time


def matches_process(pid, binary_path, config_path):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as stream:
            argv = [arg.decode(errors="replace") for arg in stream.read().split(b"\0") if arg]
        if not argv or os.path.basename(argv[0]) != os.path.basename(binary_path):
            return False
        for index, arg in enumerate(argv[:-1]):
            if arg in ("-c", "--config"):
                return os.path.realpath(argv[index + 1]) == os.path.realpath(config_path)
    except (OSError, ValueError):
        pass
    return False


def managed_pids(manager, config_path):
    if manager.process is not None:
        manager.process.poll()  # Reap exited children before inspecting /proc.
    candidates = set()
    try:
        with open(manager.pid_file) as stream:
            candidates.add(int(stream.read().strip()))
    except (OSError, ValueError):
        pass
    # Recover a core left behind by a crashed client or missing PID file.
    candidates.update(int(name) for name in os.listdir("/proc") if name.isdigit())
    return [pid for pid in candidates
            if matches_process(pid, manager.binary_path, config_path)]


def stop_processes(manager, config_path):
    for pid in managed_pids(manager, config_path):
        try:
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 2
            while matches_process(pid, manager.binary_path, config_path):
                if manager.process is not None:
                    manager.process.poll()
                if time.monotonic() >= deadline:
                    # Recheck ownership immediately before escalation.
                    if matches_process(pid, manager.binary_path, config_path):
                        os.kill(pid, signal.SIGKILL)
                    kill_deadline = time.monotonic() + 2
                    while matches_process(pid, manager.binary_path, config_path):
                        if manager.process is not None:
                            manager.process.poll()
                        if time.monotonic() >= kill_deadline:
                            manager.last_error = f"Процесс {pid} не завершился после SIGKILL."
                            return False
                        time.sleep(0.025)
                    break
                time.sleep(0.025)
        except ProcessLookupError:
            pass
        except OSError as exc:
            manager.last_error = f"Не удалось остановить процесс {pid}: {exc}"
            return False
    if manager.process is not None:
        try:
            manager.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            manager.last_error = "Ядро VPN не завершилось вовремя."
            return False
    if managed_pids(manager, config_path):
        manager.last_error = "Ядро VPN всё ещё работает."
        return False
    manager.process = None
    try:
        os.unlink(manager.pid_file)
    except FileNotFoundError:
        pass
    return True
