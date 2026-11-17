"""
Batch analysis in worker processes with a per-file time limit.

Each file is analysed in a separate worker process, so a file that hangs or crashes
the image libraries is reported as an error and the rest of the batch continues.
"""

from __future__ import annotations

import multiprocessing as mp
import time
from collections import deque
from collections.abc import Callable, Sequence
from multiprocessing.connection import Connection, wait
from pathlib import Path
from typing import Any

from src.core.models import AnalysisResult

Analyzer = Callable[[Path], AnalysisResult]
ResultCallback = Callable[[int, AnalysisResult], None]

# How often the parent wakes up to check deadlines while all workers are busy.
_POLL_SECONDS = 0.25


def _worker_main(conn: Connection, analyze: Analyzer) -> None:
    """Analyse the paths sent by the parent until it sends None or closes the pipe."""
    while True:
        try:
            path = conn.recv()
        except (EOFError, OSError):
            return
        if path is None:
            return
        conn.send(analyze(path))


class _Worker:
    """One worker process and the pipe the parent uses to talk to it."""

    def __init__(self, ctx: Any, analyze: Analyzer) -> None:
        self.conn, child_conn = ctx.Pipe()
        self.process = ctx.Process(target=_worker_main, args=(child_conn, analyze), daemon=True)
        self.process.start()
        child_conn.close()
        self.index = -1
        self.started = 0.0

    def stop(self, kill: bool = False) -> None:
        if kill:
            self.process.kill()
        else:
            try:
                self.conn.send(None)
            except OSError:
                pass
        self.process.join(timeout=5)
        if self.process.is_alive():
            self.process.kill()
            self.process.join()
        self.conn.close()


def run_parallel(
    paths: Sequence[str | Path],
    *,
    workers: int = 1,
    timeout: float | None = None,
    analyze: Analyzer | None = None,
    on_result: ResultCallback | None = None,
) -> list[AnalysisResult]:
    """
    Analyse `paths` in up to `workers` processes; results come back in input order.

    A file still running after `timeout` seconds has its worker stopped and is reported
    as an error, as is a file whose worker process dies. `on_result(index, result)` is
    called as each file finishes (completion order), e.g. to show progress.
    """
    from src.core.pipeline import analyze_file, error_result

    analyze = analyze or analyze_file
    items = [Path(p) for p in paths]
    results: list[AnalysisResult | None] = [None] * len(items)
    capacity = max(1, min(workers, len(items)))
    ctx = mp.get_context("spawn")  # same behaviour on Windows, macOS and Linux
    pending = deque(range(len(items)))
    idle: list[_Worker] = []
    busy: dict[Connection, _Worker] = {}

    def finish(index: int, result: AnalysisResult) -> None:
        results[index] = result
        if on_result is not None:
            on_result(index, result)

    def fail(worker: _Worker, message: str) -> None:
        worker.stop(kill=True)
        finish(worker.index, error_result(str(items[worker.index]), message))

    try:
        while pending or busy:
            while pending and (idle or len(busy) < capacity):
                worker = idle.pop() if idle else _Worker(ctx, analyze)
                worker.index, worker.started = pending.popleft(), time.monotonic()
                try:
                    worker.conn.send(items[worker.index])
                except OSError:
                    fail(worker, "Analysis process stopped unexpectedly")
                    continue
                busy[worker.conn] = worker

            for conn in wait(list(busy), timeout=_POLL_SECONDS):
                worker = busy.pop(conn)  # type: ignore[call-overload]
                try:
                    finish(worker.index, worker.conn.recv())
                except (EOFError, OSError):
                    fail(worker, "Analysis process crashed (the file may be malformed)")
                else:
                    idle.append(worker)

            if timeout:
                now = time.monotonic()
                for conn, worker in list(busy.items()):
                    if now - worker.started <= timeout or conn.poll():
                        continue  # still within its time, or its result has just arrived
                    del busy[conn]
                    fail(worker, f"Timed out after {timeout:g} s")
    finally:
        for worker in idle:
            worker.stop()
        for worker in busy.values():
            worker.stop(kill=True)

    return [r or error_result(str(items[i]), "Analysis did not finish") for i, r in enumerate(results)]
