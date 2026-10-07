"""
graph.py
========
Dependency-aware, bounded-concurrency execution of diagnostic nodes.

    Local interface -> Gateway -> Routing -> DNS -> TCP -> TLS -> HTTP

A *node* is a unit of work (usually one test module) that returns a list of
:class:`TestResult`. A node declares:

* ``hard`` dependencies - if one of them fails its *gate*, this node is not
  run; it is reported as ``SKIPPED`` / ``BLOCKED_BY_DEPENDENCY`` instead of
  producing a misleading failure of its own.
* ``soft`` dependencies - run first (ordering) and annotate the result, but
  never block it (e.g. a gateway that ignores ping must not stop DNS tests).
* ``exclusive`` - measurement-sensitive nodes (latency, MTU, throughput) that
  must not share the network with other probes while they run.

A dependency that was not selected by the user is simply "unknown", and does
not block anything.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable, Iterable

from app.diag.neterrors import normalize_exception
from app.diag.results import Evidence, EvidenceKind, Severity, TechnicalStatus, TestResult
from app.logger import get_logger

log = get_logger(__name__)

Gate = Callable[[list[TestResult]], bool]
SKIP_BLOCKED = "BLOCKED_BY_DEPENDENCY"
SKIP_CANCELLED = "CANCELLED"


def default_gate(results: list[TestResult]) -> bool:
    """A node 'passed' if at least one real (non-skipped) result succeeded."""
    return any(r.ok for r in results)


@dataclass
class Node:
    node_id: str
    run: Callable[["RunContext"], list[TestResult]]
    hard: tuple[str, ...] = ()
    soft: tuple[str, ...] = ()
    gate: Gate = default_gate
    exclusive: bool = False
    layer: str = ""


@dataclass
class RunContext:
    cancel: threading.Event
    results: dict[str, list[TestResult]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def get(self, node_id: str) -> list[TestResult] | None:
        with self.lock:
            return self.results.get(node_id)


def skipped_result(node: Node, reason: str, blocked_by: Iterable[str] = ()) -> TestResult:
    result = TestResult(
        test_id=node.node_id, category=node.layer or "node",
        status=TechnicalStatus.SKIPPED, severity=Severity.SKIPPED,
        summary=("Not run: an earlier step it depends on did not succeed."
                 if reason == SKIP_BLOCKED else "Not run: the diagnostic was cancelled."),
    )
    result.metadata["skip_reason"] = reason
    result.metadata["blocked_by"] = list(blocked_by)
    if reason == SKIP_BLOCKED:
        result.evidence.append(Evidence(
            f"Blocked by failed dependency: {', '.join(blocked_by)}",
            EvidenceKind.MEASURED, node.node_id))
    return result


class DependencyGraph:
    def __init__(self, nodes: Iterable[Node]) -> None:
        self.nodes: dict[str, Node] = {}
        for node in nodes:
            if node.node_id in self.nodes:
                raise ValueError(f"duplicate node id: {node.node_id}")
            self.nodes[node.node_id] = node
        self._validate()

    def _validate(self) -> None:
        for node in self.nodes.values():
            for dep in (*node.hard, *node.soft):
                if dep == node.node_id:
                    raise ValueError(f"node {dep} depends on itself")
        # cycle detection (DFS) over dependencies that exist in this graph
        state: dict[str, int] = {}

        def visit(nid: str, path: list[str]) -> None:
            if state.get(nid) == 2:
                return
            if state.get(nid) == 1:
                raise ValueError("dependency cycle: " + " -> ".join([*path, nid]))
            state[nid] = 1
            node = self.nodes[nid]
            for dep in (*node.hard, *node.soft):
                if dep in self.nodes:
                    visit(dep, [*path, nid])
            state[nid] = 2

        for nid in self.nodes:
            visit(nid, [])

    def deps_in_graph(self, node: Node) -> tuple[list[str], list[str]]:
        return ([d for d in node.hard if d in self.nodes], [d for d in node.soft if d in self.nodes])


class GraphRunner:
    """Runs a graph with at most ``max_workers`` nodes in flight."""

    def __init__(
        self,
        graph: DependencyGraph,
        max_workers: int = 8,
        cancel: threading.Event | None = None,
        on_start: Callable[[Node], None] | None = None,
        on_done: Callable[[Node, list[TestResult]], None] | None = None,
    ) -> None:
        self.graph = graph
        self.max_workers = max(1, max_workers)
        self.cancel = cancel or threading.Event()
        self.on_start = on_start
        self.on_done = on_done

    # -- internals --------------------------------------------------------
    def _execute(self, node: Node, ctx: RunContext) -> list[TestResult]:
        started = time.perf_counter()
        try:
            if self.on_start:
                self.on_start(node)
            results = node.run(ctx)
        except Exception as exc:  # noqa: BLE001 - a node must never take the run down
            err = normalize_exception(exc)
            log.exception("diag node %s crashed", node.node_id)
            results = [TestResult(
                test_id=node.node_id, category=node.layer or "node", status=TechnicalStatus.ERROR,
                error_type=err.error_type, error_code=err.error_code, error_message=err.error_message,
                summary=f"The test could not be completed ({err.error_type}).",
            )]
        for r in results:
            if r.duration_ms is None:
                r.duration_ms = (time.perf_counter() - started) * 1000.0
        return results

    def _finish(self, node: Node, results: list[TestResult], ctx: RunContext) -> None:
        with ctx.lock:
            ctx.results[node.node_id] = results
        if self.on_done:
            try:
                self.on_done(node, results)
            except Exception:  # noqa: BLE001 - callbacks are UI code; never break the run
                log.exception("on_done callback failed for %s", node.node_id)

    def run(self) -> RunContext:
        ctx = RunContext(cancel=self.cancel)
        pending = dict(self.graph.nodes)
        running: dict[Future[list[TestResult]], Node] = {}
        done_ids: set[str] = set()

        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="icpa-diag") as pool:
            while pending or running:
                if self.cancel.is_set():
                    for node in list(pending.values()):
                        self._finish(node, [skipped_result(node, SKIP_CANCELLED)], ctx)
                        done_ids.add(node.node_id)
                    pending.clear()

                started_any = False
                exclusive_running = any(n.exclusive for n in running.values())
                for node in list(pending.values()):
                    hard, soft = self.graph.deps_in_graph(node)
                    if any(d not in done_ids for d in (*hard, *soft)):
                        continue                                  # wait for dependencies
                    failed = [d for d in hard if not self._passed(d, ctx)]
                    if failed:
                        self._finish(node, [skipped_result(node, SKIP_BLOCKED, failed)], ctx)
                        done_ids.add(node.node_id)
                        del pending[node.node_id]
                        started_any = True
                        continue
                    if exclusive_running or len(running) >= self.max_workers:
                        continue
                    if node.exclusive and running:
                        continue                                  # needs the network to itself
                    running[pool.submit(self._execute, node, ctx)] = node
                    del pending[node.node_id]
                    started_any = True
                    exclusive_running = node.exclusive or exclusive_running

                if running:
                    finished, _ = wait(list(running), timeout=0.2, return_when=FIRST_COMPLETED)
                    for fut in finished:
                        node = running.pop(fut)
                        self._finish(node, fut.result(), ctx)
                        done_ids.add(node.node_id)
                elif not started_any and pending:
                    # Only possible if a dependency id is missing from done_ids: cannot happen
                    # after validation, but never spin forever.
                    for node in list(pending.values()):
                        self._finish(node, [skipped_result(node, SKIP_BLOCKED, ["unresolved"])], ctx)
                        done_ids.add(node.node_id)
                    pending.clear()
        return ctx

    def _passed(self, node_id: str, ctx: RunContext) -> bool:
        results = ctx.get(node_id) or []
        if results and all(r.skipped for r in results):
            return False                    # an upstream node that was itself blocked
        node = self.graph.nodes[node_id]
        return bool(node.gate(results))
