"""``mongoops regex-finder``: find $regex usage in slow queries (Atlas, Ops Manager, logs, live)."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, tzinfo
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

from mongoops.common import atlas_api, ops_manager_api
from mongoops.common.perf_advisor import ApiError, SlowQueryWindow
from mongoops.common.timeutil import (
    NO_WINDOW,
    TimeWindow,
    WindowSpec,
    describe_window,
    format_instant,
    is_naive,
    is_utc,
    local_zone,
    parse_instant_ms,
    parse_zone,
    resolve_window,
    validate_window,
)
from mongoops.regex_finder import sources
from mongoops.regex_finder.analyze import AnalyzeOptions, Finding, SourceLine, analyze_lines
from mongoops.regex_finder.remedy import Remedy
from mongoops.regex_finder.report import ReportMeta, render, summarize

app = typer.Typer(
    name="regex-finder",
    help="Find $regex usage in slow queries reported by Performance Advisor (Atlas / Ops Manager) "
    "or found in mongod logs.",
    no_args_is_help=True,
)
err = Console(stderr=True)

API_DEFAULT_WINDOW = "last 24h (API default)"


class Fmt(StrEnum):
    table = "table"
    csv = "csv"
    json = "json"
    html = "html"


class ViewOpt(StrEnum):
    summary = "summary"
    details = "details"
    both = "both"
    hotspots = "hotspots"


# --- shared options ---------------------------------------------------------------------------

FormatOpt = Annotated[Fmt, typer.Option("--format", "-f", help="Output format.")]
ViewOption = Annotated[
    ViewOpt,
    typer.Option(
        "--view",
        help="summary (where the time goes + what to do + shapes), details (one row per hit), "
        "both, or hotspots (database / collection roll-up only).",
    ),
]
OutputOpt = Annotated[
    Path | None, typer.Option("--output", "-o", help="Write output to this file instead of stdout.")
]
HtmlOpt = Annotated[
    Path | None,
    typer.Option(
        "--html",
        help="Also write a self-contained HTML dashboard to this file (keeps stdout output).",
    ),
]
NamespaceOpt = Annotated[
    list[str] | None,
    typer.Option("--namespace", "-n", help="Only db.coll (repeatable)."),
]
IncludeGetMoreOpt = Annotated[
    bool, typer.Option("--include-getmore", help="Count getMore continuations as separate hits.")
]
MinDurationOpt = Annotated[int, typer.Option("--min-ms", help="Ignore ops faster than this.")]
MaxRowsOpt = Annotated[
    int, typer.Option("--max-rows", help="Detail rows shown in table format (csv/json: all).")
]
SinceOpt = Annotated[
    str | None,
    typer.Option(
        "--since",
        help='Window start: an age ("24h", "7d") or a date/time ("2026-10-07 14:00", '
        '"2026-10-07T14:00+07:00"). API sources default to the last 24h.',
    ),
]
UntilOpt = Annotated[
    str | None,
    typer.Option(
        "--until",
        help="Window end, same formats as --since. Needs --since, or --duration for a window "
        "ending then.",
    ),
]
DurationOpt = Annotated[
    str | None,
    typer.Option(
        "--duration",
        help='Window length, e.g. "6h": from --since, up to --until, or the last 6h when alone.',
    ),
]
AtOpt = Annotated[
    str | None,
    typer.Option(
        "--at",
        help='Incident moment; the window is --around either side, e.g. --at "2026-10-07 14:30".',
    ),
]
AroundOpt = Annotated[
    str | None, typer.Option("--around", help="Margin either side of --at (default 30m).")
]
TzOpt = Annotated[
    str | None,
    typer.Option(
        "--tz",
        envvar="MONGOOPS_TZ",
        help="Zone for date/times typed without an offset and for times shown in the table and "
        "dashboard: UTC, local, Asia/Bangkok, +07:00. Default UTC; asks when run interactively. "
        "CSV/JSON stay UTC.",
    ),
]
NLogsOpt = Annotated[
    int, typer.Option("--n-logs", help="Max log lines per process (API max 20000).")
]
FailOnOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--fail-on",
        help="Exit 1 when any shape has one of these remedies (repeatable or comma separated), "
        "e.g. --fail-on search,fix_filter,btree_index.",
    ),
]


@dataclass(frozen=True, slots=True)
class OutputOptions:
    fmt: Fmt
    view: ViewOpt
    output: Path | None
    max_rows: int
    meta: ReportMeta
    html: Path | None = None
    fail_on: frozenset[Remedy] = frozenset()


def parse_fail_on(values: list[str] | None) -> frozenset[Remedy]:
    """``["search,fix_filter", "btree_index"]`` -> remedies; unknown names are a usage error."""
    names = tuple(n.strip() for v in values or () for n in v.split(",") if n.strip())
    unknown = tuple(n for n in names if n not in Remedy.__members__.values())
    if unknown:
        raise ValueError(
            f"--fail-on: unknown remedy {', '.join(unknown)}; "
            f"choose from {', '.join(r.value for r in Remedy)}"
        )
    return frozenset(Remedy(n) for n in names)


def _meta(
    source: str,
    target: str,
    *,
    window: str = "",
    namespaces: list[str] | None = None,
    min_ms: int = 0,
    include_getmore: bool = False,
    tz: tzinfo = UTC,
) -> ReportMeta:
    """Describe the run for the dashboard header (pure)."""
    filters = (
        *(f"namespace {ns}" for ns in namespaces or ()),
        *((f"min {min_ms} ms",) if min_ms else ()),
        *(("getMore included",) if include_getmore else ()),
    )
    return ReportMeta(source=source, target=target, window=window, filters=filters, display_tz=tz)


def _redact_uri(uri: str) -> str:
    """Drop user:password from a connection string before it lands in a report."""
    return re.sub(r"//[^@/]+@", "//***@", uri)


def _analyze_options(
    namespaces: list[str] | None,
    include_getmore: bool,
    min_ms: int,
    window: TimeWindow = NO_WINDOW,
) -> AnalyzeOptions:
    return AnalyzeOptions(
        include_getmore=include_getmore,
        namespaces=frozenset(namespaces or ()),
        min_duration_ms=min_ms,
        window=window,
    )


def _api_window(window: TimeWindow, namespaces: list[str] | None, n_logs: int) -> SlowQueryWindow:
    return SlowQueryWindow(
        since_ms=window.start_ms,
        duration_ms=window.duration_ms,
        namespaces=tuple(namespaces or ()),
        n_logs=n_logs,
    )


# --- time window and zone ---------------------------------------------------------------------


def _resolve_time(spec: WindowSpec, tz_name: str | None) -> tuple[TimeWindow, tzinfo]:
    """Validate the flags, settle the zone (asking if needed), then resolve the window."""
    validate_window(spec)
    zone = _zone(spec, tz_name)
    return resolve_window(spec, tz=zone), zone


def _zone(spec: WindowSpec, tz_name: str | None) -> tzinfo:
    if tz_name:
        return parse_zone(tz_name)
    naive = tuple(t for t in spec.typed_instants() if is_naive(t))
    local = local_zone()
    if not naive or is_utc(local):
        return UTC
    if not _interactive():
        err.print(
            f"{', '.join(naive)} read as UTC; pass --tz (or set MONGOOPS_TZ) for another zone",
            style="dim",
            markup=False,
        )
        return UTC
    return _ask_zone(naive[0], local)


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def _ask_zone(sample: str, local: tzinfo) -> tzinfo:
    """Ask once whether a date/time without an offset is UTC or this machine's zone."""
    as_utc, as_local = parse_instant_ms(sample, tz=UTC), parse_instant_ms(sample, tz=local)
    err.print(
        f'"{sample}" has no time zone:\n'
        f"  u  UTC           {format_instant(as_utc, UTC)}"
        f"  (= {format_instant(as_utc, local)} here)\n"
        f"  l  this machine  {format_instant(as_local, local)}"
        f"  (= {format_instant(as_local, UTC)})",
        markup=False,
        highlight=False,
    )
    choice = typer.prompt("Read it as [u/l]", default="u", value_proc=_zone_choice, err=True)
    return local if choice == "l" else UTC


def _zone_choice(answer: str) -> str:
    choice = answer.strip().lower()[:1]
    if choice not in ("u", "l"):
        raise typer.BadParameter("answer u (UTC) or l (this machine)")
    return choice


def _window_text(window: TimeWindow, tz: tzinfo, *, default: str = "") -> str:
    return describe_window(window, tz) or default


# --- output -----------------------------------------------------------------------------------


def _emit(
    lines: Iterable[SourceLine],
    analyze: AnalyzeOptions,
    out: OutputOptions,
    warnings: Sequence[str] = (),
) -> None:
    findings: tuple[Finding, ...] = tuple(analyze_lines(lines, analyze))
    # ``warnings`` is filled by the progress callback while ``lines`` is drained above.
    meta = replace(out.meta, warnings=(*out.meta.warnings, *warnings))
    text = render(
        findings,
        fmt=out.fmt.value,
        view=out.view.value,
        max_detail_rows=out.max_rows if out.fmt == Fmt.table else None,
        meta=meta,
    )
    if out.output:
        _write(out.output, text)
        err.print(f"[green]Wrote {len(findings)} finding(s) to {out.output}[/green]")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    if out.html:
        _write(out.html, render(findings, fmt="html", view="both", meta=meta))
        # soft_wrap keeps the URI on one line so terminals can make it clickable
        err.print(f"[green]Dashboard: {out.html.resolve().as_uri()}[/green]", soft_wrap=True)
    window = f", window {meta.window}" if meta.window else ""
    err.print(
        f"{len(findings)} regex usage(s) found{window}", style="dim", markup=False, soft_wrap=True
    )
    blocking = tuple(r for r in summarize(findings) if r.remedy in out.fail_on)
    if blocking:
        for r in blocking:
            err.print(f"[red]blocking:[/red] {r.namespace} {r.field} {r.command} -> {r.remedy}")
        raise typer.Exit(code=1)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _progress(n_logs: int, warnings: list[str]) -> sources.ProgressFn:
    """Report per-node line counts; flag nodes that hit the cap (their window is incomplete)."""

    def report(origin: str, count: int) -> None:
        err.print(f"[dim]{origin}: {count} slow query line(s)[/dim]")
        if count >= n_logs:
            note = (
                f"{origin} returned {count:,} lines, the --n-logs cap: part of the window is "
                "missing; narrow it with --since/--until or --at/--around"
            )
            warnings.append(note)
            err.print(f"warning: {note}", style="yellow", markup=False)

    return report


def _fail(message: str) -> NoReturn:
    err.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code=2)


# --- commands ---------------------------------------------------------------------------------


@app.command()
def atlas(
    project_id: Annotated[
        str,
        typer.Option(
            "--project-id",
            "-p",
            envvar="MONGODB_ATLAS_PROJECT_ID",
            help="Atlas project (group) id.",
        ),
    ],
    cluster: Annotated[
        str | None, typer.Option("--cluster", "-c", help="Cluster name; selects all its processes.")
    ] = None,
    process: Annotated[
        list[str] | None,
        typer.Option(
            "--process",
            help="Explicit processId host:port (repeatable). Overrides --cluster filter scope.",
        ),
    ] = None,
    base_url: Annotated[
        str, typer.Option(envvar="MONGODB_ATLAS_OPS_MANAGER_URL", help="Atlas API base URL.")
    ] = atlas_api.DEFAULT_BASE_URL,
    since: SinceOpt = None,
    until: UntilOpt = None,
    duration: DurationOpt = None,
    at: AtOpt = None,
    around: AroundOpt = None,
    tz: TzOpt = None,
    n_logs: NLogsOpt = 20_000,
    namespace: NamespaceOpt = None,
    include_getmore: IncludeGetMoreOpt = False,
    min_ms: MinDurationOpt = 0,
    fmt: FormatOpt = Fmt.table,
    view: ViewOption = ViewOpt.both,
    output: OutputOpt = None,
    html: HtmlOpt = None,
    max_rows: MaxRowsOpt = 50,
    fail_on: FailOnOpt = None,
) -> None:
    """Atlas: pull Performance Advisor slow query logs for a cluster and report $regex usage.

    Credentials from MONGODB_ATLAS_PUBLIC_API_KEY / MONGODB_ATLAS_PRIVATE_API_KEY (digest) or
    MONGODB_ATLAS_CLIENT_ID / MONGODB_ATLAS_CLIENT_SECRET (service account). A .env file is read.
    """
    try:
        gate = parse_fail_on(fail_on)
        window, zone = _resolve_time(WindowSpec(since, until, duration, at, around), tz)
    except ValueError as exc:
        _fail(str(exc))
    if not cluster and not process:
        _fail("pass --cluster NAME or at least one --process host:port")
    try:
        with atlas_api.atlas_client(atlas_api.auth_from_env(), base_url=base_url) as client:
            hosts = atlas_api.cluster_hosts(client, project_id, cluster) if cluster else None
            processes = atlas_api.select_processes(
                atlas_api.list_processes(client, project_id),
                hosts=hosts,
                process_ids=process or (),
            )
            if not processes:
                _fail(
                    f"no processes matched cluster={cluster!r} process={process!r} "
                    f"in project {project_id}"
                )
            err.print(f"[dim]{len(processes)} process(es) selected[/dim]")
            target = cluster or ", ".join(p.id for p in processes)
            meta = _meta(
                "atlas",
                f"{target} (project {project_id})",
                window=_window_text(window, zone, default=API_DEFAULT_WINDOW),
                namespaces=namespace,
                min_ms=min_ms,
                include_getmore=include_getmore,
                tz=zone,
            )
            warnings: list[str] = []
            _emit(
                sources.atlas_lines(
                    client,
                    project_id,
                    processes,
                    _api_window(window, namespace, n_logs),
                    _progress(n_logs, warnings),
                ),
                _analyze_options(namespace, include_getmore, min_ms),
                OutputOptions(fmt, view, output, max_rows, meta, html, gate),
                warnings,
            )
    except (ApiError, ValueError) as exc:
        _fail(str(exc))


@app.command("ops-manager")
def ops_manager(
    project_id: Annotated[
        str,
        typer.Option(
            "--project-id",
            "-p",
            envvar="MONGODB_OPS_MANAGER_PROJECT_ID",
            help="Ops Manager project id.",
        ),
    ],
    host_id: Annotated[
        list[str] | None, typer.Option("--host-id", help="Ops Manager host id (repeatable).")
    ] = None,
    replica_set: Annotated[
        str | None, typer.Option("--replica-set", "-r", help="Only hosts in this replica set.")
    ] = None,
    cluster_id: Annotated[
        str | None, typer.Option("--cluster-id", help="Only hosts in this Ops Manager cluster id.")
    ] = None,
    hostname_prefix: Annotated[
        str | None,
        typer.Option("--hostname-prefix", help="Only hosts whose hostname starts with this."),
    ] = None,
    base_url: Annotated[
        str | None, typer.Option(envvar="MONGODB_OPS_MANAGER_URL", help="Ops Manager base URL.")
    ] = None,
    ca_file: Annotated[
        Path | None,
        typer.Option(envvar="MONGODB_OPS_MANAGER_CA_FILE", help="CA bundle for self-signed TLS."),
    ] = None,
    insecure: Annotated[bool, typer.Option("--insecure", help="Skip TLS verification.")] = False,
    since: SinceOpt = None,
    until: UntilOpt = None,
    duration: DurationOpt = None,
    at: AtOpt = None,
    around: AroundOpt = None,
    tz: TzOpt = None,
    n_logs: NLogsOpt = 20_000,
    namespace: NamespaceOpt = None,
    include_getmore: IncludeGetMoreOpt = False,
    min_ms: MinDurationOpt = 0,
    fmt: FormatOpt = Fmt.table,
    view: ViewOption = ViewOpt.both,
    output: OutputOpt = None,
    html: HtmlOpt = None,
    max_rows: MaxRowsOpt = 50,
    fail_on: FailOnOpt = None,
) -> None:
    """Enterprise Advanced: pull Ops Manager Performance Advisor slow queries, report $regex usage.

    Credentials from MONGODB_OPS_MANAGER_PUBLIC_API_KEY / MONGODB_OPS_MANAGER_PRIVATE_API_KEY.
    Without host filters every host in the project is queried.
    """
    try:
        gate = parse_fail_on(fail_on)
        window, zone = _resolve_time(WindowSpec(since, until, duration, at, around), tz)
    except ValueError as exc:
        _fail(str(exc))
    env_cfg = ops_manager_api.config_from_env()
    cfg = ops_manager_api.OpsManagerConfig(
        base_url=base_url or env_cfg.base_url,
        public_key=env_cfg.public_key,
        private_key=env_cfg.private_key,
        ca_file=str(ca_file) if ca_file else env_cfg.ca_file,
        verify_tls=not insecure,
    )
    try:
        with ops_manager_api.ops_manager_client(cfg) as client:
            hosts = ops_manager_api.select_hosts(
                ops_manager_api.list_hosts(client, project_id),
                host_ids=host_id or (),
                replica_set=replica_set,
                cluster_id=cluster_id,
                hostname_prefix=hostname_prefix,
            )
            if not hosts:
                _fail(f"no hosts matched the given filters in project {project_id}")
            err.print(f"[dim]{len(hosts)} host(s) selected[/dim]")
            scope = replica_set or cluster_id or hostname_prefix or f"{len(hosts)} host(s)"
            meta = _meta(
                "ops-manager",
                f"{scope} (project {project_id}, {cfg.base_url})",
                window=_window_text(window, zone, default=API_DEFAULT_WINDOW),
                namespaces=namespace,
                min_ms=min_ms,
                include_getmore=include_getmore,
                tz=zone,
            )
            warnings: list[str] = []
            _emit(
                sources.ops_manager_lines(
                    client,
                    project_id,
                    hosts,
                    _api_window(window, namespace, n_logs),
                    _progress(n_logs, warnings),
                ),
                _analyze_options(namespace, include_getmore, min_ms),
                OutputOptions(fmt, view, output, max_rows, meta, html, gate),
                warnings,
            )
    except (ApiError, ValueError) as exc:
        _fail(str(exc))


@app.command()
def logfile(
    path: Annotated[
        str, typer.Argument(help="mongod log file (.log or .log.gz), or '-' for stdin.")
    ],
    since: SinceOpt = None,
    until: UntilOpt = None,
    duration: DurationOpt = None,
    at: AtOpt = None,
    around: AroundOpt = None,
    tz: TzOpt = None,
    namespace: NamespaceOpt = None,
    include_getmore: IncludeGetMoreOpt = False,
    min_ms: MinDurationOpt = 0,
    fmt: FormatOpt = Fmt.table,
    view: ViewOption = ViewOpt.both,
    output: OutputOpt = None,
    html: HtmlOpt = None,
    max_rows: MaxRowsOpt = 50,
    fail_on: FailOnOpt = None,
) -> None:
    """Parse a mongod log file directly (EA without Ops Manager, or exported Atlas logs).

    The time-window flags filter on each line's own timestamp; without them the whole file is read.
    """
    try:
        gate = parse_fail_on(fail_on)
        window, zone = _resolve_time(WindowSpec(since, until, duration, at, around), tz)
    except ValueError as exc:
        _fail(str(exc))
    if path != "-" and not Path(path).exists():
        _fail(f"file not found: {path}")
    meta = _meta(
        "logfile",
        "stdin" if path == "-" else path,
        window=_window_text(window, zone),
        namespaces=namespace,
        min_ms=min_ms,
        include_getmore=include_getmore,
        tz=zone,
    )
    _emit(
        sources.file_lines(path),
        _analyze_options(namespace, include_getmore, min_ms, window),
        OutputOptions(fmt, view, output, max_rows, meta, html, gate),
    )


@app.command()
def live(
    uri: Annotated[str, typer.Option("--uri", envvar="MONGODB_URI", help="Connection string.")],
    since: SinceOpt = None,
    until: UntilOpt = None,
    duration: DurationOpt = None,
    at: AtOpt = None,
    around: AroundOpt = None,
    tz: TzOpt = None,
    namespace: NamespaceOpt = None,
    include_getmore: IncludeGetMoreOpt = False,
    min_ms: MinDurationOpt = 0,
    fmt: FormatOpt = Fmt.table,
    view: ViewOption = ViewOpt.both,
    output: OutputOpt = None,
    html: HtmlOpt = None,
    max_rows: MaxRowsOpt = 50,
    fail_on: FailOnOpt = None,
) -> None:
    """Read the server's in-memory log (getLog) over a live connection; handy for atlas-local.

    The buffer only holds the last ~1024 lines, so the time-window flags can only narrow it.
    """
    try:
        gate = parse_fail_on(fail_on)
        window, zone = _resolve_time(WindowSpec(since, until, duration, at, around), tz)
    except ValueError as exc:
        _fail(str(exc))
    meta = _meta(
        "live",
        f"{_redact_uri(uri)} (getLog ring buffer)",
        window=_window_text(window, zone),
        namespaces=namespace,
        min_ms=min_ms,
        include_getmore=include_getmore,
        tz=zone,
    )
    try:
        _emit(
            sources.getlog_lines(uri),
            _analyze_options(namespace, include_getmore, min_ms, window),
            OutputOptions(fmt, view, output, max_rows, meta, html, gate),
        )
    except typer.Exit:
        raise
    except Exception as exc:  # pymongo raises many connection error types
        _fail(f"{type(exc).__name__}: {exc}")
