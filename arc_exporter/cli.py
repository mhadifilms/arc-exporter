"""Typer-powered command line.

Subcommands::

    arc-exporter doctor                       Run preflight checks.
    arc-exporter list                         List Arc profiles and spaces.
    arc-exporter export <kind>                Export one artefact kind.
    arc-exporter migrate --to=<target>        Full migration into a target browser.
    arc-exporter backup ls / restore <id>     Manage backups created during prior runs.
    arc-exporter targets                      List installable / detected browser targets.
    arc-exporter version                      Print version.

Every command supports ``--dry-run`` and ``--verbose / -v``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.table import Table

from arc_exporter import __version__
from arc_exporter.config import Config
from arc_exporter.doctor import doctor_exit_code, run_doctor
from arc_exporter.errors import ArcExporterError
from arc_exporter.guards.running_browser import ensure_browsers_quit
from arc_exporter.logging_setup import console, setup_logging
from arc_exporter.orchestrator import ExportOptions, Orchestrator
from arc_exporter.source import get_source
from arc_exporter.targets import all_targets, available_targets, target_by_name
from arc_exporter.targets.base import MigrationRequest

app = typer.Typer(
    name="arc-exporter",
    help="Safely migrate Arc Browser profiles into other browsers.",
    no_args_is_help=True,
    add_completion=False,
    invoke_without_command=True,
)
backup_app = typer.Typer(name="backup", help="Manage backups", no_args_is_help=True)
export_app = typer.Typer(name="export", help="Export portable artefacts", no_args_is_help=True)
rollback_app = typer.Typer(
    name="rollback",
    help="List or remove profiles previously created by arc-exporter",
    no_args_is_help=True,
)
app.add_typer(backup_app, name="backup")
app.add_typer(export_app, name="export")
app.add_typer(rollback_app, name="rollback")

log = logging.getLogger("arc_exporter.cli")


def _configure(verbose: int) -> Config:
    setup_logging(verbose)
    try:
        return Config.load()
    except ArcExporterError as e:
        console(stderr=True).print(f"[bold red]Config error:[/] {e}")
        raise typer.Exit(code=e.exit_code) from e


def _handle(fn):
    try:
        return fn()
    except ArcExporterError as e:
        console(stderr=True).print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=e.exit_code) from e


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Print version and exit", is_eager=True),
) -> None:
    if version:
        console().print(__version__)
        raise typer.Exit(code=0)
    if ctx.invoked_subcommand is None:
        # Show help when invoked bare.
        console().print(ctx.get_help())
        raise typer.Exit(code=0)


@app.command()
def doctor(
    verbose: int = typer.Option(0, "-v", "--verbose", count=True),
    check_targets: bool = typer.Option(
        False,
        "--check-targets",
        help="Also probe Safe Storage keychain entries for every installed Chromium target "
        "(may prompt for keychain permission on macOS)",
    ),
) -> None:
    """Run environment self-check."""
    _configure(verbose)
    results = run_doctor(check_targets=check_targets)
    table = Table(title="arc-exporter doctor")
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")
    for r in results:
        table.add_row(r.name, "[green]OK[/]" if r.ok else "[red]FAIL[/]", r.detail)
    console().print(table)
    raise typer.Exit(code=doctor_exit_code(results))


@app.command(name="list")
def list_profiles(
    verbose: int = typer.Option(0, "-v", "--verbose", count=True),
    arc_root: Path | None = typer.Option(None, "--arc-root", help="Override Arc root path (for testing)"),
) -> None:
    """List Arc profiles and their spaces."""
    _configure(verbose)

    def _do() -> None:
        src = get_source(arc_root)
        profiles = src.profiles()
        table = Table(title="Arc profiles")
        table.add_column("Directory")
        table.add_column("Display name")
        table.add_column("Path", overflow="fold")
        for p in profiles:
            table.add_row(p.directory_name, p.display_name, str(p.path))
        console().print(table)

    _handle(_do)


@app.command()
def targets(
    verbose: int = typer.Option(0, "-v", "--verbose", count=True),
    check_keys: bool = typer.Option(
        False,
        "--check-keys",
        help="Also probe each Chromium target's Safe Storage keychain entry "
        "(triggers a permission prompt per target on macOS)",
    ),
) -> None:
    """List browser targets known to arc-exporter (installed + uninstalled).

    The Safe Storage key column is hidden by default because querying the macOS
    Keychain triggers a permission prompt for each entry. Pass ``--check-keys``
    to opt in.
    """
    _configure(verbose)
    from arc_exporter.targets.chromium import ChromiumTarget

    avail = available_targets()
    table = Table(title="Targets")
    table.add_column("Name", style="bold")
    table.add_column("Family")
    table.add_column("Installed")
    if check_keys:
        table.add_column("Safe Storage key")
    table.add_column("Path", overflow="fold")
    for name, t in sorted(all_targets().items()):
        installed = name in avail
        row: list[str] = [name, t.family, "[green]Yes[/]" if installed else "[dim]No[/]"]
        if check_keys:
            from arc_exporter.secrets import first_available_secret

            if isinstance(t, ChromiumTarget) and installed:
                key_status = (
                    "[green]found[/]" if first_available_secret(t.keychain_services()) else "[red]missing[/]"
                )
            elif isinstance(t, ChromiumTarget):
                key_status = "[dim]—[/]"
            else:
                key_status = "[dim]n/a[/]"
            row.append(key_status)
        row.append(str(t.user_data_dir))
        table.add_row(*row)
    console().print(table)


@export_app.command("all")
def export_all(
    verbose: int = typer.Option(0, "-v", "--verbose", count=True),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only; do not write any files"),
    arc_root: Path | None = typer.Option(None, "--arc-root"),
    output: Path | None = typer.Option(None, "--output"),
    cookies: bool = typer.Option(False, "--cookies", help="Include cookies (decrypted!)"),
    history: bool = typer.Option(False, "--history", help="Include browsing history"),
    tabs: bool = typer.Option(False, "--tabs", help="Include today's open tabs"),
    easels: bool = typer.Option(False, "--easels", help="Include Easels & Notes (Markdown)"),
    amo: bool = typer.Option(False, "--amo-mapping", help="Fetch Chrome->AMO extension mapping"),
    force: bool = typer.Option(False, "--force", help="Bypass running-browser guard"),
    auto_quit: bool = typer.Option(
        False, "--auto-quit", help="Try to gracefully quit running browsers before proceeding"
    ),
) -> None:
    """Export every portable artefact (bookmarks, passwords, cards, extensions; optional cookies/history/tabs)."""
    _configure(verbose)
    _run_export(
        ExportOptions(
            bookmarks=True,
            passwords=True,
            cards=True,
            cookies=cookies,
            history=history,
            tabs=tabs,
            extensions=True,
            easels=easels,
            amo_mapping=amo,
            dry_run=dry_run,
            arc_root=arc_root,
            output_root=output,
        ),
        force=force,
        auto_quit=auto_quit,
    )


def _make_export_subcommand(kind: str, attr: str) -> None:
    @export_app.command(kind)
    def _cmd(
        verbose: int = typer.Option(0, "-v", "--verbose", count=True),
        dry_run: bool = typer.Option(False, "--dry-run"),
        arc_root: Path | None = typer.Option(None, "--arc-root"),
        output: Path | None = typer.Option(None, "--output"),
        force: bool = typer.Option(False, "--force"),
        auto_quit: bool = typer.Option(False, "--auto-quit"),
    ) -> None:
        """Export a single artefact kind."""
        _configure(verbose)
        opts = ExportOptions(
            bookmarks=False,
            passwords=False,
            cards=False,
            cookies=False,
            history=False,
            tabs=False,
            extensions=False,
            easels=False,
            dry_run=dry_run,
            arc_root=arc_root,
            output_root=output,
        )
        setattr(opts, attr, True)
        _run_export(opts, force=force, auto_quit=auto_quit)

    _cmd.__name__ = f"export_{kind}"


for _kind, _attr in (
    ("bookmarks", "bookmarks"),
    ("passwords", "passwords"),
    ("cards", "cards"),
    ("cookies", "cookies"),
    ("history", "history"),
    ("tabs", "tabs"),
    ("extensions", "extensions"),
    ("easels", "easels"),
):
    _make_export_subcommand(_kind, _attr)


def _run_export(options: ExportOptions, *, force: bool, auto_quit: bool = False) -> None:
    def _do() -> None:
        ensure_browsers_quit(("arc",), force=force, auto_quit=auto_quit)
        orch = Orchestrator(options)
        result = orch.run()
        _render_summary(result)

    _handle(_do)


def _render_summary(result) -> None:
    table = Table(title=f"Export run {result.timestamp}")
    table.add_column("Profile", style="bold")
    table.add_column("Bookmarks", justify="right")
    table.add_column("Passwords", justify="right")
    table.add_column("Cards", justify="right")
    table.add_column("Cookies", justify="right")
    table.add_column("History", justify="right")
    table.add_column("Tabs", justify="right")
    table.add_column("Exts", justify="right")
    table.add_column("Easels", justify="right")
    for pe in result.profiles:
        c = pe.counts
        table.add_row(
            pe.profile.display_name,
            str(c.get("bookmarks", "-")),
            str(c.get("passwords", "-")),
            str(c.get("cards", "-")),
            str(c.get("cookies", "-")),
            str(c.get("history", "-")),
            str(c.get("tabs", "-")),
            str(c.get("extensions", "-")),
            str(c.get("easels", "-")),
        )
    console().print(table)
    console().print(f"\n[bold]Output:[/] {result.run_dir}\n")


def _render_next_steps(
    target_name: str,
    is_chromium: bool,
    profile_names: list[str] | None = None,
) -> None:
    """Print the closing Next-Steps panel.

    ``profile_names`` is the list of Arc profile display names that were just
    migrated; we surface them verbatim so users see exactly which entries to look
    for in the target browser's profile picker. The names are user data, never
    hardcoded.
    """
    from rich.panel import Panel

    pretty = target_name.title()
    if is_chromium:
        if profile_names:
            quoted = ", ".join(f"[bold]{n}[/]" for n in profile_names)
            picker_line = f"   appear under their Arc names: {quoted}."
        else:
            picker_line = "   appear under their original Arc display names."
        body = (
            f"1. Launch [bold]{pretty}[/].\n"
            f"2. Click your avatar to open the profile picker. Your migrated profiles\n"
            f"{picker_line}\n"
            f"3. Sign in to {pretty} Sync to fan bookmarks and passwords out to your\n"
            f"   other devices.\n\n"
            f"[dim]Undo:[/]  arc-exporter rollback ls --to={target_name}\n"
            f"[dim]Undo:[/]  arc-exporter rollback rm --to={target_name} --all"
        )
    else:
        body = (
            f"Open [bold]{pretty}[/] and use its built-in importer to load the artefact files\n"
            f"placed under [cyan]Profile N/imports/[/] inside the target's user-data dir."
        )
    console().print(
        Panel(body, title="[bold]Next steps[/]", title_align="left", border_style="green", padding=(0, 1))
    )


@app.command()
def migrate(
    to: str = typer.Option(..., "--to", help="Target browser (run `arc-exporter targets` for the list)"),
    verbose: int = typer.Option(0, "-v", "--verbose", count=True),
    dry_run: bool = typer.Option(False, "--dry-run"),
    arc_root: Path | None = typer.Option(None, "--arc-root"),
    output: Path | None = typer.Option(None, "--output"),
    cookies: bool = typer.Option(False, "--cookies"),
    history: bool = typer.Option(False, "--history"),
    tabs: bool = typer.Option(False, "--tabs"),
    easels: bool = typer.Option(False, "--easels"),
    force: bool = typer.Option(False, "--force"),
    only: str | None = typer.Option(None, "--only", help="Comma-separated artefact kinds"),
    keep_cache_dirs: bool = typer.Option(
        False,
        "--keep-cache-dirs",
        help="Copy Chromium Cache/GPUCache/Code Cache subdirs too (skipped by default to save space)",
    ),
    strip_storage: bool = typer.Option(
        False,
        "--strip-storage",
        help="Drop IndexedDB / Local Storage / Session Storage / File System on copy (will sign you out of most web apps)",
    ),
    auto_quit: bool = typer.Option(
        False,
        "--auto-quit",
        help="Gracefully quit Arc and the target browser via osascript / SIGTERM before proceeding",
    ),
) -> None:
    """Export Arc data and import it into ``--to=<target>``."""
    _configure(verbose)

    def _do() -> None:
        target = target_by_name(to)
        ensure_browsers_quit(("arc", target.name), force=force, auto_quit=auto_quit)
        opts = ExportOptions(
            bookmarks=True,
            passwords=True,
            cards=True,
            cookies=cookies,
            history=history,
            tabs=tabs,
            extensions=True,
            easels=easels,
            dry_run=dry_run,
            arc_root=arc_root,
            output_root=output,
        )
        orch = Orchestrator(opts)
        result = orch.run()
        _render_summary(result)
        # Hand off to the target.
        # For Chromium-family targets we attempt a *full* migration (copy profile
        # tree + re-encrypt credentials). For Firefox/Safari/Orion targets we stash
        # the portable artefact files so the user can click "Import" inside that
        # browser.
        wanted_kinds = set((only or "bookmarks,passwords,cards,cookies,extensions").split(","))
        from arc_exporter.crypto import derive_v10_key
        from arc_exporter.secrets import first_available_secret
        from arc_exporter.targets.chromium import ChromiumTarget

        arc_src = get_source(arc_root)
        sidebar_path = arc_src.config.sidebar_path

        is_chromium = isinstance(target, ChromiumTarget)
        target_key: bytes | None = None
        arc_key: bytes | None = None
        if is_chromium and not dry_run:
            target_secret = first_available_secret(target.keychain_services())
            if target_secret:
                try:
                    target_key = derive_v10_key(target_secret)
                except Exception as e:
                    console(stderr=True).print(f"[yellow]Warning:[/] target key derivation failed: {e}")
            else:
                console(stderr=True).print(
                    f"[yellow]Warning:[/] could not fetch Safe Storage key for {target.name}; "
                    "credentials will not be merged. Launch the target browser once so it creates "
                    "its keychain entry, then re-run."
                )
            arc_secret = first_available_secret(("Arc Safe Storage",))
            if arc_secret:
                try:
                    arc_key = derive_v10_key(arc_secret)
                except Exception:
                    arc_key = None

        migrated_display_names: list[str] = []
        for pe in result.profiles:
            # The target's profile picker entry uses the Arc profile's display name
            # verbatim; the directory is still allocated as the next free `Profile N`.
            tp = target.create_profile(pe.profile.display_name, dry_run=dry_run)
            migrated_display_names.append(pe.profile.display_name)
            request = MigrationRequest(
                artefact_paths={
                    k: v for k, v in pe.artefacts.items() if k in wanted_kinds and k in target.supports
                },
                source_profile=pe.profile if is_chromium else None,
                arc_sidebar_path=sidebar_path if is_chromium else None,
                arc_aes_key=arc_key,
                target_aes_key=target_key,
                keep_cache_dirs=keep_cache_dirs,
                strip_storage=strip_storage,
                dry_run=dry_run,
            )
            report = target.migrate_profile(tp, request)
            console().print(
                f"[bold]{target.name}[/] [dim]{report.profile}[/] -> "
                f"ok={report.succeeded} skipped={list(report.skipped.keys())} "
                f"errors={list(report.errors.keys())}"
            )
            for kind, note in report.notes.items():
                console().print(f"  [yellow]note[/] [bold]{kind}:[/] {note}")

        if not dry_run:
            _render_next_steps(target.name, is_chromium, migrated_display_names)

    _handle(_do)


@backup_app.command("ls")
def backup_ls(
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """List backups created during prior runs (both export-side and target-side)."""
    from arc_exporter.guards.backups import BackupManager
    from arc_exporter.orchestrator import _default_output_root
    from arc_exporter.targets.registry import all_targets

    roots: list[Path] = []
    if output:
        roots.append(output)
    else:
        roots.append(_default_output_root())
        roots.append(Path.cwd() / "arc-export")
        # Target-side: chromium targets store backups inside their user-data dir.
        for tgt in all_targets().values():
            tgt_root = getattr(tgt, "root_dir", None)
            if isinstance(tgt_root, Path):
                roots.append(tgt_root / ".arc-exporter-backups")

    table = Table(title="Backups")
    table.add_column("ID", style="bold")
    table.add_column("Timestamp")
    table.add_column("Original", overflow="fold")
    table.add_column("Backup", overflow="fold")
    table.add_column("Note", overflow="fold")
    total = 0
    seen: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        mgr = BackupManager(root)
        for e in mgr.list_entries():
            if e.backup_id in seen:
                continue
            seen.add(e.backup_id)
            table.add_row(e.backup_id, e.timestamp, e.original, e.backup, e.description)
            total += 1
    console().print(table)
    if total == 0:
        console().print("[dim]No backups found.[/]")


@backup_app.command("restore")
def backup_restore(
    backup_id: str = typer.Argument(...),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Restore the file referenced by ``backup_id`` to its original path."""
    from arc_exporter.guards.backups import BackupManager
    from arc_exporter.orchestrator import _default_output_root
    from arc_exporter.targets.registry import all_targets

    roots: list[Path] = []
    if output:
        roots.append(output)
    else:
        roots.extend([_default_output_root(), Path.cwd() / "arc-export"])
        for tgt in all_targets().values():
            tgt_root = getattr(tgt, "root_dir", None)
            if isinstance(tgt_root, Path):
                roots.append(tgt_root / ".arc-exporter-backups")

    last_err: Exception | None = None
    for root in roots:
        if not root.exists():
            continue
        mgr = BackupManager(root)
        try:
            entry = mgr.restore(backup_id)
        except FileNotFoundError as e:
            last_err = e
            continue
        console().print(f"Restored {entry.original} from {entry.backup}")
        return
    if last_err:
        console(stderr=True).print(f"[red]{last_err}[/]")
        raise typer.Exit(code=1) from last_err
    console(stderr=True).print(f"[red]backup_id {backup_id!r} not found[/]")
    raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the installed version."""
    console().print(__version__)


@dataclass
class _RollbackEntry:
    target: str
    profile_dir: str
    display_name: str
    path: Path
    created_at: str


def _rollback_candidates(target_name: str | None) -> list[tuple[str, _RollbackEntry]]:
    """Find target profile dirs that arc-exporter created, identified by the marker file."""
    import json as _json

    if target_name:
        candidates = [target_by_name(target_name)]
    else:
        candidates = [t for t in all_targets().values() if t.family == "chromium"]
    out: list[tuple[str, _RollbackEntry]] = []
    for tgt in candidates:
        root = getattr(tgt, "root_dir", None)
        if not isinstance(root, Path) or not root.exists():
            continue
        for d in sorted(root.iterdir()):
            marker = d / ".arc-exporter.json"
            if not (d.is_dir() and marker.exists()):
                continue
            try:
                meta = _json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, _json.JSONDecodeError):
                meta = {}
            entry = _RollbackEntry(
                target=tgt.name,
                profile_dir=d.name,
                display_name=meta.get("display_name", d.name),
                path=d,
                created_at=meta.get("created_at", ""),
            )
            out.append((tgt.name, entry))
    return out


@rollback_app.command("ls")
def rollback_ls(
    target: str | None = typer.Option(None, "--to", help="Filter to a single target browser"),
) -> None:
    """List profiles created by arc-exporter (identified by the `.arc-exporter.json` marker)."""
    entries = _rollback_candidates(target)
    table = Table(title="arc-exporter created profiles")
    table.add_column("Target", style="bold")
    table.add_column("Profile dir")
    table.add_column("Display name")
    table.add_column("Created")
    table.add_column("Path", overflow="fold")
    for _, e in entries:
        table.add_row(e.target, e.profile_dir, e.display_name, e.created_at, str(e.path))
    console().print(table)
    if not entries:
        console().print("[dim]No matching profiles.[/]")


@rollback_app.command("rm")
def rollback_rm(
    target: str = typer.Option(..., "--to", help="Target browser"),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Profile directory name to remove (e.g. 'Profile 1'). Omit with --all to remove all.",
    ),
    all_profiles: bool = typer.Option(
        False, "--all", help="Remove every arc-exporter-created profile for the target"
    ),
    yes: bool = typer.Option(False, "-y", "--yes", help="Skip confirmation prompt"),
) -> None:
    """Delete profiles previously created by arc-exporter and unregister them from the target's `Local State`."""
    import json
    import shutil as _shutil

    if not profile and not all_profiles:
        console(stderr=True).print("[red]Specify --profile or --all[/]")
        raise typer.Exit(code=2)
    entries = [e for _, e in _rollback_candidates(target)]
    if profile:
        entries = [e for e in entries if e.profile_dir == profile]
    if not entries:
        console().print("[yellow]Nothing to remove.[/]")
        raise typer.Exit(code=0)

    table = Table(title="About to remove")
    table.add_column("Target", style="bold")
    table.add_column("Profile dir")
    table.add_column("Display name")
    table.add_column("Path", overflow="fold")
    for e in entries:
        table.add_row(e.target, e.profile_dir, e.display_name, str(e.path))
    console().print(table)

    if not yes and not typer.confirm("Proceed?"):
        raise typer.Exit(code=1)

    tgt = target_by_name(target)
    root = getattr(tgt, "root_dir", None)
    if not isinstance(root, Path):
        console(stderr=True).print(f"[red]Rollback not supported for target {target!r}[/]")
        raise typer.Exit(code=2)
    local_state_path = root / "Local State"
    state: dict = {}
    if local_state_path.exists():
        try:
            state = json.loads(local_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}

    for e in entries:
        if e.path.exists():
            _shutil.rmtree(e.path)
        info_cache = state.get("profile", {}).get("info_cache", {})
        info_cache.pop(e.profile_dir, None)
        console().print(f"[green]Removed[/] {e.target} / {e.profile_dir}")

    if state:
        local_state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    app()
