"""Click CLI entry point for firewalld-manager."""

from __future__ import annotations

import sys
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from firewalld_manager.firewall import FirewallManager, PROTECTED_SERVICES
from firewalld_manager.risk import get_risk, get_risk_for_service, score_bar, score_color

console = Console()


def _get_fw(zone: Optional[str] = None) -> FirewallManager:
    fw = FirewallManager()
    if zone:
        fw.set_active_zone(zone)
    return fw


@click.group(invoke_without_command=True)
@click.option("--zone", "-z", default=None, help="Firewall zone to use (default: active zone)")
@click.pass_context
def main(ctx: click.Context, zone: Optional[str]) -> None:
    """Interactive TUI and CLI for managing firewalld.

    Run without arguments to start the interactive TUI.
    """
    ctx.ensure_object(dict)
    ctx.obj["zone"] = zone

    if ctx.invoked_subcommand is None:
        # No subcommand → start TUI
        try:
            from firewalld_manager.tui.app import FirewallTUI
            tui = FirewallTUI(zone=zone)
            tui.run()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            console.print(f"[bold red]Error starting TUI:[/bold red] {e}")
            raise SystemExit(1)


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show current firewall status in a table."""
    zone = ctx.obj.get("zone")
    fw = _get_fw(zone)
    z = fw.get_active_zone()

    try:
        zs = fw.get_zone_status(z)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise SystemExit(1)

    active_zones = fw.get_active_zones()
    is_active = z in active_zones
    active_label = "[bold green]ACTIVE[/bold green]" if is_active else "[dim]INACTIVE[/dim]"
    default_label = " [dim](default)[/dim]" if zs.is_default else ""

    # Header panel
    header_lines = [
        f"[bold cyan]Zone:[/bold cyan] {z}{default_label}  {active_label}",
        f"[bold cyan]Target:[/bold cyan] {zs.target}",
        f"[bold cyan]Interfaces:[/bold cyan] {', '.join(zs.interfaces) or 'none'}",
    ]
    console.print(Panel("\n".join(header_lines), title="firewalld Status", border_style="cyan"))

    # Services table
    if zs.services:
        svc_table = Table(
            title="Open Services",
            box=box.ROUNDED,
            border_style="green",
            show_header=True,
            header_style="bold green",
        )
        svc_table.add_column("Service")
        svc_table.add_column("Ports")
        svc_table.add_column("Risk Score")
        svc_table.add_column("Risk Summary")
        svc_table.add_column("Note")

        for svc_name in sorted(zs.services):
            try:
                si = fw._client.getServiceSettings(svc_name)
                port_tuples = list(si.getPorts())
                ports_str = ", ".join(f"{p}/{pr}" for p, pr in port_tuples) or "-"
            except Exception:
                port_tuples = []
                ports_str = "-"

            risk = get_risk_for_service(svc_name, port_tuples)
            bar = score_bar(risk.score, width=8)
            color = score_color(risk.score)
            risk_cell = f"[{color}]{bar} {risk.score}[/{color}]"
            summary_cell = f"[{color}]{risk.summary[:45]}{'…' if len(risk.summary) > 45 else ''}[/{color}]"
            note = "[bold yellow]⚠ PROTECTED[/bold yellow]" if svc_name in PROTECTED_SERVICES else ""
            svc_table.add_row(svc_name, ports_str, risk_cell, summary_cell, note)

        console.print(svc_table)
    else:
        console.print("[dim]No open services.[/dim]")

    # Raw ports table
    if zs.ports:
        port_table = Table(
            title="Open Raw Ports",
            box=box.ROUNDED,
            border_style="yellow",
            show_header=True,
            header_style="bold yellow",
        )
        port_table.add_column("Port")
        port_table.add_column("Protocol")
        port_table.add_column("Risk Score")
        port_table.add_column("Risk Summary")

        for port, proto in sorted(zs.ports):
            risk = get_risk(port, proto)
            bar = score_bar(risk.score, width=8)
            color = score_color(risk.score)
            risk_cell = f"[{color}]{bar} {risk.score}[/{color}]"
            summary_cell = f"[{color}]{risk.summary[:45]}{'…' if len(risk.summary) > 45 else ''}[/{color}]"
            port_table.add_row(port, proto, risk_cell, summary_cell)

        console.print(port_table)

    # Rich rules
    if zs.rich_rules:
        console.print("\n[bold]Rich Rules:[/bold]")
        for rule in zs.rich_rules:
            console.print(f"  [dim]{rule}[/dim]")


@main.command(name="list")
@click.pass_context
def list_cmd(ctx: click.Context) -> None:
    """List all open ports and services."""
    zone = ctx.obj.get("zone")
    fw = _get_fw(zone)
    z = fw.get_active_zone()

    try:
        zs = fw.get_zone_status(z)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise SystemExit(1)

    console.print(f"[bold]Zone:[/bold] {z}")

    if zs.services:
        console.print(f"\n[green]Open services:[/green] {', '.join(sorted(zs.services))}")
    else:
        console.print("\n[dim]No open services.[/dim]")

    if zs.ports:
        port_strs = [f"{p}/{pr}" for p, pr in sorted(zs.ports)]
        console.print(f"\n[yellow]Open raw ports:[/yellow] {', '.join(port_strs)}")

    if zs.rich_rules:
        console.print(f"\n[dim]Rich rules: {len(zs.rich_rules)}[/dim]")


@main.command()
@click.argument("target")
@click.option("--runtime-only", is_flag=True, default=False, help="Apply runtime only (not permanent)")
@click.option("--zone", "-z", default=None, help="Override zone")
@click.pass_context
def open(ctx: click.Context, target: str, runtime_only: bool, zone: Optional[str]) -> None:
    """Open a port or service.

    TARGET can be a service name (e.g. 'https') or port/proto (e.g. '8080/tcp').
    """
    zone = zone or ctx.obj.get("zone")
    fw = _get_fw(zone)
    permanent = not runtime_only

    z = fw.get_active_zone()

    # Determine if it's a port/proto or service name
    if "/" in target and target.split("/")[0].isdigit():
        port, proto = fw.parse_port_spec(target)
        if fw.is_protected(port=port, proto=proto):
            console.print(f"[bold yellow]⚠ Warning:[/bold yellow] {port}/{proto} is a protected port.")
        try:
            fw.open_port(port, proto, permanent=permanent, runtime=True)
            mode = "runtime only" if runtime_only else "permanent + runtime"
            console.print(f"[green]✓[/green] Opened port {port}/{proto} on zone '{z}' ({mode})")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise SystemExit(1)
    else:
        # Treat as service name
        svc_name = target
        if fw.is_protected(service=svc_name):
            console.print(f"[bold yellow]⚠ Warning:[/bold yellow] {svc_name} is a protected service.")
        try:
            fw.open_service(svc_name, permanent=permanent, runtime=True)
            mode = "runtime only" if runtime_only else "permanent + runtime"
            console.print(f"[green]✓[/green] Opened service '{svc_name}' on zone '{z}' ({mode})")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise SystemExit(1)


@main.command()
@click.argument("target")
@click.option("--zone", "-z", default=None, help="Override zone")
@click.pass_context
def close(ctx: click.Context, target: str, zone: Optional[str]) -> None:
    """Close a port or service.

    TARGET can be a service name (e.g. 'https') or port/proto (e.g. '8080/tcp').
    """
    zone = zone or ctx.obj.get("zone")
    fw = _get_fw(zone)
    z = fw.get_active_zone()

    if "/" in target and target.split("/")[0].isdigit():
        port, proto = fw.parse_port_spec(target)
        if fw.is_protected(port=port, proto=proto):
            console.print(
                f"[bold yellow]⚠ WARNING:[/bold yellow] {port}/{proto} is protected (SSH/HTTPS)."
            )
            if not click.confirm("Close anyway?", default=False):
                console.print("Aborted.")
                return
        try:
            fw.close_port(port, proto, permanent=True, runtime=True)
            console.print(f"[green]✓[/green] Closed port {port}/{proto} on zone '{z}'")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise SystemExit(1)
    else:
        svc_name = target
        if fw.is_protected(service=svc_name):
            console.print(
                f"[bold yellow]⚠ WARNING:[/bold yellow] {svc_name} is protected (SSH/HTTPS). "
                "Closing this may lock you out!"
            )
            if not click.confirm("Close anyway?", default=False):
                console.print("Aborted.")
                return
        try:
            fw.close_service(svc_name, permanent=True, runtime=True)
            console.print(f"[green]✓[/green] Closed service '{svc_name}' on zone '{z}'")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise SystemExit(1)


@main.command()
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt")
@click.option("--dry-run", is_flag=True, default=False, help="Show what would be removed, don't apply")
@click.option("--keep", default=None, help="Comma-separated services to keep (default: ssh,https)")
@click.option("--zone", "-z", default=None, help="Override zone")
@click.pass_context
def lockdown(
    ctx: click.Context,
    yes: bool,
    dry_run: bool,
    keep: Optional[str],
    zone: Optional[str],
) -> None:
    """Lock down firewall: remove all except ssh and https."""
    zone = zone or ctx.obj.get("zone")
    fw = _get_fw(zone)
    z = fw.get_active_zone()

    keep_list = [s.strip() for s in keep.split(",")] if keep else list(PROTECTED_SERVICES)

    # Preview what will be removed
    preview = fw.lockdown(zone=z, keep=keep_list, dry_run=True)
    services_to_remove = preview["services"]
    ports_to_remove = preview["ports"]

    if not services_to_remove and not ports_to_remove:
        console.print(f"[green]✓[/green] Zone '{z}' is already in lockdown state. Nothing to do.")
        return

    # Show preview
    console.print(Panel(
        f"[bold]Zone:[/bold] {z}\n"
        f"[bold red]Services to remove:[/bold red] {', '.join(services_to_remove) or 'none'}\n"
        f"[bold red]Ports to remove:[/bold red] {', '.join(f'{p}/{pr}' for p, pr in ports_to_remove) or 'none'}\n"
        f"[bold green]Keeping:[/bold green] {', '.join(keep_list)}",
        title="Lockdown Preview",
        border_style="red",
    ))

    if dry_run:
        console.print("[dim]Dry-run mode: no changes applied.[/dim]")
        return

    if not yes:
        if not click.confirm(
            f"Apply lockdown to zone '{z}'?",
            default=False,
        ):
            console.print("Aborted.")
            return

    try:
        fw.lockdown(zone=z, keep=keep_list, permanent=True, runtime=True)
        console.print(f"[bold red]🔒[/bold red] Lockdown applied to zone '{z}'")
        console.print(
            f"[green]Kept:[/green] {', '.join(keep_list)}"
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise SystemExit(1)


@main.command()
@click.argument("target")
def risk(target: str) -> None:
    """Show detailed risk assessment for a port or service.

    TARGET can be a service name (e.g. 'ssh', 'telnet') or port/proto (e.g. '22/tcp', '3389/tcp').
    """
    import textwrap

    # Determine if it's a port/proto or service name
    if "/" in target and target.split("/")[0].isdigit():
        if "/" in target:
            port, proto = target.split("/", 1)
        else:
            port, proto = target, "tcp"
        assessment = get_risk(port, proto)
        title = f"{port}/{proto}"
    else:
        # Try to get ports from firewalld service definition
        try:
            fw = FirewallManager()
            si = fw._client.getServiceSettings(target)
            port_tuples = list(si.getPorts())
        except Exception:
            port_tuples = []
        assessment = get_risk_for_service(target, port_tuples)
        ports_str = ", ".join(f"{p}/{pr}" for p, pr in port_tuples) or "no ports defined"
        title = f"{target} ({ports_str})"

    color = score_color(assessment.score)
    bar = score_bar(assessment.score, width=30)

    console.print()
    console.print(Panel(
        f"[bold]Target:[/bold] {title}\n"
        f"[bold]Score:[/bold]  [{color}]{bar} {assessment.score}/100[/{color}]  "
        f"[{color}][bold]{assessment.label}[/bold][/{color}]\n"
        f"[bold]Summary:[/bold] [{color}]{assessment.summary}[/{color}]",
        title=" Risk Assessment ",
        border_style=color if color not in ("bold red", "bold green") else color.split()[1],
    ))

    console.print()
    console.print("[bold]Explanation:[/bold]")
    for para in assessment.explanation.split("\n"):
        if para.strip():
            wrapped = textwrap.fill(para, width=80, initial_indent="  ", subsequent_indent="  ")
            console.print(wrapped)
        else:
            console.print()

    if assessment.cves:
        console.print()
        console.print(f"[bold]Notable CVEs:[/bold] [dim]{', '.join(assessment.cves)}[/dim]")
