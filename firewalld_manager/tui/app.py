"""Main TUI Application for firewalld-manager."""

from __future__ import annotations

import sys
from typing import Optional

from prompt_toolkit import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.formatted_text import HTML, StyleAndTextTuples
from prompt_toolkit.key_binding import KeyBindings, merge_key_bindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import (
    Float,
    FloatContainer,
    HSplit,
    VSplit,
    Window,
)
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension as D
from prompt_toolkit.styles import Style

from firewalld_manager.firewall import FirewallManager, ServiceInfo, PROTECTED_SERVICES
from firewalld_manager.risk import get_risk_for_service, score_bar
from firewalld_manager.tui.port_list import PortListControl
from firewalld_manager.tui.dialogs import (
    action_menu,
    confirm_dialog,
    lockdown_dialog,
    rich_rule_dialog,
    zone_picker_dialog,
)


APP_STYLE = Style.from_dict(
    {
        # Layout chrome
        "header-zone": "bg:#89b4fa #1e1e2e bold",
        "header-status": "bg:#a6e3a1 #1e1e2e bold",
        "header-inactive": "bg:#6c7086 #1e1e2e",
        "statusbar": "bg:#313244 #cdd6f4",
        "statusbar-key": "bg:#89b4fa #1e1e2e bold",
        "statusbar-sep": "bg:#313244 #585b70",
        "search-bar": "bg:#1e1e2e #cdd6f4",
        "search-label": "bg:#1e1e2e #89b4fa bold",
        "search-active": "bg:#45475a #cdd6f4",
        # Table
        "header": "bg:#313244 #89b4fa bold",
        "selected": "bg:#89b4fa #1e1e2e",
        "selected-open": "bg:#89b4fa #1e1e2e bold",
        "selected-closed": "bg:#89b4fa #1e1e2e",
        "selected-protected": "bg:#f9e2af #1e1e2e bold",
        "row-open": "#a6e3a1",
        "row-closed": "#585b70",
        "row-protected": "#f9e2af",
        "status-open": "#a6e3a1 bold",
        "status-closed": "#585b70",
        "status-protected": "#f9e2af bold",
        "scroll-info": "#585b70 italic",
        "empty": "#585b70 italic",
        # Risk score colors
        "risk-critical": "#f38ba8 bold",   # red
        "risk-high": "#fab387 bold",        # orange
        "risk-medium": "#f9e2af",           # yellow
        "risk-low": "#89dceb",              # cyan
        "risk-minimal": "#a6e3a1",          # green
        "risk-selected": "bg:#89b4fa #1e1e2e bold",
        # Dialog
        "dialog": "bg:#1e1e2e #cdd6f4",
        "frame.border": "bg:#1e1e2e #89b4fa",
        "frame.label": "bg:#89b4fa #1e1e2e bold",
    }
)


class FirewallTUI:
    """The main TUI application."""

    def __init__(self, zone: Optional[str] = None) -> None:
        self.fw = FirewallManager()
        if zone:
            self.fw.set_active_zone(zone)

        self._port_list = PortListControl()
        self._status_msg: str = "Ready. Loading services…"
        self._search_mode: bool = False
        self._search_text: str = ""
        self._loading: bool = False
        self._error_msg: Optional[str] = None

        # Buffers
        self._search_buffer = Buffer(name="search")

        self._app: Optional[Application] = None

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _reload_services(self) -> None:
        self._loading = True
        self._status_msg = "Loading…"
        try:
            self.fw.invalidate_cache()
            services = self.fw.get_all_services()
            self._port_list.load(services)
            zone = self.fw.get_active_zone()
            open_count = len([s for s in services if s.is_open])
            self._status_msg = (
                f"Zone: {zone}  |  {open_count} open services  |  "
                f"{len(services)} total services"
            )
            self._error_msg = None
        except Exception as e:
            self._error_msg = str(e)
            self._status_msg = f"Error: {e}"
        finally:
            self._loading = False

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def _get_header_text(self) -> StyleAndTextTuples:
        try:
            status = self.fw.get_zone_status()
            zone = status.name
            interfaces = ", ".join(status.interfaces) or "none"
            target = status.target
            active_zones = self.fw.get_active_zones()
            is_active = zone in active_zones
            active_label = "ACTIVE" if is_active else "INACTIVE"
            active_style = "class:header-status" if is_active else "class:header-inactive"
        except Exception as e:
            return [("class:header", f"  firewalld-manager  [Error: {e}]\n")]

        result: StyleAndTextTuples = [
            ("class:header", "  firewalld-manager  │  "),
            ("class:header-zone", f"Zone: {zone}"),
            ("class:header", "  │  "),
            (active_style, active_label),
            ("class:header", f"  │  Target: {target}  │  Interface: {interfaces}  \n"),
        ]
        return result

    def _get_search_text(self) -> StyleAndTextTuples:
        if self._search_mode:
            label = "  Suche: "
            text = self._search_text or ""
            cursor = "█"
            return [
                ("class:search-label", label),
                ("class:search-active", text + cursor + "  "),
                ("", "\n"),
            ]
        else:
            return [
                ("class:search-bar",
                 "  Type to search  │  /: activate search  │  Esc: clear  \n"),
            ]

    def _get_list_text(self) -> StyleAndTextTuples:
        return self._port_list.render(available_rows=22)

    def _get_statusbar_text(self) -> StyleAndTextTuples:
        if self._error_msg:
            return [("bg:#f38ba8 #1e1e2e bold", f"  ERROR: {self._error_msg}  ")]

        keys = [
            ("[↑↓]", "Navigate"),
            ("[Enter]", "Action"),
            ("[O]", "Open"),
            ("[C]", "Close"),
            ("[L]", "Lockdown"),
            ("[Z]", "Zone"),
            ("[R]", "Refresh"),
            ("[Q]", "Quit"),
        ]
        result: StyleAndTextTuples = [("class:statusbar", "  ")]
        for key, desc in keys:
            result.append(("class:statusbar-key", key))
            result.append(("class:statusbar", f" {desc}  "))
        result.append(("class:statusbar-sep", f"│  {self._status_msg}  "))
        return result

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _action_open(self, svc: ServiceInfo, runtime_only: bool = False) -> None:
        if self.fw.is_protected(service=svc.name):
            self._status_msg = f"  {svc.name} is always protected – already open"
            return
        try:
            permanent = not runtime_only
            self.fw.open_service(svc.name, permanent=permanent, runtime=True)
            mode = "runtime only" if runtime_only else "permanent"
            self._status_msg = f"Opened {svc.name} ({mode})"
            self._reload_services()
        except Exception as e:
            self._error_msg = str(e)

    async def _action_close(self, svc: ServiceInfo) -> None:
        if self.fw.is_protected(service=svc.name):
            confirmed = await confirm_dialog(
                title=f" WARNING: Close {svc.name}? ",
                message=(
                    f"<ansired><b>{svc.name}</b> is a protected service (SSH/HTTPS).</ansired>\n\n"
                    "Closing it may lock you out!\n\nAre you sure?"
                ),
                yes_text="Close anyway",
                no_text="Cancel",
            )
            if not confirmed:
                return
        try:
            self.fw.close_service(svc.name, permanent=True, runtime=True)
            self._status_msg = f"Closed {svc.name}"
            self._reload_services()
        except Exception as e:
            self._error_msg = str(e)

    async def _action_open_for_source(self, svc: ServiceInfo) -> None:
        if not svc.ports:
            self._status_msg = f"{svc.name} has no ports defined"
            return
        port, proto = svc.ports[0]
        result = await rich_rule_dialog(port, proto)
        if result is None:
            return
        port_r, proto_r, source_cidr = result
        try:
            if proto_r == "both":
                for p in ["tcp", "udp"]:
                    self.fw.open_port_for_source(port_r, p, source_cidr)
                self._status_msg = f"Added rich rule: {port_r}/tcp+udp from {source_cidr}"
            else:
                self.fw.open_port_for_source(port_r, proto_r, source_cidr)
                self._status_msg = f"Added rich rule: {port_r}/{proto_r} from {source_cidr}"
            self._reload_services()
        except Exception as e:
            self._error_msg = str(e)

    async def _action_enter(self) -> None:
        """Open action menu for selected service."""
        svc = self._port_list.get_selected()
        if svc is None:
            return

        is_open = svc.is_open
        is_protected = svc.name in PROTECTED_SERVICES

        if is_open:
            options = [
                "Close (permanent + runtime)",
                "Open only for IP/CIDR (Rich Rule)",
                "Risk assessment",
                "Service details",
                "Back",
            ]
        else:
            options = [
                "Open (permanent + runtime)",
                "Open runtime only (until reload)",
                "Open only for IP/CIDR (Rich Rule)",
                "Risk assessment",
                "Service details",
                "Back",
            ]

        port_info = ", ".join(f"{p}/{pr}" for p, pr in svc.ports) or "no ports"
        bar = score_bar(svc.risk_score, width=10)
        risk_info = f"  Risk: {bar} {svc.risk_score}/100 [{svc.risk_label}]"
        message = f"{svc.short or svc.name}  [{port_info}]  {'● OPEN' if is_open else '○ closed'}{risk_info}"
        if is_protected:
            message += "  ⚠ PROTECTED"

        choice = await action_menu(
            title=f" {svc.name} ",
            options=options,
            message=message,
        )

        if choice is None or options[choice] == "Back":
            return

        chosen = options[choice]

        if chosen == "Open (permanent + runtime)":
            self._action_open(svc, runtime_only=False)
        elif chosen == "Open runtime only (until reload)":
            self._action_open(svc, runtime_only=True)
        elif chosen == "Close (permanent + runtime)":
            await self._action_close(svc)
        elif chosen == "Open only for IP/CIDR (Rich Rule)":
            await self._action_open_for_source(svc)
        elif chosen == "Risk assessment":
            await self._show_risk_assessment(svc)
        elif chosen == "Service details":
            await self._show_service_details(svc)

    async def _show_risk_assessment(self, svc: ServiceInfo) -> None:
        """Show detailed risk assessment for a service."""
        import textwrap
        risk = get_risk_for_service(svc.name, svc.ports)
        bar = score_bar(risk.score, width=20)
        lines = [
            f"Service:  {svc.name}",
            f"Port(s):  {', '.join(f'{p}/{pr}' for p, pr in svc.ports) or '(none)'}",
            "",
            f"Risk Score: {risk.score}/100  [{risk.label}]",
            f"  {bar}",
            "",
            f"Summary: {risk.summary}",
            "",
            "Explanation:",
        ]
        for para in risk.explanation.split("\n"):
            if para.strip():
                wrapped = textwrap.fill(para, width=70, initial_indent="  ", subsequent_indent="  ")
                lines.append(wrapped)
            else:
                lines.append("")

        if risk.cves:
            lines.append("")
            lines.append(f"Notable CVEs: {', '.join(risk.cves)}")

        await action_menu(
            title=f" Risk Assessment: {svc.name} ",
            options=["Back"],
            message="\n".join(lines),
        )

    async def _show_service_details(self, svc: ServiceInfo) -> None:
        lines = [
            f"Name:        {svc.name}",
            f"Short:       {svc.short}",
            f"Description: {svc.description or '(none)'}",
            f"Ports:       {', '.join(f'{p}/{pr}' for p, pr in svc.ports) or '(none)'}",
            f"Status:      {'OPEN' if svc.is_open else 'CLOSED'}",
            f"Risk:        {score_bar(svc.risk_score, width=10)} {svc.risk_score}/100 [{svc.risk_label}]",
        ]
        choice = await action_menu(
            title=f" Details: {svc.name} ",
            options=["Risk assessment", "Back"],
            message="\n".join(lines),
        )
        if choice == 0:
            await self._show_risk_assessment(svc)

    async def _action_lockdown(self) -> None:
        zone = self.fw.get_active_zone()
        keep = list(PROTECTED_SERVICES)
        preview = self.fw.lockdown(zone=zone, keep=keep, dry_run=True)
        confirmed = await lockdown_dialog(
            services_to_remove=preview["services"],
            ports_to_remove=preview["ports"],
            keep=keep,
        )
        if not confirmed:
            self._status_msg = "Lockdown cancelled"
            return
        try:
            self.fw.lockdown(zone=zone, keep=keep, permanent=True, runtime=True)
            self._status_msg = f"Lockdown applied to zone '{zone}'"
            self._reload_services()
        except Exception as e:
            self._error_msg = str(e)

    async def _action_zone_switch(self) -> None:
        zones = self.fw.get_zones()
        current = self.fw.get_active_zone()
        chosen = await zone_picker_dialog(zones, current)
        if chosen and chosen != current:
            self.fw.set_active_zone(chosen)
            self._reload_services()
            self._status_msg = f"Switched to zone: {chosen}"

    # ------------------------------------------------------------------
    # Search handling
    # ------------------------------------------------------------------

    def _activate_search(self) -> None:
        self._search_mode = True
        if self._app:
            self._app.invalidate()

    def _deactivate_search(self) -> None:
        self._search_mode = False
        self._search_text = ""
        self._port_list.set_filter("")
        if self._app:
            self._app.invalidate()

    def _search_char(self, char: str) -> None:
        self._search_text += char
        self._port_list.set_filter(self._search_text)
        if self._app:
            self._app.invalidate()

    def _search_backspace(self) -> None:
        if self._search_text:
            self._search_text = self._search_text[:-1]
            self._port_list.set_filter(self._search_text)
        else:
            self._deactivate_search()
        if self._app:
            self._app.invalidate()

    # ------------------------------------------------------------------
    # Key bindings
    # ------------------------------------------------------------------

    def _build_key_bindings(self) -> KeyBindings:
        kb = KeyBindings()

        @kb.add("up")
        def _up(event) -> None:
            if not self._search_mode:
                self._port_list.move_up()

        @kb.add("down")
        def _down(event) -> None:
            if not self._search_mode:
                self._port_list.move_down()

        @kb.add("enter")
        async def _enter(event) -> None:
            if self._search_mode:
                self._search_mode = False
            else:
                await self._action_enter()

        @kb.add("escape")
        def _escape(event) -> None:
            self._deactivate_search()

        @kb.add("/")
        def _slash(event) -> None:
            self._activate_search()

        @kb.add("o")
        @kb.add("O")
        def _open(event) -> None:
            if self._search_mode:
                self._search_char("o")
                return
            svc = self._port_list.get_selected()
            if svc and not svc.is_open:
                self._action_open(svc)
            elif svc:
                self._status_msg = f"{svc.name} is already open"

        @kb.add("c")
        @kb.add("C")
        async def _close(event) -> None:
            if self._search_mode:
                self._search_char("c")
                return
            svc = self._port_list.get_selected()
            if svc and svc.is_open:
                await self._action_close(svc)
            elif svc:
                self._status_msg = f"{svc.name} is already closed"

        @kb.add("l")
        @kb.add("L")
        async def _lockdown(event) -> None:
            if self._search_mode:
                self._search_char("l")
                return
            await self._action_lockdown()

        @kb.add("z")
        @kb.add("Z")
        async def _zone(event) -> None:
            if self._search_mode:
                self._search_char("z")
                return
            await self._action_zone_switch()

        @kb.add("r")
        @kb.add("R")
        def _refresh(event) -> None:
            if self._search_mode:
                self._search_char("r")
                return
            self._reload_services()

        @kb.add("q")
        @kb.add("Q")
        def _quit(event) -> None:
            if self._search_mode:
                self._search_char("q")
                return
            event.app.exit()

        @kb.add("c-c")
        @kb.add("c-q")
        def _force_quit(event) -> None:
            event.app.exit()

        @kb.add("backspace")
        def _backspace(event) -> None:
            if self._search_mode:
                self._search_backspace()

        # Catch all printable chars in search mode
        for char in "abdefghijkmnopstuvwxy0123456789.-_: ":
            @kb.add(char)
            def _char(event, c=char) -> None:
                if self._search_mode:
                    self._search_char(c)

        return kb

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_layout(self) -> Layout:
        header_window = Window(
            content=FormattedTextControl(text=self._get_header_text),
            height=1,
        )

        search_window = Window(
            content=FormattedTextControl(text=self._get_search_text),
            height=1,
        )

        list_window = Window(
            content=FormattedTextControl(
                text=self._get_list_text,
                focusable=True,
            ),
            height=D(preferred=24, min=5),
        )

        statusbar_window = Window(
            content=FormattedTextControl(text=self._get_statusbar_text),
            height=1,
        )

        root = HSplit(
            [
                header_window,
                Window(height=1, char="─", style="class:header"),
                search_window,
                Window(height=1, char="─", style="class:statusbar-sep"),
                list_window,
                Window(height=1, char="─", style="class:statusbar-sep"),
                statusbar_window,
            ]
        )

        return Layout(root, focused_element=list_window)

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start the TUI application."""
        # Load data before starting
        self._reload_services()

        layout = self._build_layout()
        kb = self._build_key_bindings()

        self._app = Application(
            layout=layout,
            key_bindings=kb,
            style=APP_STYLE,
            full_screen=True,
            mouse_support=False,
            refresh_interval=0,
        )

        self._app.run()
