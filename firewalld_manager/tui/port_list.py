"""Filterable, navigable port list component for firewalld-manager TUI."""

from __future__ import annotations

from typing import Optional

from prompt_toolkit.formatted_text import StyleAndTextTuples
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.containers import Window

from firewalld_manager.firewall import ServiceInfo, PROTECTED_SERVICES
from firewalld_manager.risk import score_bar


# Column widths
COL_PORT = 8
COL_PROTO = 7
COL_SERVICE = 20
COL_SHORT = 22
COL_STATUS = 10
COL_RISK = 14  # "█████░░░░░ 73"


def _pad(s: str, width: int) -> str:
    s = str(s)
    if len(s) > width:
        return s[: width - 1] + "…"
    return s.ljust(width)


def _risk_style(score: int, selected: bool = False) -> str:
    """Return a prompt_toolkit style class name based on risk score."""
    if selected:
        return "class:risk-selected"
    if score >= 90:
        return "class:risk-critical"
    if score >= 70:
        return "class:risk-high"
    if score >= 45:
        return "class:risk-medium"
    if score >= 20:
        return "class:risk-low"
    return "class:risk-minimal"


class PortListControl:
    """Manages the filtered, scrollable list of services."""

    def __init__(self) -> None:
        self._all_services: list[ServiceInfo] = []
        self._filtered: list[ServiceInfo] = []
        self._selected_idx: int = 0
        self._filter: str = ""
        self._scroll_offset: int = 0
        self._visible_rows: int = 20  # updated by render

    # ------------------------------------------------------------------
    # Data management
    # ------------------------------------------------------------------

    def load(self, services: list[ServiceInfo]) -> None:
        """Load (or reload) the service list."""
        # Sort: open first (by risk score desc), then closed alphabetically
        self._all_services = sorted(
            services,
            key=lambda s: (not s.is_open, -s.risk_score if s.is_open else 0, s.name.lower()),
        )
        self._apply_filter()

    def _apply_filter(self) -> None:
        q = self._filter.lower()
        if not q:
            self._filtered = list(self._all_services)
        else:
            self._filtered = [
                s
                for s in self._all_services
                if q in s.name.lower()
                or q in s.short.lower()
                or q in s.description.lower()
                or any(q in port for port, _ in s.ports)
                or q in s.risk_label.lower()
            ]
        # Clamp selection
        if self._filtered:
            self._selected_idx = min(self._selected_idx, len(self._filtered) - 1)
        else:
            self._selected_idx = 0
        self._scroll_offset = 0

    def set_filter(self, text: str) -> None:
        self._filter = text
        self._apply_filter()

    def get_filter(self) -> str:
        return self._filter

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def move_up(self) -> None:
        if self._filtered:
            self._selected_idx = (self._selected_idx - 1) % len(self._filtered)
            self._ensure_visible()

    def move_down(self) -> None:
        if self._filtered:
            self._selected_idx = (self._selected_idx + 1) % len(self._filtered)
            self._ensure_visible()

    def _ensure_visible(self) -> None:
        if self._selected_idx < self._scroll_offset:
            self._scroll_offset = self._selected_idx
        elif self._selected_idx >= self._scroll_offset + self._visible_rows:
            self._scroll_offset = self._selected_idx - self._visible_rows + 1

    def get_selected(self) -> Optional[ServiceInfo]:
        if not self._filtered:
            return None
        return self._filtered[self._selected_idx]

    def get_total(self) -> int:
        return len(self._filtered)

    def get_selected_idx(self) -> int:
        return self._selected_idx

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render(self, available_rows: int) -> StyleAndTextTuples:
        self._visible_rows = max(1, available_rows)

        result: StyleAndTextTuples = []

        # Header row
        header = (
            _pad("Port", COL_PORT)
            + _pad("Proto", COL_PROTO)
            + _pad("Service", COL_SERVICE)
            + _pad("Description", COL_SHORT)
            + _pad("Status", COL_STATUS)
            + _pad("Risk", COL_RISK)
        )
        result.append(("class:header", header + "\n"))
        result.append(("class:header", "─" * len(header) + "\n"))

        if not self._filtered:
            result.append(("class:empty", "  (no results)\n"))
            return result

        visible = self._filtered[
            self._scroll_offset : self._scroll_offset + self._visible_rows
        ]

        for i, svc in enumerate(visible):
            abs_idx = self._scroll_offset + i
            is_selected = abs_idx == self._selected_idx
            is_protected = svc.name in PROTECTED_SERVICES

            # Determine port display
            if svc.ports:
                port_str = svc.ports[0][0]
                proto_str = svc.ports[0][1]
                if len(svc.ports) > 1:
                    port_str += f"+{len(svc.ports)-1}"
            else:
                port_str = "-"
                proto_str = "-"

            # Status
            if svc.is_open:
                if is_protected:
                    status_str = "● OPEN*"
                    status_style = "class:status-protected"
                else:
                    status_str = "● OPEN"
                    status_style = "class:status-open"
            else:
                status_str = "○ closed"
                status_style = "class:status-closed"

            # Risk bar: "██████░░░░ 73"
            bar = score_bar(svc.risk_score, width=8)
            risk_str = _pad(f"{bar} {svc.risk_score}", COL_RISK)

            row_text = (
                _pad(port_str, COL_PORT)
                + _pad(proto_str, COL_PROTO)
                + _pad(svc.name, COL_SERVICE)
                + _pad(svc.short or svc.description, COL_SHORT)
            )
            status_col = _pad(status_str, COL_STATUS)

            if is_selected:
                row_style = "class:selected"
                result.append((row_style, row_text))
                if svc.is_open and is_protected:
                    result.append(("class:selected-protected", status_col))
                elif svc.is_open:
                    result.append(("class:selected-open", status_col))
                else:
                    result.append(("class:selected-closed", status_col))
                result.append(("class:risk-selected", risk_str + "\n"))
            else:
                if is_protected and svc.is_open:
                    result.append(("class:row-protected", row_text))
                    result.append((status_style, status_col))
                elif svc.is_open:
                    result.append(("class:row-open", row_text))
                    result.append((status_style, status_col))
                else:
                    result.append(("class:row-closed", row_text))
                    result.append((status_style, status_col))
                result.append((_risk_style(svc.risk_score, selected=False), risk_str + "\n"))

        # Scroll indicator
        total = len(self._filtered)
        shown_end = min(self._scroll_offset + self._visible_rows, total)
        result.append(
            ("class:scroll-info", f"\n  {self._scroll_offset + 1}-{shown_end} of {total}")
        )

        return result

    def make_window(self, height: int = 20) -> Window:
        """Create a prompt_toolkit Window bound to this control."""
        control = FormattedTextControl(
            text=lambda: self.render(height),
            focusable=True,
        )
        return Window(
            content=control,
            height=height,
        )
