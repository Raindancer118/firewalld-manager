"""Dialog components for firewalld-manager TUI."""

from __future__ import annotations

from typing import Optional

from prompt_toolkit import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import (
    Button,
    Dialog,
    Frame,
    Label,
    TextArea,
)


DIALOG_STYLE = Style.from_dict(
    {
        "dialog": "bg:#1e1e2e #cdd6f4",
        "dialog frame.label": "bg:#89b4fa #1e1e2e bold",
        "dialog.body": "bg:#1e1e2e #cdd6f4",
        "button": "bg:#313244 #cdd6f4",
        "button.focused": "bg:#89b4fa #1e1e2e bold",
        "dialog shadow": "bg:#11111b",
        "text-area": "bg:#313244 #cdd6f4",
        "text-area focused": "bg:#45475a #cdd6f4",
    }
)

MENU_STYLE = Style.from_dict(
    {
        "dialog": "bg:#1e1e2e #cdd6f4",
        "frame.border": "bg:#1e1e2e #89b4fa",
        "frame.label": "bg:#89b4fa #1e1e2e bold",
        "selected": "bg:#89b4fa #1e1e2e bold",
        "hint": "#585b70 italic",
    }
)


async def confirm_dialog(
    title: str,
    message: str,
    yes_text: str = "Yes",
    no_text: str = "No",
) -> bool:
    """Show a yes/no confirmation dialog. Returns True if confirmed."""
    result: list[bool] = [False]

    kb = KeyBindings()

    def yes_handler() -> None:
        result[0] = True
        app.exit()

    def no_handler() -> None:
        result[0] = False
        app.exit()

    yes_btn = Button(yes_text, handler=yes_handler)
    no_btn = Button(no_text, handler=no_handler)

    @kb.add("escape")
    @kb.add("q")
    def _cancel(event) -> None:
        no_handler()

    @kb.add("y")
    def _yes(event) -> None:
        yes_handler()

    @kb.add("n")
    def _no(event) -> None:
        no_handler()

    dialog = Dialog(
        title=title,
        body=HSplit(
            [
                Label(text=HTML(message), dont_extend_height=True),
                Label(text=""),
            ],
            padding=1,
        ),
        buttons=[yes_btn, no_btn],
        modal=True,
        with_background=True,
    )

    app = Application(
        layout=Layout(dialog),
        key_bindings=kb,
        style=DIALOG_STYLE,
        mouse_support=False,
        full_screen=False,
    )
    await app.run_async()
    return result[0]


async def action_menu(
    title: str, options: list[str], message: str = ""
) -> Optional[int]:
    """Show an action menu with arrow navigation.

    Returns the index of the selected option, or None if cancelled.
    """
    result: list[Optional[int]] = [None]
    selected: list[int] = [0]

    kb = KeyBindings()

    @kb.add("up")
    def _up(event) -> None:
        selected[0] = (selected[0] - 1) % len(options)
        app.invalidate()

    @kb.add("down")
    def _down(event) -> None:
        selected[0] = (selected[0] + 1) % len(options)
        app.invalidate()

    @kb.add("enter")
    def _select(event) -> None:
        result[0] = selected[0]
        app.exit()

    @kb.add("escape")
    @kb.add("q")
    def _cancel(event) -> None:
        result[0] = None
        app.exit()

    def _get_menu_text():
        lines = []
        if message:
            for line in message.split("\n"):
                lines.append(("", f"  {line}\n"))
            lines.append(("", "\n"))
        for i, opt in enumerate(options):
            if i == selected[0]:
                lines.append(("class:selected", f"  > {opt}\n"))
            else:
                lines.append(("", f"    {opt}\n"))
        lines.append(("class:hint", "\n  [↑↓] Navigate  [Enter] Select  [Esc] Cancel"))
        return lines

    control = FormattedTextControl(text=_get_menu_text, focusable=True)
    body_window = Window(content=control)

    frame = Frame(body=body_window, title=title, style="class:dialog")
    layout = Layout(frame, focused_element=body_window)

    app = Application(
        layout=layout,
        key_bindings=kb,
        style=MENU_STYLE,
        mouse_support=False,
        full_screen=False,
    )
    await app.run_async()
    return result[0]


async def lockdown_dialog(
    services_to_remove: list[str],
    ports_to_remove: list[tuple[str, str]],
    keep: list[str],
) -> bool:
    """Show lockdown confirmation dialog. Returns True if the user confirms."""
    lines = ["The following will be <b>REMOVED</b>:\n"]

    if services_to_remove:
        lines.append(f"\n<ansired>Services: {', '.join(services_to_remove)}</ansired>")
    if ports_to_remove:
        port_strs = [f"{p}/{pr}" for p, pr in ports_to_remove]
        lines.append(f"\n<ansired>Ports: {', '.join(port_strs)}</ansired>")

    lines.append(f"\n\n<ansigreen>Keeping: {', '.join(keep)}</ansigreen>")
    lines.append("\n\n<b>This will be applied permanently and immediately!</b>")

    if not services_to_remove and not ports_to_remove:
        lines = ["<ansigreen>Nothing to remove. Zone is already in lockdown state.</ansigreen>"]

    return await confirm_dialog(
        title=" LOCKDOWN CONFIRMATION ",
        message="".join(lines),
        yes_text="LOCK IT DOWN",
        no_text="Cancel",
    )


async def zone_picker_dialog(zones: list[str], current_zone: str) -> Optional[str]:
    """Show zone picker. Returns the selected zone name or None."""
    idx = await action_menu(
        title=f" Switch Zone (current: {current_zone}) ",
        options=zones,
        message="Select a zone:",
    )
    if idx is None:
        return None
    return zones[idx]


async def rich_rule_dialog(port: str, proto: str) -> Optional[tuple[str, str, str]]:
    """Dialog to enter source IP/CIDR for a rich rule.

    Returns (port, proto, source_cidr) or None if cancelled.
    """
    result: list = [None]
    proto_options: list[str] = [proto, "tcp" if proto == "udp" else "udp", "both"]
    proto_idx: list[int] = [0]

    kb = KeyBindings()

    @kb.add("escape")
    def _cancel(event) -> None:
        result[0] = None
        app.exit()

    @kb.add("tab")
    def _tab(event) -> None:
        proto_idx[0] = (proto_idx[0] + 1) % len(proto_options)
        app.invalidate()

    @kb.add("enter")
    def _confirm(event) -> None:
        src = source_area.buffer.text.strip()
        if not src:
            return
        chosen_proto = proto_options[proto_idx[0]]
        result[0] = (port, chosen_proto, src)
        app.exit()

    def _get_proto_text():
        parts = []
        for i, p in enumerate(proto_options):
            if i == proto_idx[0]:
                parts.append(("class:selected", f" [{p}] "))
            else:
                parts.append(("", f"  {p}  "))
        return parts

    source_area = TextArea(
        text="",
        multiline=False,
        password=False,
        focusable=True,
        prompt="IP/CIDR: ",
        style="class:text-area",
    )

    proto_control = FormattedTextControl(text=_get_proto_text)
    proto_window = Window(content=proto_control, height=1)

    body = HSplit(
        [
            Label(text=HTML(f"  Restrict <b>{port}/{proto}</b> to a specific source:")),
            Label(text=""),
            source_area,
            Label(text=""),
            Label(text="  Protocol: "),
            proto_window,
            Label(text=""),
            Label(
                text=HTML(
                    "  <ansiyellow>[Enter]</ansiyellow> Apply  "
                    "<ansiyellow>[Tab]</ansiyellow> Switch protocol  "
                    "<ansiyellow>[Esc]</ansiyellow> Cancel"
                )
            ),
        ],
        padding=1,
    )

    frame = Frame(
        body=body,
        title=f" Source restriction: {port}/{proto} ",
        style="class:dialog",
    )

    style = Style.from_dict(
        {
            "dialog": "bg:#1e1e2e #cdd6f4",
            "frame.border": "bg:#1e1e2e #89b4fa",
            "frame.label": "bg:#89b4fa #1e1e2e bold",
            "text-area": "bg:#313244 #cdd6f4",
            "selected": "bg:#89b4fa #1e1e2e bold",
        }
    )

    app = Application(
        layout=Layout(frame, focused_element=source_area),
        key_bindings=kb,
        style=style,
        mouse_support=False,
        full_screen=False,
    )
    await app.run_async()
    return result[0]
