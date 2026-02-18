"""Wrapper around FirewallClient with data classes for firewalld-manager."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:
    from firewall.client import FirewallClient
    _FIREWALL_CLIENT_AVAILABLE = True
except ImportError:
    _FIREWALL_CLIENT_AVAILABLE = False
    FirewallClient = None  # type: ignore[misc,assignment]


def _check_firewalld_available() -> None:
    """Check that firewalld and python-firewall are available, with helpful errors."""
    if not _FIREWALL_CLIENT_AVAILABLE:
        import shutil, sys
        lines = [
            "python-firewall is not installed.",
            "",
            "Install it for your distribution:",
            "  Manjaro/Arch:  sudo pacman -S python-firewall",
            "  Ubuntu/Debian: sudo apt install firewalld python3-firewall",
            "  Fedora/RHEL:   sudo dnf install python3-firewall",
            "  openSUSE:      sudo zypper install python3-firewall",
        ]
        raise SystemExit("\n".join(lines))

    # Check that the firewalld daemon is running
    import subprocess
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", "firewalld"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            "firewalld is not running.\n\n"
            "Start it with:  sudo systemctl start firewalld\n"
            "Enable it:      sudo systemctl enable firewalld"
        )


PROTECTED_SERVICES = {"ssh", "https"}
PROTECTED_PORTS = {"22/tcp", "443/tcp"}


@dataclass
class ServiceInfo:
    name: str
    ports: list[tuple[str, str]]  # [(port, proto), ...]
    description: str
    short: str
    is_open: bool = False  # open as service in current zone
    open_ports: set[str] = field(default_factory=set)  # "port/proto" open as raw port
    risk_score: int = 0
    risk_label: str = "UNKNOWN"


@dataclass
class ZoneStatus:
    name: str
    target: str
    interfaces: list[str]
    services: list[str]
    ports: list[tuple[str, str]]  # [(port, proto)]
    rich_rules: list[str]
    is_default: bool = False


class FirewallManager:
    """High-level wrapper around FirewallClient."""

    def __init__(self) -> None:
        _check_firewalld_available()
        try:
            self._client = FirewallClient()
            # Verify connection works
            self._client.getDefaultZone()
        except Exception as e:
            raise SystemExit(
                f"Cannot connect to firewalld via D-Bus: {e}\n\n"
                "Make sure firewalld is running and you have the right permissions.\n"
                "Try: sudo systemctl start firewalld"
            ) from e
        self._active_zone: str = self._client.getDefaultZone()
        self._service_cache: dict[str, ServiceInfo] | None = None

    # ------------------------------------------------------------------
    # Zone management
    # ------------------------------------------------------------------

    def get_zones(self) -> list[str]:
        return sorted(self._client.getZones())

    def get_active_zone(self) -> str:
        return self._active_zone

    def set_active_zone(self, zone: str) -> None:
        if zone not in self._client.getZones():
            raise ValueError(f"Unknown zone: {zone}")
        self._active_zone = zone
        self._service_cache = None  # invalidate cache

    def get_default_zone(self) -> str:
        return self._client.getDefaultZone()

    def get_active_zones(self) -> dict:
        """Returns dict zone -> {'interfaces': [...], 'sources': [...]}"""
        return self._client.getActiveZones()

    def get_zone_status(self, zone: Optional[str] = None) -> ZoneStatus:
        z = zone or self._active_zone
        settings = self._client.getZoneSettings(z)
        default = self._client.getDefaultZone()
        return ZoneStatus(
            name=z,
            target=settings.getTarget(),
            interfaces=list(settings.getInterfaces()),
            services=list(settings.getServices()),
            ports=list(settings.getPorts()),
            rich_rules=list(settings.getRichRules()),
            is_default=(z == default),
        )

    # ------------------------------------------------------------------
    # Service / port discovery
    # ------------------------------------------------------------------

    def _load_service_cache(self, zone: Optional[str] = None) -> dict[str, ServiceInfo]:
        if self._service_cache is not None:
            return self._service_cache

        z = zone or self._active_zone
        zone_settings = self._client.getZoneSettings(z)
        open_services: set[str] = set(zone_settings.getServices())
        open_ports_raw: set[str] = {
            f"{p}/{proto}" for p, proto in zone_settings.getPorts()
        }

        from firewalld_manager.risk import get_risk_for_service

        cache: dict[str, ServiceInfo] = {}
        for svc_name in self._client.listServices():
            try:
                si = self._client.getServiceSettings(svc_name)
                ports = [(p, proto) for p, proto in si.getPorts()]
                desc = si.getDescription() or ""
                short = si.getShort() or svc_name

                # Which of this service's ports are open as raw ports?
                svc_open_ports: set[str] = set()
                for p, proto in ports:
                    key = f"{p}/{proto}"
                    if key in open_ports_raw:
                        svc_open_ports.add(key)

                risk = get_risk_for_service(svc_name, ports)

                cache[svc_name] = ServiceInfo(
                    name=svc_name,
                    ports=ports,
                    description=desc,
                    short=short,
                    is_open=(svc_name in open_services),
                    open_ports=svc_open_ports,
                    risk_score=risk.score,
                    risk_label=risk.label,
                )
            except Exception:
                # Skip services that can't be read
                pass

        self._service_cache = cache
        return cache

    def get_all_services(self, zone: Optional[str] = None) -> list[ServiceInfo]:
        """All known services, with is_open set for the given zone."""
        return list(self._load_service_cache(zone).values())

    def get_open_services(self, zone: Optional[str] = None) -> list[str]:
        z = zone or self._active_zone
        return list(self._client.getZoneSettings(z).getServices())

    def get_open_ports(self, zone: Optional[str] = None) -> list[tuple[str, str]]:
        """Returns list of (port, proto) tuples that are open as raw ports."""
        z = zone or self._active_zone
        return list(self._client.getZoneSettings(z).getPorts())

    def invalidate_cache(self) -> None:
        self._service_cache = None

    # ------------------------------------------------------------------
    # Port / service operations
    # ------------------------------------------------------------------

    def open_port(
        self,
        port: str,
        proto: str,
        zone: Optional[str] = None,
        permanent: bool = True,
        runtime: bool = True,
        timeout: int = 0,
    ) -> None:
        z = zone or self._active_zone
        if runtime:
            self._client.addPort(z, port, proto, timeout)
        if permanent:
            pz = self._client.config().getZoneByName(z)
            if not pz.queryPort(port, proto):
                pz.addPort(port, proto)
        self.invalidate_cache()

    def close_port(
        self,
        port: str,
        proto: str,
        zone: Optional[str] = None,
        permanent: bool = True,
        runtime: bool = True,
    ) -> None:
        z = zone or self._active_zone
        if runtime:
            try:
                self._client.removePort(z, port, proto)
            except Exception:
                pass
        if permanent:
            pz = self._client.config().getZoneByName(z)
            if pz.queryPort(port, proto):
                pz.removePort(port, proto)
        self.invalidate_cache()

    def open_service(
        self,
        service: str,
        zone: Optional[str] = None,
        permanent: bool = True,
        runtime: bool = True,
        timeout: int = 0,
    ) -> None:
        z = zone or self._active_zone
        if runtime:
            self._client.addService(z, service, timeout)
        if permanent:
            pz = self._client.config().getZoneByName(z)
            if not pz.queryService(service):
                pz.addService(service)
        self.invalidate_cache()

    def close_service(
        self,
        service: str,
        zone: Optional[str] = None,
        permanent: bool = True,
        runtime: bool = True,
    ) -> None:
        z = zone or self._active_zone
        if runtime:
            try:
                self._client.removeService(z, service)
            except Exception:
                pass
        if permanent:
            pz = self._client.config().getZoneByName(z)
            if pz.queryService(service):
                pz.removeService(service)
        self.invalidate_cache()

    def query_port(self, port: str, proto: str, zone: Optional[str] = None) -> bool:
        z = zone or self._active_zone
        return bool(self._client.queryPort(z, port, proto))

    def query_service(self, service: str, zone: Optional[str] = None) -> bool:
        z = zone or self._active_zone
        return bool(self._client.queryService(z, service))

    # ------------------------------------------------------------------
    # Rich rules
    # ------------------------------------------------------------------

    def add_rich_rule(
        self,
        rule: str,
        zone: Optional[str] = None,
        permanent: bool = True,
        runtime: bool = True,
        timeout: int = 0,
    ) -> None:
        z = zone or self._active_zone
        if runtime:
            self._client.addRichRule(z, rule, timeout)
        if permanent:
            pz = self._client.config().getZoneByName(z)
            if not pz.queryRichRule(rule):
                pz.addRichRule(rule)
        self.invalidate_cache()

    def remove_rich_rule(
        self,
        rule: str,
        zone: Optional[str] = None,
        permanent: bool = True,
        runtime: bool = True,
    ) -> None:
        z = zone or self._active_zone
        if runtime:
            try:
                self._client.removeRichRule(z, rule)
            except Exception:
                pass
        if permanent:
            pz = self._client.config().getZoneByName(z)
            if pz.queryRichRule(rule):
                pz.removeRichRule(rule)
        self.invalidate_cache()

    def open_port_for_source(
        self,
        port: str,
        proto: str,
        source_cidr: str,
        zone: Optional[str] = None,
        permanent: bool = True,
        runtime: bool = True,
    ) -> str:
        """Open a port only for a specific source IP/CIDR using a rich rule.
        Returns the rule string that was added."""
        rule = f'rule family="ipv4" source address="{source_cidr}" port port="{port}" protocol="{proto}" accept'
        self.add_rich_rule(rule, zone=zone, permanent=permanent, runtime=runtime)
        return rule

    # ------------------------------------------------------------------
    # Lockdown
    # ------------------------------------------------------------------

    def lockdown(
        self,
        zone: Optional[str] = None,
        keep: Optional[list[str]] = None,
        permanent: bool = True,
        runtime: bool = True,
        dry_run: bool = False,
    ) -> dict:
        """Remove all services and ports except those in 'keep'.

        Returns a dict describing what was removed:
          {'services': [...], 'ports': [...]}
        """
        z = zone or self._active_zone
        if keep is None:
            keep = list(PROTECTED_SERVICES)

        status = self.get_zone_status(z)

        services_to_remove = [s for s in status.services if s not in keep]
        ports_to_remove = list(status.ports)  # remove all raw ports

        if dry_run:
            return {"services": services_to_remove, "ports": ports_to_remove}

        for svc in services_to_remove:
            self.close_service(svc, zone=z, permanent=permanent, runtime=runtime)

        for port, proto in ports_to_remove:
            self.close_port(port, proto, zone=z, permanent=permanent, runtime=runtime)

        # Ensure kept services are actually open
        for svc in keep:
            if not self.query_service(svc, zone=z):
                self.open_service(svc, zone=z, permanent=permanent, runtime=runtime)

        self.invalidate_cache()
        return {"services": services_to_remove, "ports": ports_to_remove}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_port_spec(spec: str) -> tuple[str, str]:
        """Parse '8080/tcp' or '8080' -> ('8080', 'tcp')."""
        if "/" in spec:
            port, proto = spec.split("/", 1)
            return port.strip(), proto.strip().lower()
        return spec.strip(), "tcp"

    def is_protected(self, service: Optional[str] = None, port: Optional[str] = None, proto: Optional[str] = None) -> bool:
        if service and service in PROTECTED_SERVICES:
            return True
        if port and proto and f"{port}/{proto}" in PROTECTED_PORTS:
            return True
        return False
