from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass
class Interface:
    ip: str
    name: str
    description: str

    @property
    def display(self) -> str:
        return f"[{self.name}] {self.description} ({self.ip})"

    @classmethod
    def check_valid(cls, ip, name, description) -> Interface | None:
        try:
            if ipaddress.ip_address(ip).version != 4:
                return None
        except ValueError:
            return None
        if "loopback" in name.lower():
            return None
        return cls(ip, name, description)
