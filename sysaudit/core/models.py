from dataclasses import dataclass, asdict
from enum import Enum

class Status(Enum):
    OK = "ok"
    FAIL = "fail"
    WARN = "warning"
    ERROR = "error"
    INFO = "info"

@dataclass
class CheckResult:
    name: str
    status: str  # On peut stocker la string pour la compatibilité, ou Status.value
    message: str
    severity: str = "medium"  # low, medium, high, critical

    def to_dict(self):
        """Convertit le résultat en dictionnaire pour l'export JSON."""
        return asdict(self)