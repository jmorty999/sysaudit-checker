import subprocess
import os
import ctypes
import sys
from typing import List, Tuple, Optional

def color_text(text: str, color_code: str) -> str:
    """Ajoute des codes couleur ANSI au texte."""
    return f"\033[{color_code}m{text}\033[0m"

def is_admin() -> bool:
    """
    Vérifie si l'utilisateur actuel possède les privilèges Administrateur ou Root.
    """
    try:
        if sys.platform == "win32":
            # Pour Windows : vérifie si l'utilisateur appartient au groupe Admin
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Pour Linux/macOS : vérifie l'ID de l'utilisateur (Root = 0)
            return os.getuid() == 0
    except Exception:
        return False

def require_admin(name: str):
    """
    Retourne un CheckResult d'erreur si les droits sont insuffisants.
    """
    from sysaudit.core.models import CheckResult
    return CheckResult(
        name=name,
        status="error",
        message="Privilèges insuffisants (Root/Admin requis pour ce test)"
    )

def run_command(command: List[str], timeout: int = 30) -> Tuple[int, str]:
    """
    Exécute une commande système de manière sécurisée et cross-platform.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode, output

    except subprocess.TimeoutExpired:
        return 124, "La commande a dépassé le délai imparti (timeout)"
    except FileNotFoundError:
        return 127, f"Commande introuvable : {command[0]}"
    except Exception as error:
        return 1, f"Erreur système : {str(error)}"

def command_check(
        name: str,
        command: List[str],
        ok_patterns: List[str],
        fail_patterns: List[str],
        ok_message: str,
        fail_message: str,
        error_prefix: str = "Commande échouée",
        unexpected_prefix: str = "Réponse inattendue"
):
    """
    Exécute une commande et analyse la sortie par rapport à des motifs.
    """
    from sysaudit.core.models import CheckResult

    returncode, output = run_command(command)
    output_lower = output.lower()

    if returncode != 0:
        return CheckResult(
            name=name,
            status="error",
            message=f"{error_prefix} ({returncode}) : {output}"
        )

    for pattern in ok_patterns:
        if pattern.lower() in output_lower:
            return CheckResult(name=name, status="ok", message=ok_message)

    for pattern in fail_patterns:
        if pattern.lower() in output_lower:
            return CheckResult(name=name, status="fail", message=fail_message)

    return CheckResult(
        name=name,
        status="error",
        message=f"{unexpected_prefix} : {output}"
    )