import subprocess
from typing import Optional, List, Tuple

def run_command(command: List[str], timeout: int = 30) -> Tuple[int, str]:
    """
    Exécute une commande système de manière sécurisée et cross-platform.
    """
    try:
        # Sur Windows, on utilise shell=True uniquement si nécessaire,
        # mais ici la liste d'arguments est plus sûre.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",      # On force l'UTF-8
            errors="replace",      # Remplace les caractères invalides au lieu de crash
            timeout=timeout        # Évite les blocages infinis
        )

        # On combine stdout et stderr car certaines commandes
        # écrivent leurs infos sur stderr (ex: sshd -T)
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
    Exécute une commande et analyse la sortie par rapport à des motifs (patterns).
    """
    # Import local pour éviter les imports circulaires
    from sysaudit.core.models import CheckResult

    returncode, output = run_command(command)

    # On normalise en minuscules pour la comparaison
    output_lower = output.lower()

    # Si la commande a échoué (code de retour différent de 0)
    if returncode != 0:
        return CheckResult(
            name=name,
            status="error",
            message=f"{error_prefix} ({returncode}) : {output}"
        )

    # 1. Vérification des succès
    for pattern in ok_patterns:
        if pattern.lower() in output_lower:
            return CheckResult(
                name=name,
                status="ok",
                message=ok_message
            )

    # 2. Vérification des échecs connus
    for pattern in fail_patterns:
        if pattern.lower() in output_lower:
            return CheckResult(
                name=name,
                status="fail",
                message=fail_message
            )

    # 3. Cas non géré
    return CheckResult(
        name=name,
        status="error",
        message=f"{unexpected_prefix} : {output}"
    )