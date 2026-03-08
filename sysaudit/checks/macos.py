import subprocess

from sysaudit.core.models import CheckResult


def check_firewall():
    command = ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]

    try: #execute a system command
        result = subprocess.run(
            command,
            capture_output=True, ##Launches the macOS command that queries the state of the firewall.
            text=True
        )

        output = (result.stdout or result.stderr).strip().lower() ##launches an exception in case of failure

        if result.returncode != 0:
            return CheckResult(
                name="firewall_enabled",
                status="error",
                message=f"Commande échouée : {output}"
            )

        if "enabled" in output:
            return CheckResult(
                name="firewall_enabled",
                status="ok",
                message="Le firewall macOS est activé"
            )

        if "disabled" in output:
            return CheckResult(
                name="firewall_enabled",
                status="fail",
                message="Le firewall macOS est désactivé"
            )

        return CheckResult(
            name="firewall_enabled",
            status="error",
            message=f"Réponse inattendue : {output}"
        )

    except FileNotFoundError:
        return CheckResult(
            name="firewall_enabled",
            status="error",
            message="Commande firewall introuvable sur ce système"
        )
    except Exception as error:
        return CheckResult(
            name="firewall_enabled",
            status="error",
            message=f"Impossible de vérifier le firewall : {error}"
        )


def run_checks():
    return [
        check_firewall()
    ]

def run_checks():
    return [
        check_firewall()
    ]