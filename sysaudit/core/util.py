import subprocess
from typing import Optional


def run_command(command: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = (result.stdout or result.stderr).strip()
        return result.returncode, output

    except FileNotFoundError:
        return 127, "Commande introuvable"
    except Exception as error:
        return 1, str(error)


def command_check(
    name: str,
    command: list[str],
    ok_patterns: list[str],
    fail_patterns: list[str],
    ok_message: str,
    fail_message: str,
    error_prefix: str = "Commande échouée",
    unexpected_prefix: str = "Réponse inattendue"
):
    from sysaudit.core.models import CheckResult

    returncode, output = run_command(command)
    output_lower = output.lower()

    if returncode != 0:
        return CheckResult(
            name=name,
            status="error",
            message=f"{error_prefix} : {output}"
        )

    for pattern in ok_patterns:
        if pattern in output_lower:
            return CheckResult(
                name=name,
                status="ok",
                message=ok_message
            )

    for pattern in fail_patterns:
        if pattern in output_lower:
            return CheckResult(
                name=name,
                status="fail",
                message=fail_message
            )

    return CheckResult(
        name=name,
        status="error",
        message=f"{unexpected_prefix} : {output}"
    )