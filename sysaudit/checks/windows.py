from sysaudit.core.models import CheckResult


def run_checks():
    return [
        CheckResult(
            name="windows_basic_check",
            status="info",
            message="Check Windows à implémenter"
        )
    ]
