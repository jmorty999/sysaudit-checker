from sysaudit.core.models import CheckResult


def run_checks():
    return [
        CheckResult(
            name="linux_basic_check",
            status="info",
            message="Check Linux à implémenter"
        )
    ]
