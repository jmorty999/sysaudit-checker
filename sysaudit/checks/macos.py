from sysaudit.core.models import CheckResult
#specific checks for macos

def run_checks():
    return [
        CheckResult(
            name="macos_basic_check",
            status="info",
            message="Check macOS à implémenter"
        )
    ]
