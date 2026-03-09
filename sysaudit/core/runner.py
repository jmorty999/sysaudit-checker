from sysaudit.core.os_detect import detect_os
from sysaudit.checks import macos, linux, windows


def run_audit():
    #detect the os
    os_name = detect_os()

    if os_name == "macos":
        return macos.run_checks()
    if os_name == "linux":
        return linux.run_checks()
    if os_name == "windows":
        return windows.run_checks()

    return []
