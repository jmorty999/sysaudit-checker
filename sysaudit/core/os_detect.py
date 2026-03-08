# detect the os
import platform
# It allows you to retrieve information about the machine.

def detect_os() -> str:
#returns a string 
    system = platform.system().lower()

    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    if system == "windows":
        return "windows"

    return "unknown"
