from sysaudit.core.models import CheckResult
#specific checks for macos

def check_firewall():
    try:
        #execute a system command
        result = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            capture_output=True, #Launches the macOS command that queries the state of the firewall.
            text=True,
            check=True #Returns the text as a string, not in bytes.
        )

        output = result.stdout.strip().lower() #launches an exception in case of failure

        if "enabled" in output: #if "enabled", the firewall is off
            return CheckResult(
                name="firewall_enabled",
                status="ok",
                message="Le firewall macOS est activé"
            )

        return CheckResult(
            name="firewall_enabled",
            status="fail",
            message="Le firewall macOS est désactivé"
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