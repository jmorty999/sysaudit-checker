import subprocess
import os
import plistlib

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

#checks for filevault
def check_filevault():
    command = ["fdesetup", "status"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = (result.stdout or result.stderr).strip().lower()

        if result.returncode != 0:
            return CheckResult(
                name="filevault_enabled",
                status="error",
                message=f"Commande échouée : {output}"
            )

        if "filevault is on" in output:
            return CheckResult(
                name="filevault_enabled",
                status="ok",
                message="FileVault est activé"
            )

        if "filevault is off" in output:
            return CheckResult(
                name="filevault_enabled",
                status="fail",
                message="FileVault est désactivé"
            )

        return CheckResult(
            name="filevault_enabled",
            status="error",
            message=f"Réponse inattendue : {output}"
        )

    except FileNotFoundError:
        return CheckResult(
            name="filevault_enabled",
            status="error",
            message="Commande fdesetup introuvable sur ce système"
        )
    except Exception as error:
        return CheckResult(
            name="filevault_enabled",
            status="error",
            message=f"Impossible de vérifier FileVault : {error}"
        )

#gatekeeper =/= sip
#gatekeeper = controls what the apps have the right to execute
#sip = protects the critical parts of the macos system
#xip = silent anti-virus of macos
def check_gatekeeper():
    command = ["spctl", "--status"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = (result.stdout or result.stderr).strip().lower()

        if result.returncode != 0:
            return CheckResult(
                name="gatekeeper_enabled",
                status="error",
                message=f"Commande échouée : {output}"
            )

        if "assessments enabled" in output:
            return CheckResult(
                name="gatekeeper_enabled",
                status="ok",
                message="Gatekeeper est activé"
            )

        if "assessments disabled" in output:
            return CheckResult(
                name="gatekeeper_enabled",
                status="fail",
                message="Gatekeeper est désactivé"
            )

        return CheckResult(
            name="gatekeeper_enabled",
            status="error",
            message=f"Réponse inattendue : {output}"
        )

    except FileNotFoundError:
        return CheckResult(
            name="gatekeeper_enabled",
            status="error",
            message="Commande spctl introuvable sur ce système"
        )
    except Exception as error:
        return CheckResult(
            name="gatekeeper_enabled",
            status="error",
            message=f"Impossible de vérifier Gatekeeper : {error}"
        )


def check_sip():
    command = ["csrutil", "status"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = (result.stdout or result.stderr).strip().lower()

        if result.returncode != 0:
            return CheckResult(
                name="sip_enabled",
                status="error",
                message=f"Commande échouée : {output}"
            )

        if "enabled" in output:
            return CheckResult(
                name="sip_enabled",
                status="ok",
                message="System Integrity Protection (SIP) est activé"
            )

        if "disabled" in output:
            return CheckResult(
                name="sip_enabled",
                status="fail",
                message="System Integrity Protection (SIP) est désactivé"
            )

        return CheckResult(
            name="sip_enabled",
            status="error",
            message=f"Réponse inattendue : {output}"
        )

    except FileNotFoundError:
        return CheckResult(
            name="sip_enabled",
            status="error",
            message="Commande csrutil introuvable sur ce système"
        )
    except Exception as error:
        return CheckResult(
            name="sip_enabled",
            status="error",
            message=f"Impossible de vérifier SIP : {error}"
        )
def check_xprotect():
    possible_paths = [
        "/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    ]

    try:
        found_path = None

        for plist_path in possible_paths:
            if os.path.exists(plist_path):
                found_path = plist_path
                break

        if not found_path:
            return CheckResult(
                name="xprotect_present",
                status="fail",
                message="XProtect bundle introuvable dans les emplacements connus"
            )

        with open(found_path, "rb") as plist_file:
            plist_data = plistlib.load(plist_file)

        version = plist_data.get("CFBundleShortVersionString", "Version inconnue")

        return CheckResult(
            name="xprotect_present",
            status="ok",
            message=f"XProtect présent (version {version}, chemin {found_path})"
        )

    except Exception as error:
        return CheckResult(
            name="xprotect_present",
            status="error",
            message=f"Impossible de vérifier XProtect : {error}"
        )

def run_checks():
    return [
        check_firewall(),
        check_filevault(),
        check_gatekeeper(),
        check_sip(),
        check_xprotect()
    ]