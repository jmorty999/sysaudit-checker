import os
import plistlib

from sysaudit.core.models import CheckResult
from sysaudit.core.util import run_command


def check_firewall():
    returncode, output = run_command(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]
    )
    output_lower = output.lower()

    if returncode != 0:
        return CheckResult(
            name="firewall_enabled",
            status="error",
            message=f"Commande échouée : {output}"
        )

    if "enabled" in output_lower:
        return CheckResult(
            name="firewall_enabled",
            status="ok",
            message="Le firewall macOS est activé"
        )

    if "disabled" in output_lower:
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


def check_filevault():
    returncode, output = run_command(["fdesetup", "status"])
    output_lower = output.lower()

    if returncode != 0:
        return CheckResult(
            name="filevault_enabled",
            status="error",
            message=f"Commande échouée : {output}"
        )

    if "filevault is on" in output_lower:
        return CheckResult(
            name="filevault_enabled",
            status="ok",
            message="FileVault est activé"
        )

    if "filevault is off" in output_lower:
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


def check_gatekeeper():
    returncode, output = run_command(["spctl", "--status"])
    output_lower = output.lower()

    if returncode != 0:
        return CheckResult(
            name="gatekeeper_enabled",
            status="error",
            message=f"Commande échouée : {output}"
        )

    if "assessments enabled" in output_lower:
        return CheckResult(
            name="gatekeeper_enabled",
            status="ok",
            message="Gatekeeper est activé"
        )

    if "assessments disabled" in output_lower:
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


def check_sip():
    returncode, output = run_command(["csrutil", "status"])
    output_lower = output.lower()

    if returncode != 0:
        return CheckResult(
            name="sip_enabled",
            status="error",
            message=f"Commande échouée : {output}"
        )

    if "enabled" in output_lower:
        return CheckResult(
            name="sip_enabled",
            status="ok",
            message="System Integrity Protection (SIP) est activé"
        )

    if "disabled" in output_lower:
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


def check_xprotect():
    possible_paths = [
        "/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    ]

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

    try:
        with open(found_path, "rb") as plist_file:
            plist_data = plistlib.load(plist_file)

        version = plist_data.get("CFBundleShortVersionString", "Version inconnue")

        return CheckResult(
            name="xprotect_present",
            status="ok",
            message=f"XProtect présent (version {version})"
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