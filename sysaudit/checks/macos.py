import os
import plistlib

from sysaudit.core.models import CheckResult
from sysaudit.core.util import run_command


def command_check(name, command, ok_patterns, fail_patterns, ok_message, fail_message):
    returncode, output = run_command(command)
    output_lower = output.lower()

    if returncode != 0:
        return CheckResult(
            name=name,
            status="error",
            message=f"Commande échouée : {output}"
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
        message=f"Réponse inattendue : {output}"
    )


def check_firewall():
    return command_check(
        name="firewall_enabled",
        command=["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        ok_patterns=["enabled"],
        fail_patterns=["disabled"],
        ok_message="Le firewall macOS est activé",
        fail_message="Le firewall macOS est désactivé"
    )


def check_filevault():
    return command_check(
        name="filevault_enabled",
        command=["fdesetup", "status"],
        ok_patterns=["filevault is on"],
        fail_patterns=["filevault is off"],
        ok_message="FileVault est activé",
        fail_message="FileVault est désactivé"
    )


def check_gatekeeper():
    return command_check(
        name="gatekeeper_enabled",
        command=["spctl", "--status"],
        ok_patterns=["assessments enabled"],
        fail_patterns=["assessments disabled"],
        ok_message="Gatekeeper est activé",
        fail_message="Gatekeeper est désactivé"
    )


def check_sip():
    return command_check(
        name="sip_enabled",
        command=["csrutil", "status"],
        ok_patterns=["enabled"],
        fail_patterns=["disabled"],
        ok_message="System Integrity Protection (SIP) est activé",
        fail_message="System Integrity Protection (SIP) est désactivé"
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