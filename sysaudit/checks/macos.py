import os
import plistlib
from pathlib import Path

from sysaudit.core.models import CheckResult
from sysaudit.core.util import command_check, run_command

CHECKS = []

def register_check(func):
    CHECKS.append(func)
    return func

@register_check
def check_firewall():
    return command_check(
        name="firewall_enabled",
        command=["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        ok_patterns=["enabled"],
        fail_patterns=["disabled"],
        ok_message="Le firewall macOS est activé",
        fail_message="Le firewall macOS est désactivé"
    )

@register_check
def check_filevault():
    return command_check(
        name="filevault_enabled",
        command=["fdesetup", "status"],
        ok_patterns=["filevault is on"],
        fail_patterns=["filevault is off"],
        ok_message="FileVault est activé (Chiffrement disque)",
        fail_message="FileVault est désactivé"
    )

@register_check
def check_gatekeeper():
    # Note: spctl peut nécessiter des droits sudo pour un status précis
    return command_check(
        name="gatekeeper_enabled",
        command=["spctl", "--status"],
        ok_patterns=["assessments enabled"],
        fail_patterns=["assessments disabled"],
        ok_message="Gatekeeper est activé",
        fail_message="Gatekeeper est désactivé"
    )

@register_check
def check_sip():
    return command_check(
        name="sip_enabled",
        command=["csrutil", "status"],
        ok_patterns=["enabled"],
        fail_patterns=["disabled"],
        ok_message="System Integrity Protection (SIP) est activé",
        fail_message="System Integrity Protection (SIP) est désactivé ou partiel"
    )

@register_check
def check_xprotect():
    possible_paths = [
        "/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    ]

    found_path = next((Path(p) for p in possible_paths if Path(p).exists()), None)

    if not found_path:
        return CheckResult(
            name="xprotect_present",
            status="fail",
            message="XProtect bundle introuvable"
        )

    try:
        with open(found_path, "rb") as f:
            plist_data = plistlib.load(f)

        version = plist_data.get("CFBundleShortVersionString", "Inconnue")
        return CheckResult(
            name="xprotect_status",
            status="ok",
            message=f"XProtect actif (Version {version})"
        )
    except Exception as e:
        return CheckResult(
            name="xprotect_status",
            status="error",
            message=f"Erreur lecture XProtect : {e}"
        )

@register_check
def check_software_update():
    """Vérifie si les mises à jour automatiques sont configurées."""
    return command_check(
        name="auto_update",
        command=["softwareupdate", "--schedule"],
        ok_patterns=["on"],
        fail_patterns=["off"],
        ok_message="Vérification auto des mises à jour activée",
        fail_message="Vérification auto des mises à jour désactivée"
    )

def run_checks():
    """Exécute tous les checks enregistrés pour macOS."""
    return [check() for check in CHECKS]