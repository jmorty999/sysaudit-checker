import os
import plistlib
from pathlib import Path

from sysaudit.core.models import CheckResult
from sysaudit.core.util import command_check, run_command, is_admin, require_admin

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
    # Nécessite souvent d'être admin pour interroger le statut de chiffrement proprement
    if not is_admin():
        return require_admin("filevault_enabled")

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
    # Sur les versions récentes de macOS, spctl sans privilèges peut être imprécis
    if not is_admin():
        return require_admin("gatekeeper_enabled")

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
    # csrutil peut être lancé en utilisateur normal
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
    return command_check(
        name="auto_update",
        command=["softwareupdate", "--schedule"],
        ok_patterns=["on"],
        fail_patterns=["off"],
        ok_message="Vérification auto des mises à jour activée",
        fail_message="Vérification auto des mises à jour désactivée"
    )

@register_check
def check_admin_accounts():
    rc, output = run_command(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
    if rc != 0:
        return CheckResult(name="admin_users", status="error", message="Impossible de lire les groupes admin")

    admins = output.replace("GroupMembership:", "").strip().split()
    if "root" in admins: admins.remove("root")

    return CheckResult(
        name="admin_users",
        status="info",
        message=f"Utilisateurs admin (hors root) : {', '.join(admins)}"
    )

@register_check
def check_listening_ports():
    # lsof sans root ne montre que les processus de l'utilisateur actuel.
    # Pour un audit système, root est obligatoire pour voir TOUS les ports.
    if not is_admin():
        return require_admin("network_ports")

    rc, output = run_command(["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"])
    lines = output.splitlines()[1:]

    if not lines:
        return CheckResult(name="network_ports", status="ok", message="Aucun port TCP en écoute")

    return CheckResult(name="network_ports", status="info", message=f"{len(lines)} services réseau en écoute")

@register_check
def check_world_writable_system():
    # Nécessite root pour scanner les dossiers protégés sans erreurs de permission
    if not is_admin():
        return require_admin("writable_system")

    cmd = "find /Library/LaunchAgents /Library/LaunchDaemons -type f -perm -0002 2>/dev/null"
    rc, output = run_command(["sh", "-c", cmd])
    files = output.splitlines()

    if files:
        return CheckResult(name="writable_system", status="fail", message=f"{len(files)} fichiers système modifiables par tous")
    return CheckResult(name="writable_system", status="ok", message="Permissions système saines")

def run_checks():
    """Exécute tous les checks enregistrés pour macOS."""
    return [check() for check in CHECKS]