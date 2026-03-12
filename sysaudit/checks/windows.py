from sysaudit.core.models import CheckResult
from sysaudit.core.util import command_check, run_command

CHECKS = []

def register_check(func):
    CHECKS.append(func)
    return func

def powershell_command(script: str) -> list[str]:
    """Prépare une commande PowerShell propre."""
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"$ProgressPreference = 'SilentlyContinue'; {script}"
    ]

@register_check
def check_firewall():
    # On vérifie s'il existe au moins un profil désactivé
    return command_check(
        name="firewall_enabled",
        command=powershell_command(
            "if ((Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'False'})) { 'fail' } else { 'ok' }"
        ),
        ok_patterns=["ok"],
        fail_patterns=["fail"],
        ok_message="Tous les profils du pare-feu Windows sont actifs",
        fail_message="Au moins un profil du pare-feu Windows est désactivé"
    )

@register_check
def check_defender():
    return command_check(
        name="defender_enabled",
        command=powershell_command("(Get-MpComputerStatus).AntivirusEnabled"),
        ok_patterns=["True"],
        fail_patterns=["False"],
        ok_message="Microsoft Defender Antivirus est activé",
        fail_message="Microsoft Defender Antivirus est désactivé"
    )

@register_check
def check_bitlocker():
    # Vérification du statut de protection (1 = On, 0 = Off)
    rc, output = run_command(
        powershell_command("(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus")
    )

    if rc != 0:
        return CheckResult(
            name="bitlocker_status",
            status="error",
            message="Erreur (Droits insuffisants ? Lancer en tant qu'Admin)"
        )

    clean_output = output.strip()
    if clean_output == "1":
        return CheckResult(name="bitlocker", status="ok", message="BitLocker est activé sur C:")

    return CheckResult(name="bitlocker", status="fail", message="BitLocker est désactivé sur C:")

@register_check
def check_smartscreen():
    # Vérifie le registre pour SmartScreen
    return command_check(
        name="smartscreen_enabled",
        command=powershell_command(
            "Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled"
        ),
        ok_patterns=["RequireAdmin", "Warn"],
        fail_patterns=["Off"],
        ok_message="SmartScreen est configuré (Safe)",
        fail_message="SmartScreen est désactivé"
    )

@register_check
def check_windows_update():
    # Vérifie si le service n'est pas désactivé
    return command_check(
        name="windows_update_service",
        command=powershell_command("(Get-Service wuauserv).StartType"),
        ok_patterns=["Automatic", "Manual"],
        fail_patterns=["Disabled"],
        ok_message="Le service Windows Update est opérationnel",
        fail_message="Le service Windows Update est désactivé"
    )

def run_checks():
    """Exécute tous les tests Windows enregistrés."""
    return [check() for check in CHECKS]