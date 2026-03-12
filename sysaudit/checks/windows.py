from sysaudit.core.models import CheckResult
from sysaudit.core.util import command_check, run_command, is_admin, require_admin

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
    if not is_admin():
        return require_admin("bitlocker")

    rc, output = run_command(
        powershell_command("(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus")
    )

    if rc != 0:
        return CheckResult(name="bitlocker", status="error", message=f"Erreur d'accès BitLocker : {output}")

    clean_output = output.strip()
    if clean_output == "1":
        return CheckResult(name="bitlocker", status="ok", message="BitLocker est activé sur C:")

    return CheckResult(name="bitlocker", status="fail", message="BitLocker est désactivé sur C:")

@register_check
def check_smartscreen():
    if not is_admin():
        return require_admin("smartscreen")

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
    return command_check(
        name="windows_update_service",
        command=powershell_command("(Get-Service wuauserv).StartType"),
        ok_patterns=["Automatic", "Manual"],
        fail_patterns=["Disabled"],
        ok_message="Le service Windows Update est opérationnel",
        fail_message="Le service Windows Update est désactivé"
    )

@register_check
def check_admin_users():
    if not is_admin():
        return require_admin("admin_accounts")

    script = "Get-LocalGroupMember -Group 'Administrateurs' | Select-Object -ExpandProperty Name"
    rc, output = run_command(powershell_command(script))
    admins = [line.strip() for line in output.splitlines() if line]

    if len(admins) > 2:
        return CheckResult(name="admin_accounts", status="warn", message=f"Nombre élevé d'admins : {', '.join(admins)}")
    return CheckResult(name="admin_accounts", status="ok", message=f"Admins identifiés : {len(admins)}")

@register_check
def check_open_ports():
    # Nécessite souvent d'être admin pour voir l'intégralité des connexions système
    script = "Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique"
    rc, output = run_command(powershell_command(script))
    ports = output.splitlines()

    critical = [p for p in ["21", "23", "445", "3389"] if p in ports]
    if critical:
        return CheckResult(name="open_ports", status="fail", message=f"Ports sensibles ouverts : {', '.join(critical)}")
    return CheckResult(name="open_ports", status="info", message=f"{len(ports)} ports TCP en écoute")

@register_check
def check_unquoted_service_paths():
    if not is_admin():
        return require_admin("unquoted_paths")

    script = 'Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName -notlike "*`""* -and $_.PathName -like "* *" } | Select-Object -ExpandProperty Name'
    rc, output = run_command(powershell_command(script))

    if output.strip():
        return CheckResult(name="unquoted_paths", status="fail", message=f"Services vulnérables détectés : {output.strip()}")
    return CheckResult(name="unquoted_paths", status="ok", message="Aucun Unquoted Service Path trouvé")

def run_checks():
    """Exécute tous les tests Windows enregistrés."""
    return [check() for check in CHECKS]