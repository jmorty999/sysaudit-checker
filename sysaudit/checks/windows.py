from sysaudit.core.models import CheckResult
from sysaudit.core.util import command_check, run_command

#checks must be validated on a windows env
def powershell_command(script: str) -> list[str]:
    return [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script
    ]


def check_firewall():
    return command_check(
        name="firewall_enabled",
        command=powershell_command(
            "(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) -join ','"
        ),
        ok_patterns=["true,true,true", "true, true, true"],
        fail_patterns=["false"],
        ok_message="Le pare-feu Windows est activé sur tous les profils",
        fail_message="Le pare-feu Windows n'est pas activé sur tous les profils"
    )


def check_defender():
    return command_check(
        name="defender_enabled",
        command=powershell_command(
            "(Get-MpComputerStatus).AntivirusEnabled"
        ),
        ok_patterns=["true"],
        fail_patterns=["false"],
        ok_message="Microsoft Defender Antivirus est activé",
        fail_message="Microsoft Defender Antivirus est désactivé"
    )


def check_bitlocker():
    returncode, output = run_command(
        powershell_command(
            "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"
        )
    )
    output_lower = output.lower()

    if returncode != 0:
        return CheckResult(
            name="bitlocker_enabled",
            status="error",
            message=f"Commande échouée : {output}"
        )

    if "1" in output_lower or "on" in output_lower:
        return CheckResult(
            name="bitlocker_enabled",
            status="ok",
            message="BitLocker est activé sur le disque système"
        )

    if "0" in output_lower or "off" in output_lower:
        return CheckResult(
            name="bitlocker_enabled",
            status="fail",
            message="BitLocker est désactivé sur le disque système"
        )

    return CheckResult(
        name="bitlocker_enabled",
        status="error",
        message=f"Réponse inattendue : {output}"
    )


def check_smartscreen():
    return command_check(
        name="smartscreen_enabled",
        command=powershell_command(
            "Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled"
        ),
        ok_patterns=["requireadmin", "warn"],
        fail_patterns=["off"],
        ok_message="SmartScreen est activé",
        fail_message="SmartScreen est désactivé"
    )


def check_windows_update():
    return command_check(
        name="windows_update_service_enabled",
        command=powershell_command(
            "(Get-Service wuauserv).StartType"
        ),
        ok_patterns=["automatic", "manual"],
        fail_patterns=["disabled"],
        ok_message="Le service Windows Update est disponible",
        fail_message="Le service Windows Update est désactivé"
    )


def run_checks():
    return [
        check_firewall(),
        check_defender(),
        check_bitlocker(),
        check_smartscreen(),
        check_windows_update()
    ]