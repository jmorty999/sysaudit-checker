import os

from sysaudit.core.models import CheckResult
from sysaudit.core.util import command_check, run_command
#checks must be validated on a linux env

def check_firewall():
    nft_returncode, nft_output = run_command(["sh", "-c", "command -v nft"])
    if nft_returncode == 0 and nft_output:
        return command_check(
            name="firewall_enabled",
            command=["systemctl", "is-active", "nftables"],
            ok_patterns=["active"],
            fail_patterns=["inactive", "failed"],
            ok_message="Le firewall nftables est actif",
            fail_message="Le firewall nftables n'est pas actif"
        )

    ufw_returncode, ufw_output = run_command(["sh", "-c", "command -v ufw"])
    if ufw_returncode == 0 and ufw_output:
        return command_check(
            name="firewall_enabled",
            command=["ufw", "status"],
            ok_patterns=["status: active"],
            fail_patterns=["status: inactive"],
            ok_message="Le firewall UFW est actif",
            fail_message="Le firewall UFW est inactif"
        )

    firewalld_returncode, firewalld_output = run_command(["sh", "-c", "command -v firewall-cmd"])
    if firewalld_returncode == 0 and firewalld_output:
        return command_check(
            name="firewall_enabled",
            command=["systemctl", "is-active", "firewalld"],
            ok_patterns=["active"],
            fail_patterns=["inactive", "failed"],
            ok_message="Le firewall firewalld est actif",
            fail_message="Le firewall firewalld n'est pas actif"
        )

    return CheckResult(
        name="firewall_enabled",
        status="error",
        message="Aucun outil de firewall connu détecté (nftables, ufw, firewalld)"
    )


def check_selinux():
    returncode, output = run_command(["sh", "-c", "command -v getenforce"])
    if returncode != 0 or not output:
        return CheckResult(
            name="selinux_enabled",
            status="info",
            message="SELinux non disponible sur ce système"
        )

    return command_check(
        name="selinux_enabled",
        command=["getenforce"],
        ok_patterns=["enforcing"],
        fail_patterns=["disabled", "permissive"],
        ok_message="SELinux est actif en mode enforcing",
        fail_message="SELinux n'est pas en mode enforcing"
    )


def check_apparmor():
    if not os.path.exists("/sys/module/apparmor/parameters/enabled"):
        return CheckResult(
            name="apparmor_enabled",
            status="info",
            message="AppArmor non disponible sur ce système"
        )

    try:
        with open("/sys/module/apparmor/parameters/enabled", "r", encoding="utf-8") as file:
            value = file.read().strip().lower()

        if value in ("y", "yes", "1"):
            return CheckResult(
                name="apparmor_enabled",
                status="ok",
                message="AppArmor est activé"
            )

        return CheckResult(
            name="apparmor_enabled",
            status="fail",
            message="AppArmor est désactivé"
        )

    except Exception as error:
        return CheckResult(
            name="apparmor_enabled",
            status="error",
            message=f"Impossible de vérifier AppArmor : {error}"
        )


def check_automatic_updates():
    if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
        try:
            with open("/etc/apt/apt.conf.d/20auto-upgrades", "r", encoding="utf-8") as file:
                content = file.read().lower()

            if 'apt::periodic::unattended-upgrade "1"' in content:
                return CheckResult(
                    name="automatic_updates_enabled",
                    status="ok",
                    message="Les mises à jour automatiques APT sont activées"
                )

            return CheckResult(
                name="automatic_updates_enabled",
                status="fail",
                message="Les mises à jour automatiques APT sont désactivées"
            )

        except Exception as error:
            return CheckResult(
                name="automatic_updates_enabled",
                status="error",
                message=f"Impossible de lire la configuration APT : {error}"
            )

    dnf_returncode, dnf_output = run_command(["sh", "-c", "command -v dnf"])
    if dnf_returncode == 0 and dnf_output:
        return command_check(
            name="automatic_updates_enabled",
            command=["systemctl", "is-enabled", "dnf-automatic.timer"],
            ok_patterns=["enabled"],
            fail_patterns=["disabled"],
            ok_message="Les mises à jour automatiques DNF sont activées",
            fail_message="Les mises à jour automatiques DNF sont désactivées"
        )

    return CheckResult(
        name="automatic_updates_enabled",
        status="info",
        message="Gestionnaire de mises à jour automatiques non reconnu"
    )


def check_ssh_root_login():
    sshd_config = "/etc/ssh/sshd_config"

    if not os.path.exists(sshd_config):
        return CheckResult(
            name="ssh_root_login_disabled",
            status="info",
            message="OpenSSH n'est pas installé ou sshd_config est absent"
        )

    try:
        with open(sshd_config, "r", encoding="utf-8") as file:
            lines = file.readlines()

        effective_value = None

        for raw_line in lines:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() == "permitrootlogin":
                effective_value = parts[1].lower()

        if effective_value in ("no",):
            return CheckResult(
                name="ssh_root_login_disabled",
                status="ok",
                message="La connexion SSH root est désactivée"
            )

        if effective_value in ("yes", "prohibit-password", "forced-commands-only", "without-password"):
            return CheckResult(
                name="ssh_root_login_disabled",
                status="fail",
                message="La connexion SSH root n'est pas totalement désactivée"
            )

        return CheckResult(
            name="ssh_root_login_disabled",
            status="info",
            message="Directive PermitRootLogin absente ou non interprétable"
        )

    except Exception as error:
        return CheckResult(
            name="ssh_root_login_disabled",
            status="error",
            message=f"Impossible de lire sshd_config : {error}"
        )


def run_checks():
    return [
        check_firewall(),
        check_selinux(),
        check_apparmor(),
        check_automatic_updates(),
        check_ssh_root_login()
    ]