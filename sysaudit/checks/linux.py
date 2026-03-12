import os
from sysaudit.core.models import CheckResult
from sysaudit.core.util import command_check, run_command, is_admin, require_admin

# Liste pour enregistrer automatiquement les fonctions de check
CHECKS = []

def register_check(func):
    CHECKS.append(func)
    return func

def _has_cmd(cmd):
    """Utilitaire interne pour vérifier si une commande existe."""
    rc, _ = run_command(["sh", "-c", f"command -v {cmd}"])
    return rc == 0

@register_check
def check_firewall():
    # 1. NFTABLES
    if _has_cmd("nft"):
        return command_check(
            name="firewall_nftables",
            command=["systemctl", "is-active", "nftables"],
            ok_patterns=["active"],
            fail_patterns=["inactive", "failed"],
            ok_message="Le firewall nftables est actif",
            fail_message="Le firewall nftables n'est pas actif"
        )

    # 2. UFW
    if _has_cmd("ufw"):
        return command_check(
            name="firewall_ufw",
            command=["ufw", "status"],
            ok_patterns=["status: active"],
            fail_patterns=["status: inactive"],
            ok_message="Le firewall UFW est actif",
            fail_message="Le firewall UFW est inactif"
        )

    # 3. FIREWALLD
    if _has_cmd("firewall-cmd"):
        return command_check(
            name="firewall_firewalld",
            command=["systemctl", "is-active", "firewalld"],
            ok_patterns=["active"],
            fail_patterns=["inactive", "failed"],
            ok_message="Le firewall firewalld est actif",
            fail_message="Le firewall firewalld n'est pas actif"
        )

    return CheckResult(
        name="firewall_enabled",
        status="error",
        message="Aucun outil de firewall reconnu (nft, ufw, firewalld)"
    )

@register_check
def check_selinux():
    if not _has_cmd("getenforce"):
        return CheckResult(name="selinux", status="info", message="SELinux non disponible")

    return command_check(
        name="selinux_mode",
        command=["getenforce"],
        ok_patterns=["Enforcing"],
        fail_patterns=["Permissive", "Disabled"],
        ok_message="SELinux est en mode Enforcing",
        fail_message="SELinux n'est pas restrictif"
    )

@register_check
def check_apparmor():
    path = "/sys/module/apparmor/parameters/enabled"
    if not os.path.exists(path):
        return CheckResult(name="apparmor", status="info", message="AppArmor non disponible")

    try:
        with open(path, "r") as f:
            enabled = f.read().strip().lower() in ("y", "1")

        return CheckResult(
            name="apparmor_enabled",
            status="ok" if enabled else "fail",
            message="AppArmor est activé" if enabled else "AppArmor est désactivé"
        )
    except Exception as e:
        return CheckResult(name="apparmor", status="error", message=f"Erreur lecture AppArmor: {e}")

@register_check
def check_automatic_updates():
    # Test pour Debian/Ubuntu (APT)
    apt_conf = "/etc/apt/apt.conf.d/20auto-upgrades"
    if os.path.exists(apt_conf):
        try:
            with open(apt_conf, "r") as f:
                content = f.read()
            enabled = 'APT::Periodic::Unattended-Upgrade "1"' in content
            return CheckResult(
                name="updates_apt",
                status="ok" if enabled else "fail",
                message="Mises à jour APT auto activées" if enabled else "Mises à jour APT auto désactivées"
            )
        except Exception: pass

    # Test pour RHEL/Fedora (DNF)
    if _has_cmd("dnf"):
        return command_check(
            name="updates_dnf",
            command=["systemctl", "is-enabled", "dnf-automatic.timer"],
            ok_patterns=["enabled"],
            fail_patterns=["disabled"],
            ok_message="Mises à jour DNF auto activées",
            fail_message="Mises à jour DNF auto désactivées"
        )

    return CheckResult(name="updates_auto", status="info", message="Gestionnaire d'auto-updates non détecté")

@register_check
def check_ssh_root_login():
    if not _has_cmd("sshd"):
        return CheckResult(name="ssh_root", status="info", message="Service SSH non détecté")

    # Utilisation de sshd -T (nécessite souvent les droits root pour lire les clés d'hôte)
    rc, output = run_command(["sshd", "-T"])
    if rc != 0:
        # Si échec, on tente un parsing manuel ou on demande les droits
        if not is_admin():
            return require_admin("ssh_root_login")
        return CheckResult(name="ssh_root", status="error", message="Erreur lors de l'appel à sshd -T")

    for line in output.splitlines():
        if line.lower().startswith("permitrootlogin"):
            value = line.split()[-1].lower()
            if value == "no":
                return CheckResult(name="ssh_root", status="ok", message="Accès Root SSH interdit (Sécurisé)")
            return CheckResult(name="ssh_root", status="fail", message=f"Accès Root SSH autorisé ({value})")

    return CheckResult(name="ssh_root", status="info", message="Paramètre PermitRootLogin introuvable")

@register_check
def check_critical_users():
    # 1. Vérifier les UID 0 (Root déguisé)
    rc, output = run_command(["sh", "-c", "cut -d: -f1,3 /etc/passwd | grep ':0$'"])
    users = [line.split(':')[0] for line in output.splitlines() if line]

    if len(users) > 1:
        return CheckResult(
            name="extra_root_users",
            status="fail",
            message=f"Comptes avec UID 0 détectés : {', '.join(users)}"
        )

    # 2. Vérifier les mots de passe vides (nécessite impérativement root)
    if not is_admin():
        return require_admin("empty_passwords")

    rc, shadow_out = run_command(["awk", "-F:", '($2 == "" ) { print $1 }', "/etc/shadow"])
    if rc == 0 and shadow_out:
        return CheckResult(
            name="empty_passwords",
            status="fail",
            message=f"Comptes sans mot de passe : {shadow_out.strip()}"
        )

    return CheckResult(name="user_audit", status="ok", message="Audit des utilisateurs sain")

@register_check
def check_open_ports():
    # ss fonctionne sans root pour le TCP basique, mais root est mieux pour voir les noms de processus
    rc, output = run_command(["ss", "-ltun"])
    if rc != 0:
        return CheckResult(name="open_ports", status="error", message="Impossible de lister les ports")

    ports_count = len(output.splitlines()) - 1
    critical_ports = []
    for p in ["21", "23", "445"]:
        if f":{p} " in output:
            critical_ports.append(p)

    if critical_ports:
        return CheckResult(
            name="critical_ports",
            status="fail",
            message=f"Ports dangereux ouverts : {', '.join(critical_ports)}"
        )

    return CheckResult(name="open_ports", status="info", message=f"{ports_count} ports en écoute détectés")

@register_check
def check_world_writable_files():
    # Pas besoin d'être root pour chercher, mais root évite les erreurs "Permission denied" durant le scan
    cmd = "find /etc /bin /sbin -type f -perm -0002 2>/dev/null"
    rc, output = run_command(["sh", "-c", cmd])

    files = output.splitlines()
    if files:
        return CheckResult(
            name="world_writable_files",
            status="fail",
            message=f"{len(files)} fichiers modifiables par TOUS dans les dossiers système"
        )

    return CheckResult(name="permissions_audit", status="ok", message="Aucun fichier 777 critique trouvé")

@register_check
def check_integrity_binaries():
    # debsums nécessite souvent root pour accéder aux fichiers de contrôle
    if not is_admin():
        return require_admin("integrity_check")

    if _has_cmd("debsums"):
        rc, output = run_command(["debsums", "-s", "/bin/ls", "/bin/ps", "/bin/login"])
        if rc != 0:
            return CheckResult(name="integrity_check", status="fail", message="Altération détectée sur des binaires vitaux !")
    elif _has_cmd("rpm"):
        rc, output = run_command(["rpm", "-Vf", "/bin/ls"])
        if rc != 0:
            return CheckResult(name="integrity_check", status="fail", message="L'empreinte de /bin/ls ne correspond pas")
    else:
        return CheckResult(name="integrity_check", status="info", message="Outil d'intégrité (debsums/rpm) manquant")

    return CheckResult(name="integrity_check", status="ok", message="Binaires système intègres")

def run_checks():
    """Lance tous les checks enregistrés via le décorateur."""
    return [check_func() for check_func in CHECKS]