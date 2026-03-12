import importlib
import logging
from sysaudit.core.os_detect import detect_os

def run_audit():
    """
    Détecte l'OS et exécute les checks correspondants de manière dynamique.
    """
    os_name = detect_os()

    # Dictionnaire de correspondance entre l'OS et le module de checks
    os_modules = {
        "macos": "sysaudit.checks.macos",
        "linux": "sysaudit.checks.linux",
        "windows": "sysaudit.checks.windows"
    }

    if os_name not in os_modules:
        print(f"[-] OS non supporté : {os_name}")
        return []

    try:
        # Import dynamique du module spécifique à l'OS
        module_path = os_modules[os_name]
        check_module = importlib.import_module(module_path)

        # On appelle la fonction run_checks() du module chargé
        if hasattr(check_module, "run_checks"):
            return check_module.run_checks()
        else:
            print(f"[-] Erreur : Le module {module_path} n'a pas de fonction run_checks()")
            return []

    except ImportError as e:
        print(f"[-] Impossible de charger les checks pour {os_name} : {e}")
        return []
    except Exception as e:
        print(f"[-] Une erreur inattendue est survenue lors de l'audit : {e}")
        return []