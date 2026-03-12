import platform

def detect_os() -> str:
    """
    Identifie le système d'exploitation actuel et retourne un identifiant normalisé.
    
    Returns:
        str: 'macos', 'linux', 'windows' ou 'unknown'.
    """
    # platform.system() renvoie généralement 'Darwin', 'Linux', or 'Windows'
    system = platform.system().lower()

    # Utilisation d'un dictionnaire pour un mapping propre
    os_map = {
        "darwin": "macos",
        "linux": "linux",
        "windows": "windows"
    }

    # On récupère la valeur, 'unknown' par défaut si l'OS n'est pas dans le dictionnaire
    detected = os_map.get(system, "unknown")

    # Optionnel : Si c'est du Linux, on pourrait plus tard vouloir détecter la distro 
    # via platform.freedesktop_os_release() pour affiner les checks.

    return detected