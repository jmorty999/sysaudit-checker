import os
import sys

# Active les couleurs ANSI sur Windows si nécessaire
if sys.platform == "win32":
    os.system('color')

def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def format_status(status):
    status_map = {
        "ok": ("OK", "32"),      # Vert
        "fail": ("FAIL", "31"),    # Rouge
        "error": ("ERROR", "35"),   # Magenta (plus distinct que le jaune)
        "info": ("INFO", "36"),    # Cyan
        "warning": ("WARN", "33")   # Jaune
    }
    label, color = status_map.get(status.lower(), (status.upper(), "37"))
    return color_text(f"{label:<7}", color)

def write(results):
    if not results:
        print(color_text("[-] Aucun résultat à afficher.", "31"))
        return

    print(f"\n{'='*60}")
    print(f"{'RÉSULTATS DE L''AUDIT SYSTÈME':^60}")
    print(f"{'='*60}\n")

    counts = {"ok": 0, "fail": 0, "error": 0, "info": 0, "warning": 0}

    for result in results:
        counts[result.status.lower()] = counts.get(result.status.lower(), 0) + 1

        status_str = format_status(result.status)
        # On aligne le nom du test sur 30 caractères pour un rendu propre
        print(f"[{status_str}] {result.name:<30} | {result.message}")

    total = len(results)
    # On ne compte pas les 'info' dans le score pour ne pas le fausser
    relevant_checks = total - counts.get("info", 0)
    score_percent = (counts['ok'] / relevant_checks * 100) if relevant_checks > 0 else 0

    print(f"\n{'-'*60}")
    print(f" Résumé :")
    print(f"  {color_text('✔ OK', '32')}: {counts['ok']}  |  {color_text('✖ FAIL', '31')}: {counts['fail']}  |  {color_text('⚠ ERR', '35')}: {counts['error']}")
    print(f"  {color_text('ℹ INFO', '36')}: {counts['info']}")
    print(f"{'-'*60}")

    # Affichage du score avec couleur dynamique
    score_color = "32" if score_percent >= 80 else "33" if score_percent >= 50 else "31"
    print(f" NOTE GLOBALE : {color_text(f'{score_percent:.1f}%', score_color)} ({counts['ok']}/{relevant_checks} checks critiques réussis)")
    print(f"{'='*60}\n")