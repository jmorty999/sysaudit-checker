import json
from datetime import datetime
from sysaudit.core.os_detect import detect_os

def write(results, to_file=True, filename="audit_report.json"):
    """
    Formate les résultats en JSON avec métadonnées et résumé.
    """
    # Construction de la structure de données
    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "os_detected": detect_os(),
            "tool_version": "1.0.0"
        },
        "summary": {
            "total_checks": len(results),
            "ok": len([r for r in results if r.status == "ok"]),
            "fail": len([r for r in results if r.status == "fail"]),
            "error": len([r for r in results if r.status == "error"]),
            "info": len([r for r in results if r.status == "info"]),
        },
        "results": []
    }

    # Remplissage des résultats
    for result in results:
        report["results"].append({
            "name": result.name,
            "status": result.status,
            "message": result.message
        })

    # Conversion en chaîne JSON
    json_output = json.dumps(report, indent=4, ensure_ascii=False)

    # Affichage console
    print("\n[+] Rapport d'audit généré au format JSON.")

    # Écriture dans un fichier
    if to_file:
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"[+] Rapport sauvegardé dans : {filename}")
        except Exception as e:
            print(f"[-] Erreur lors de l'écriture du fichier : {e}")

    return json_output