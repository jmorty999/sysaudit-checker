import sys
from sysaudit.core.runner import run_audit
from sysaudit.core.util import is_admin, color_text
from sysaudit.outputs import console_writer, json_writer

def main():
    # 1. Petit check de bienvenue et de privilèges
    print(f"--- SysAudit Checker v1.0 ---")
    if not is_admin():
        print(color_text("[!] Attention: Droits limités. Lancez avec sudo/admin pour un audit complet.\n", "33"))

    # 2. Exécution de l'audit
    results = run_audit()

    if not results:
        print(color_text("[-] Aucun test n'a été effectué.", "31"))
        return

    # 3. Sortie console (toujours affichée)
    console_writer.write(results)

    # 4. Sortie JSON si l'argument --json est présent
    if "--json" in sys.argv:
        json_writer.write(results)

if __name__ == "__main__":
    main()