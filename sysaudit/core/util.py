import subprocess


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = (result.stdout or result.stderr).strip()
        return result.returncode, output

    except FileNotFoundError:
        return 127, "Commande introuvable"
    except Exception as error:
        return 1, str(error)