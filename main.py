from sysaudit.core.runner import run_audit
from sysaudit.outputs.console_writer import write


def main():
    results = run_audit()
    write(results)


if __name__ == "__main__":
    main()