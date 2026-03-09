def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"


def format_status(status):
    if status == "ok":
        return color_text("OK", "32")
    if status == "fail":
        return color_text("FAIL", "31")
    if status == "error":
        return color_text("ERROR", "33")
    if status == "info":
        return color_text("INFO", "34")
    return status.upper()


def write(results):
    ok_count = 0
    fail_count = 0
    error_count = 0
    info_count = 0

    for result in results:
        formatted_status = format_status(result.status)
        print(f"[{formatted_status}] {result.name} - {result.message}")

        if result.status == "ok":
            ok_count += 1
        elif result.status == "fail":
            fail_count += 1
        elif result.status == "error":
            error_count += 1
        elif result.status == "info":
            info_count += 1

    total_checks = len(results)
    score = ok_count

    print()
    print("Résumé :")
    print(f"  OK    : {ok_count}")
    print(f"  FAIL  : {fail_count}")
    print(f"  ERROR : {error_count}")
    print(f"  INFO  : {info_count}")
    print()
    print(f"Score sécurité : {score} / {total_checks}")