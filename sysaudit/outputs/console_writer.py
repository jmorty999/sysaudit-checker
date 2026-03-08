def write(results):
#format and display the results
    for result in results:
        print(f"[{result.status}] {result.name} - {result.message}")
