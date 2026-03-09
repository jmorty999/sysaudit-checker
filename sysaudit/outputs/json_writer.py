import json
def write(results):
#display results in a json file
    data = []

    for result in results:
        data.append({
            "name": result.name,
            "status": result.status,
            "message": result.message
        })

    print(json.dumps(data, indent=2, ensure_ascii=False))
