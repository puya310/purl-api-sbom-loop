import json
import requests
from urllib.parse import quote

api_key=f"enter api key" #ENTER YOUR API KEY - find in Snyk UI under your User Account name on bottom left -> Account Settings (consider using env variable if possible)
org_id=f"enter org id" #ENTER YOUR ORG ID - find in Snyk UI under Settings -> Organization ID 
json_file_path = 'bom1.json'  # PATH TO YOUR JSON file 
version=f"2024-05-23"

def extract_purls(json_data):
    purls = []
    
    def find_purls(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == 'purl':
                    purls.append(value)
                else:
                    find_purls(value)
        elif isinstance(obj, list):
            for item in obj:
                find_purls(item)
    
    find_purls(json_data)
    return purls

def get_issues(purl, org_id, api_key):
    encoded_purl = quote(purl, safe='')
    url = f"https://api.snyk.io/rest/orgs/{org_id}/packages/{encoded_purl}/issues?version=2024-05-23"
    headers = {
        'Authorization': f"token {api_key}",
        'Accept': 'application/vnd.api+json; charset=utf-8'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code, "message": response.text}

def main():
    output_file_path = 'api_results.json'
    
    with open(json_file_path, 'r') as file:
        json_data = json.load(file)
    
    purls = extract_purls(json_data)
    results = []
    
    for encoded_purl in purls:
        issues = get_issues(encoded_purl, org_id, api_key)
        results.append({encoded_purl: issues})

    with open(output_file_path, 'w') as outfile:
        json.dump(results, outfile, indent=2)

if __name__ == "__main__":
    main()
