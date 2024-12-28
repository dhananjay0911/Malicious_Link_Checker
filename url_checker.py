import requests
import base64

def check_url(url):
    API_KEY="6bbb51c6e8a4b128d11c75734349ba50b616d98f2a4fd91f96dbb04bb33cadf0"
    API_URL="https://www.virustotal.com/api/v3/urls/"

    encoded_url=base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers={"x-apikey":API_KEY}

    try:
        response=requests.get(f"{API_URL}{encoded_url}",headers=headers)

        if response.status_code==200:
            data=response.json()
            malicious=data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0)

            if malicious>0:
                return f"Warning: {malicious} malicious detections found!"
            else:
                return "No malicious activity detected.The URl is safe."
        else:
            return f"Error: API request failed with status code {response.status_code}"
    except Exception as e:
        return f"Error:{e}"    