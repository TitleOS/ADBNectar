import sys
import requests

class IPV4HostAddressInfo:
    def __init__(self, address, countryCode, organization):
        self.address = address,
        self.countryCode = countryCode
        self.organization = organization

    def __str__(self):
        return f"IPV4HostAddressInfo(address={self.address}, countryCode={self.countryCode}, organization={self.organization})"

def get_ipv4_host_address_info(ipv4_address):
    """
    Retrieves information about an IPv4 address using the ipinfo.io API.
    
    :param ipv4_address: The IPv4 address to look up.
    :return: An instance of IPV4HostAddressInfo containing the address, country code, and organization.
    """
    
    url = f"https://ipinfo.io/{ipv4_address}/json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        return IPV4HostAddressInfo(
            address=data.get('ip'),
            countryCode=data.get('country'),
            organization=data.get('org')
        )
        
    except requests.RequestException as e:
        print(f"Error fetching data for {ipv4_address}: {e}", file=sys.stderr)
        return None

# WIP
# Submit an APK file to VirusTotal for analysis    
def submit_sample_to_VT(apk_file, vt_api_key):
    """
    Submits an APK file to VirusTotal for analysis.
    
    :param apk_file: Path to the APK file to be submitted.
    :param vt_api_key: Your VirusTotal API key.
    :return: The response from the VirusTotal API.
    """

    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": vt_api_key
    }
    
    with open(apk_file, 'rb') as f:
        files = {'file': f}
        response = requests.post(url, headers=headers, files=files)
    
    return response.json()