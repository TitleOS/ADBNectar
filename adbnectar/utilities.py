import sys
import requests
import logging
import time

from config import CONFIG


logger = logging.getLogger(CONFIG.get('honeypot', 'hostname'))

class IPV4HostAddressInfo:
    def __init__(self, address, countryCode, organization):
        self.address = address,
        self.countryCode = countryCode
        self.organization = organization

    def __str__(self):
        return f"IPV4HostAddressInfo(address={self.address}, countryCode={self.countryCode}, organization={self.organization})"

class AnalysisResultStats:
    def __init__(self, malicious, suspicious, harmless, undetected, timeout, confirmed_timeout, failure, type_unsupported, identifer):
        self.malicious = malicious
        self.suspicious = suspicious
        self.harmless = harmless
        self.undetected = undetected
        self.timeout = timeout
        self.confirmed_timeout = confirmed_timeout
        self.failure = failure
        self.type_unsupported = type_unsupported
        self.identifer = identifer

    def __str__(self):
        return f"AnalysisResultStats {self.identifer} Detections: malicious={self.malicious}, suspicious={self.suspicious}, harmless={self.harmless}, undetected={self.undetected}, timeout={self.timeout}, confirmed_timeout={self.confirmed_timeout}, failure={self.failure}, type_unsupported={self.type_unsupported}"

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
        if response.status_code == 400:
            logger.warning(f"VirusTotal API returned an error for {apk_file} indicating the file may have been corrupted in transit. Retrying once.")
            response = requests.post(url, headers=headers, files=files)
            if response.status_code != 200:
                logger.error(f"Failed to submit {apk_file} to VirusTotal: {response.text}")
                return None
        else:
            analysis_id = response.json().get('data', {}).get('id')
            logger.info(f"Submitted {apk_file} to VirusTotal with analysis ID: {analysis_id}")
            analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/" + analysis_id, headers=headers)
            if analysis_response.status_code == 200:
                analysis_status = analysis_response.json().get('attributes', {}).get('status')
                while analysis_status == 'queued':
                    logger.info(f"Analysis for {apk_file} is still queued. Waiting for 30 seconds before checking again.")
                    time.sleep(30)
                    analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/" + analysis_id, headers=headers)
                    if analysis_response.json().get('attributes', {}).get('status') == 'queued':
                        analysis_status = 'queued'
                        continue
                    if analysis_response.json().get('attributes', {}).get('status') == 'completed':
                        analysis_status = 'completed'
                        logger.info(f"Analysis for {apk_file} completed.")
                completed_analysis = analysis_response.json()
                
                stats = AnalysisResultStats(completed_analysis.get('attributes', {}).get('stats', {}).get('malicious', 0),
                                            completed_analysis.get('attributes', {}).get('stats', {}).get('suspicious', 0),
                                            completed_analysis.get('attributes', {}).get('stats', {}).get('harmless', 0),
                                            completed_analysis.get('attributes', {}).get('stats', {}).get('undetected', 0),
                                            completed_analysis.get('attributes', {}).get('stats', {}).get('timeout', 0),
                                            completed_analysis.get('attributes', {}).get('stats', {}).get('confirmed_timeout', 0),
                                            completed_analysis.get('attributes', {}).get('stats', {}).get('failure', 0),
                                            completed_analysis.get('attributes', {}).get('stats', {}).get('type-unsupported', 0),
                                            analysis_id)
                if stats.malicious > 0 or stats.suspicious > 0:
                    logger.warning(f"APK {apk_file} has been flagged by VirusTotal. Malicious detections: {stats.malicious}, Suspicious detections: {stats.suspicious}.\nFull analysis report can be found at https://www.virustotal.com/gui/file/{analysis_id}/detection")
                else:
                    logger.info(f"APK {apk_file} has no malicious or suspicious detections.\nFull analysis report can be found at https://www.virustotal.com/gui/file/{analysis_id}/detection")


            else:
                logger.error(f"Failed to retrieve analysis for {apk_file}: {analysis_response.text}")
                return None
            