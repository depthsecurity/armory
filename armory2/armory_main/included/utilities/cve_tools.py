import pdb
import time
import html
import requests


def get_cve_data(cve, proxies={}, quiet=False):

    temporal_score, description = get_cve_data_api(cve, proxies, quiet)
    if temporal_score == 0.0:
        temp_score, descr = get_cve_data_legacy(cve, proxies, quiet)
        if temp_score > 0.0:
            temporal_score = temp_score
            description = descr
    return temporal_score, description

def clean(str):
    str = str.replace('\xc2', ' ').replace('\xa0', ' ').replace('\n', ' ').replace('\r', ' ')
    while '  ' in str:
        str = str.replace('  ', ' ')
    
    str = html.unescape(str)

    return str
def get_cve_data_legacy(cve, proxies, quiet=False):

    url = "https://nvd.nist.gov/vuln/detail/{}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    res = requests.get(url.format(cve), proxies=proxies, verify=False, headers=headers).text
    
    try:
        cveDescription = clean(res.split('<p data-testid="vuln-description">')[1].split(
            "</p>"
        )[0])
        if not quiet:
            print(f"Legacy description: {cveDescription}")
    except:
        return 0.0, ""

    # pdb.set_trace()
    # if 'vuln-cvss3-base-score' in res:
    #     cvss = float(res.split('<span data-testid="vuln-cvss3-base-score">')[1].split('</span>')[0].strip())
    # else:
    #     cvss = float(res.split('<span data-testid="vuln-cvss2-base-score">')[1].split('</span>')[0].strip())
    try:
        cvss = float(res.split("Base Score:")[1].split(" ")[3].split(";")[-1])
    except:
        try:
            cvss = float(res.split("Base Score:")[1].split(" ")[2].split(";")[-1])
        except:
            cvss = 0.0
    return cvss, cveDescription

def get_cve_data_api(cve, proxies, quiet=False):

    url = f"https://cveawg.mitre.org/api/cve/{cve}"

    try:
        #print(f"[*] Trying to request data for {cve}")
        
        res = requests.get(url, proxies=proxies, verify=False)
        res_code = res.status_code

        #retry logic
        if res_code != 200:
            ## if API returns a 404 then it's not in the database so just skip immediately
            if res_code == 404:
                if not quiet:
                    print(f"[-] Error getting {cve} data, received HTTP {res_code} - CVE not found in API")
                return 0.0, ""
            if not quiet:
                print(f"[-] Error getting {cve} data, received HTTP {res_code} - sleeping 30 seconds before retrying")
            time.sleep(30)
            if not quiet:
                print(f"[*] Retrying request for {cve}")
            res = requests.get(url, proxies=proxies, verify=False)
            res_code = res.status_code
            if res_code == 200:
                #print(f"[+] Got {cve} data")
                res = res.json()
            else:
                if not quiet:
                    print(f"[-] Could not get data for CVE {cve} - skipping")
                return 0.0, ""

        else:
            #print(f"[+] Got {cve} data")
            res = res.json()
            
        cve_description = ""
        rating = ""
        base_score = 0.0

        # get the cve description and remove newlines
        for desc in res["containers"]["cna"]["descriptions"]:
            if 'en' in desc["lang"]:
                cve_description = clean(desc["value"])
                if not quiet:
                    print(f"New desc: {cve_description}")
        # check to see if metrics are in the response
        if "metrics" in res["containers"]["cna"]:
            # try to get cvss data starting from v4 down
            cvvs = res["containers"]["cna"]["metrics"][0].get("cvssV4_0", None)
            if not cvvs:
                cvvs = res["containers"]["cna"]["metrics"][0].get("cvssV3_1", None)
            if not cvvs:
                cvvs = res["containers"]["cna"]["metrics"][0].get("cvssV3_0", None)
            if not cvvs:
                cvvs = res["containers"]["cna"]["metrics"][0].get("cvssV2_0", None)
            
            # if there's no cvss data try to get the rating text instead
            if not cvvs:
                rating = res["containers"]["cna"]["metrics"][0]["other"]["content"]["text"]
                cve_description = f"Rating: {rating.lower()} - " + cve_description

            # get the cvss score
            if not rating:
                base_score = cvvs["baseScore"]

        if not cve_description:
            cve_description = f"No CVE description found."
        return base_score, cve_description
        
            
        
    except Exception as e:
        if not quiet:
            print(f"[-] Error processing data for {cve}: {e}")
        return 0.0, ""