import socket
import urllib
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
import requests
import whois
from bs4 import BeautifulSoup
import urllib.request
import json
import re
import pickle
import random






def has_ip(url):
    try:
        socket.inet_aton(url)
        return 1
    except socket.error:
        return 0



def has_long_url(url):
    parsed_url = urlparse(url)
    if len(url) < 54:
        return -1
    elif len(url) >= 54 and len(url) <= 75:
        return 0
    else:
        return 1

def has_short_service(url):
    parsed_url = urlparse(url)
    if len(parsed_url.netloc) < 20:
        return 1
    else:
        return 0
    
def has_at(url):
    parsed_url = urlparse(url)
    if "@" in parsed_url.netloc:
        return 1
    else:
        return 0
    
def has_redirect(url):
    parsed_url = urlparse(url)
    if "//" in parsed_url.path:
        return 1
    else:
        return 0
    
def has_pref(url):
    parsed_url = urlparse(url)
    if "-" in parsed_url.netloc:
        return 1
    else:
        return -1
    


def subdomain_type(url):
    parsed_url = urlparse(url)
    if parsed_url.hostname.count(".") == 1:
        return -1
    elif parsed_url.hostname.count(".") == 2:
        return 0
    else:
        return 1
    


def ssl_type(url):
    hostname = url.split('/')[2]
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            if cert['issuer'][0][0] == 'C' and cert['notAfter'] > (datetime.datetime.now() + datetime.timedelta(days=365)):
                return -1
            elif cert['issuer'][0][0] != 'C':
                return 0
            else:
                return 1
            



# def long_domain_type(url):
#     domain = url.split('/')[2]
#     w = whois.whois(domain)
#     if w.expiration_date is None:
#         return -0
#     elif (w.expiration_date - datetime.now()).days <= 365:
#         return -1
#     else:
#         return 1

def long_domain_type(url):
    domain = get_domain(url)
    try:
        w = whois.whois(domain)
        
        if isinstance(w.expiration_date, list):
            expiration_date = w.expiration_date[0]
        else:
            expiration_date = w.expiration_date
        
        remaining_days = (expiration_date - datetime.now()).days
        if remaining_days <= 365:
            return -1
        else:
            return 1
    #no match for domain
    except whois.parser.PywhoisError:
        return -1
        
    


def favicon_type(url):
    r = requests.get(url)
    if 'favicon.ico' in r.text:
        return 1
    else:
        return 0
    
def port_type(url):
    parsed_url = urlparse(url)
    if parsed_url.port == None or parsed_url.port == 80 or parsed_url.port == 443:
        return 0
    else:
        return 1
    
def https_token_type(url):
    parsed_url = urlparse(url)
    if 'https' in parsed_url.netloc:
        return 1
    elif 'http' in parsed_url.netloc:
        return 1
    else:
        return 0
    
def req_url_type(url):
    parsed_url = urlparse(url)
    if len(parsed_url.query) == 0:
        return -1
    elif len(parsed_url.query) / len(url) < 0.22:
        return -1
    else:
        return 1
    
def url_of_anchor_type(url):
    parsed_url = urlparse(url)
    if len(parsed_url.fragment) == 0:
        return -1
    elif len(parsed_url.fragment) / len(url) < 0.31:
        return -1
    elif len(parsed_url.fragment) / len(url) >= 0.31 and len(parsed_url.fragment) / len(url) <= 0.67:
        return 0
    else:
        return 1




def tag_links_type(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    meta_links = soup.find_all('meta')
    script_links = soup.find_all('script')
    link_links = soup.find_all('link')
    total_links = len(meta_links) + len(script_links) + len(link_links)
    if total_links == 0:
        return -1
    elif total_links / len(str(response.content)) < 0.17:
        return -1
    elif total_links / len(str(response.content)) >= 0.17 and total_links / len(str(response.content)) <= 0.81:
        return 0
    else:
        return 1
    
def sfh_type(url):
    parsed_url = urlparse(url)
    if parsed_url.fragment == "" or parsed_url.fragment == "about:blank":
        return 1
    elif parsed_url.fragment.startswith("http") and parsed_url.fragment not in url:
        return 1
    else:
        return -1
    
def submit_to_email_type(url):
    parsed_url = urlparse(url)
    if "mail()" in url or "mailto:" in url:
        return 0
    else:
        return 1
    
def abnormal_url_type(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc == "":
        return 1
    else:
        return 0
    

def redirect_type(url):
    response = requests.get(url)
    if len(response.history) <= 1:
        return 0
    elif len(response.history) >= 2 and len(response.history) < 4:
        return 1
    else:
        return 1
    
def on_mouseover_type(url):
    response = requests.get(url)
    if "onmouseover=" in str(response.content):
        return 1
    else:
        return 0
    
def right_click_type(url):
    response = requests.get(url)
    if "event.button==2" in str(response.content):
        return 1
    else:
        return 0
    
def popup_type(url):
    response = requests.get(url)
    if "prompt(" in str(response.content):
        return 1
    else:
        return 0
    
def iframe_type(url):
    response = requests.get(url)
    if "<iframe" in str(response.content):
        return 1
    else:
        return 0

# def age_of_domain_type(url):
#     domain = url.split('/')[2]
#     w = whois.whois(domain)
#     if w.creation_date is None:
#         return 0
#     elif (datetime.now() - w.creation_date).days <= 182:
#         return 1
#     else:
#         return -1
def age_of_domain_type(url):
    domain = get_domain(url)
    try:
        w = whois.whois(domain)

        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date
        
        age_in_days = (datetime.now() - creation_date).days
        if age_in_days <= 182:
            return 1
        else:
            return -1
    except whois.parser.PywhoisError:
        return 1
    
def dns_record_type(url):
    domain = url.split('/')[2]
    try:
        w = whois.whois(domain)
        return 1
    except:
        return 0
    
def get_traffic_value(url):
    try:
        api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={url}&strategy=mobile"
        result = urllib.request.urlopen(api_url).read().decode('UTF-8')
        data = json.loads(result)
        score = data['loadingExperience']['metrics']['CUMULATIVE_LAYOUT_SHIFT_SCORE']['percentile']
        if score >= 67:
            return -1
        elif score >= 34:
            return 0
        else:
            return 1
    except KeyError:
        return 0



def get_page_rank(url):
        return random.choice([-1, 0, 1])


     




    
def is_indexed(url):
    r = requests.get(f"https://www.google.com/search?q=site:{url}")
    if r.status_code == 200:
        if "did not match any documents" in r.text:
            return 0
        else:
            return 1
    else:
        return 0

def count_external_links(url):
    html_page = requests.get(url)
    soup = BeautifulSoup(html_page.content, 'html.parser')
    external_links = 0
    for link in soup.find_all('a'):
        href = link.get('href')
        if href.startswith('http') and not url in href:
            external_links += 1
    if external_links == 0:
        return -1
    elif external_links > 0 and external_links <= 2:
        return 0
    else:
        return 1
    
# def get_ip_address(url):
#     try:
#         response = requests.get(url)
#         if response.status_code == 200:
#             ip_address = response.raw._connection.sock.getpeername()[0]
#             return ip_address
#         else:
#             print("Error retrieving IP address.")
#     except requests.exceptions.RequestException as e:
#         print("Error: ", e)
#     return None
def get_ip_address(url):
    try:
        ip_address = socket.gethostbyname(url)
        return ip_address
    except socket.error as e:
        
        
        return "255.255.255.255"

def get_domain(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            domain = response.url.split('/')[2]
            return domain
        else:
            print("Error retrieving domain.")
    except requests.exceptions.RequestException as e:
        print("Error: ", e)
    return 

def check_top_phishing_ips(url):
    # Replace with your own list of top phishing IPs
    top_phishing_ips = [
        "217.122.135.98",
        "62.57.100.227",
        "201.52.111.210",
        "41.95.8.88",
        "212.195.19.100",
        "98.213.207.87",
        "77.232.142.203",
        "82.230.176.157",
        "84.29.121.96",
        "188.135.2.252"


    ]
    ip_address = get_ip_address(url)
    if ip_address in top_phishing_ips:
        return True
    return False

def check_top_phishing_domains(url):
    # Replace with your own list of top phishing domains
    top_phishing_domains = [
        "att-rsshelp.com",
        "paypal-opladen.be",
        "login.microsoftonline.ccisystems.us",
        "paypal.com.cgi-bin-webscrcmd.login-submit.dispatch.5885d80a13c0db1f8e263663d3faee8d0b7e7284",
        "dhlinfos.link",
        "facebookztv.com",
        "irs-contact-payments.com",
        "loginnnaolcccom.weebly.com",
        "cufjaj.id",
        "adobe-pdf-sick-alley.surge.sh",
        "login-amazon-account.com"

    ]
    domain = get_domain(url)
    if domain in top_phishing_domains:
        return True
    return False





def get_stats_report_value(url):
    if check_top_phishing_ips(url) or check_top_phishing_domains(url):
        return 1  # Phishing
    else:
        return 0  # Legitimate
    
def extractfeatures(url):
    features = []
    features.append(has_ip(url))
    features.append(has_long_url(url))
    features.append(has_short_service(url))
    features.append(has_at(url))
    features.append(has_redirect(url))
    features.append(has_pref(url))
    features.append(subdomain_type(url))
    features.append(ssl_type(url))
    features.append(long_domain_type(url))
    features.append(favicon_type(url))
    features.append(port_type(url))
    features.append(https_token_type(url))
    features.append(req_url_type(url))
    features.append(url_of_anchor_type(url))
    features.append(tag_links_type(url))
    features.append(sfh_type(url))
    features.append(submit_to_email_type(url))
    features.append(abnormal_url_type(url))
    features.append(redirect_type(url))
    features.append(on_mouseover_type(url))
    features.append(right_click_type(url))
    features.append(popup_type(url))
    features.append(iframe_type(url))
    features.append(age_of_domain_type(url))
    features.append(dns_record_type(url))
    features.append(get_traffic_value(url))
    features.append(get_page_rank(url))
    features.append(is_indexed(url))
    features.append(count_external_links(url))
    features.append(get_stats_report_value(url))
    return features

features = extractfeatures("https://pchandler488.wixsite.com/my-site")
fnames =['has_ip', 'long_url', 'short_service', 'has_at', 'double_slash_redirect', 'pref_suf', 'has_sub_domain', 'ssl_state', 'long_domain', 'favicon', 'port', 'https_token', 'req_url', 'url_of_anchor', 'tag_links', 'SFH', 'submit_to_email', 'abnormal_url', 'redirect', 'mouseover', 'right_click', 'popup', 'iframe', 'domain_Age', 'dns_record', 'traffic', 'page_rank', 'google_index', 'links_to_page', 'stats_report']
print(features)
model = pickle.load(open('model.pkl', 'rb'))
prediction = model.predict([features])
print(prediction)

    

    



    
