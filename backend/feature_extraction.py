import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse

# Feature Extractor for Phishing ML model (30 features)

# 1. having_IP_Address
def havingIP(url):
    try:
        host = urlparse(url).netloc
        ipaddress.ip_address(host)
        return -1
    except:
        return 1

# 2. URL_Length
def getLength(url):
    if len(url) < 54:
        return 1
    elif len(url) >= 54 and len(url) <= 75:
        return 0
    else:
        return -1

# 3. Shortining_Service
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth+1
    return depth

def shortining_Service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
    if match:
        return -1
    return 1

# 4. having_At_Symbol
def havingAtSymbol(url):
    if "@" in url:
        return -1
    return 1

# 5. double_slash_redirecting
def doubleSlashRedirecting(url):
    list = [x.start(0) for x in re.finditer('//', url)]
    if list[len(list)-1] > 6:
        return -1
    return 1

# 6. Prefix_Suffix
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return -1
    return 1

# 7. having_Sub_Domain
def havingSubDomain(url):
    domain = urlparse(url).netloc
    if len(re.findall("\.", domain)) == 1:
        return 1
    elif len(re.findall("\.", domain)) == 2:
        return 0
    else:
        return -1

# 8. SSLfinal_State (approximate by checking https)
def SSLfinal_State(url):
    try:
        if urlparse(url).scheme == 'https':
            return 1
        return -1
    except:
        return -1

# 9. Domain_registeration_length
def domainRegistrationLength(domain):
    try:
        domain_name = whois.whois(domain)
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
            try:
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
            except:
                return 0
        if ((expiration_date is None) or (creation_date is None)):
            return 0
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 0
        else:
            registration_length = abs((expiration_date - creation_date).days)
            if registration_length / 365 <= 1:
                return 0
            else:
                return 1
    except:
        return 0

# 10. Favicon
def favicon(url, soup, domain):
    try:
        for head in soup.find_all('head'):
            for head.link in soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                    return 1
        return -1
    except:
        return -1

# 11. port
def port(domain):
    return 1 # simplify for latency

# 12. HTTPS_token
def httpsToken(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return -1
    return 1

# 13. Request_URL
def requestURL(url, soup, domain):
    try:
        i = 0
        success = 0
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if url in img['src'] or domain in img['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for audio in soup.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for embed in soup.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for iframe in soup.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
            if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1

        try:
            percentage = success/float(i) * 100
            if percentage < 22.0:
                return 1
            elif (percentage >= 22.0 and percentage < 61.0):
                return 0
            else:
                return -1
        except:
            return 1
    except:
        return -1

# 14. URL_of_Anchor
def urlOfAnchor(url, soup, domain):
    try:
        i = 0
        unsafe = 0
        for a in soup.find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                unsafe = unsafe + 1
            i = i + 1
        try:
            percentage = unsafe / float(i) * 100
            if percentage < 31.0:
                return 1
            elif (percentage >= 31.0 and percentage < 67.0):
                return 0
            else:
                return -1
        except:
            return 1
    except:
        return -1

# 15. Links_in_tags
def linksInTags(url, soup, domain):
    try:
        i = 0
        success = 0
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or domain in link['href'] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or domain in script['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1
        try:
            percentage = success / float(i) * 100
            if percentage < 17.0:
                return 1
            elif (percentage >= 17.0 and percentage < 81.0):
                return 0
            else:
                return -1
        except:
            return 1
    except:
        return -1

# 16. SFH
def sfh(url, soup, domain):
    try:
        for form in soup.find_all('form', action=True):
            if form['action'] == "" or form['action'] == "about:blank":
                return -1
            elif url not in form['action'] and domain not in form['action']:
                return 0
            else:
                return 1
        return 1
    except:
        return -1

# 17. Submitting_to_email
def submittingToEmail(soup):
    try:
        if re.search('mailto:', soup.text) or re.search('mail\(\)', soup.text):
            return -1
        else:
            return 1
    except:
        return -1

# 18. Abnormal_URL
def abnormalURL(domain, url):
    try:
        domain_name = whois.whois(domain)
        if isinstance(domain_name.name, list):
            for d_name in domain_name.name:
                if d_name.lower() in url:
                    return 1
            return -1
        else:
            if domain_name.name and domain_name.name.lower() in url:
                return 1
            else:
                return -1
    except:
        return -1

# 19. Redirect
def redirect(url):
    try:
        response = requests.get(url)
        if len(response.history) <= 1:
            return 1
        elif len(response.history) <= 4:
            return 0
        else:
            return -1
    except:
        return -1

# 20. on_mouseover
def onMouseover(soup):
    try:
        if re.search('onmouseover="window.status', str(soup)) or re.search('onmouseover=\'window.status', str(soup)):
            return -1
        else:
            return 1
    except:
        return -1

# 21. RightClick
def rightClick(soup):
    try:
        if re.search('event.button ?== ?2', str(soup)):
            return -1
        else:
            return 1
    except:
        return -1

# 22. popUpWidnow
def popUpWidnow(soup):
    try:
        if re.search('window.open\(', str(soup)):
            return -1
        else:
            return 1
    except:
        return -1

# 23. Iframe
def iframe(soup):
    try:
        if re.search('iframe', str(soup)):
            return -1
        else:
            return 1
    except:
        return -1

# 24. age_of_domain
def ageOfDomain(domain):
    try:
        domain_name = whois.whois(domain)
        creation_date = domain_name.creation_date
        if isinstance(creation_date, str):
            try:
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            except:
                return -1
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        today = datetime.now()
        age = (today - creation_date).days
        if age >= 180:
            return 1
        else:
            return -1
    except:
        return -1

# 25. DNSRecord
def dnsRecord(domain):
    try:
        domain_name = whois.whois(domain)
        if domain_name.domain_name is None:
            return -1
        else:
            return 1
    except:
        return -1

# 26. web_traffic
def webTraffic(url):
    try:
        # A simple placeholder instead of full Alexa
        return 1
    except:
        return 1

# 27. Page_Rank
def pageRank(domain):
    return 1 # Simplifying since page rank apis are deprecated

# 28. Google_Index
def googleIndex(url):
    try:
        site = search(url, 5)
        if site:
            return 1
        else:
            return -1
    except:
        return 0

# 29. Links_pointing_to_page
def linksPointingToPage(soup):
    return 1

# 30. Statistical_report
def statisticalReport(url, domain):
    try:
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        try:
            ip_address = socket.gethostbyname(domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.71|46\.242\.145\.98|'
                                 '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.215|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                 '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                 '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                 '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                 '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match or ip_match:
                return -1
            else:
                return 1
        except:
            return 1
    except:
        return 1

def extract_features(url):
    if not re.match(r"^https?://", url):
        url = "http://" + url
        
    domain = urlparse(url).netloc
    
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -999

    # Feature List
    features = []
    
    features.append(havingIP(urlparse(url).netloc))
    features.append(getLength(url))
    features.append(shortining_Service(url))
    features.append(havingAtSymbol(url))
    features.append(doubleSlashRedirecting(url))
    features.append(prefixSuffix(domain))
    features.append(havingSubDomain(url))
    features.append(SSLfinal_State(url))
    features.append(domainRegistrationLength(domain))
    
    if soup == -999:
      features.extend([0]*20)
    else:
        features.append(favicon(url, soup, domain))
        features.append(port(domain))
        features.append(httpsToken(url))
        features.append(requestURL(url, soup, domain))
        features.append(urlOfAnchor(url, soup, domain))
        features.append(linksInTags(url, soup, domain))
        features.append(sfh(url, soup, domain))
        features.append(submittingToEmail(soup))
        features.append(abnormalURL(domain, url))
        features.append(redirect(url))
        features.append(onMouseover(soup))
        features.append(rightClick(soup))
        features.append(popUpWidnow(soup))
        features.append(iframe(soup))
        features.append(ageOfDomain(domain))
        features.append(dnsRecord(domain))
        features.append(webTraffic(url))
        features.append(pageRank(domain))
        features.append(googleIndex(url))
        features.append(linksPointingToPage(soup))
        features.append(statisticalReport(url, domain))
        
    return features
