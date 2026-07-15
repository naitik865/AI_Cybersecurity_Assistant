import os
from explainability import generate_explanation
from flask import Flask, render_template, request
import joblib
import numpy as np
import pandas as pd

from feature_extraction import extract_features

app = Flask(__name__)

# Load trained model (resolved relative path)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, 'phishing_model.pkl')
model = joblib.load(model_path)


# =========================
# TRUSTED DOMAIN SAFELIST
# =========================
# If the base domain of a URL matches any entry here, the URL is
# automatically classified as Safe regardless of the path, query
# string, or any other content after the slash.
# This prevents false positives for long YouTube channel URLs,
# Amazon product links, Google search results, etc.

TRUSTED_DOMAINS = {
    # ===== SEARCH ENGINES =====
    'google.com', 'google.co.in', 'google.co.uk', 'google.ca',
    'google.com.au', 'google.de', 'google.fr', 'google.co.jp',
    'bing.com', 'yahoo.com', 'yahoo.co.in', 'yahoo.co.jp',
    'duckduckgo.com', 'baidu.com', 'yandex.com', 'yandex.ru',
    'ask.com', 'ecosia.org', 'startpage.com', 'brave.com',

    # ===== VIDEO & STREAMING =====
    'youtube.com', 'netflix.com', 'primevideo.com', 'disneyplus.com',
    'hulu.com', 'twitch.tv', 'vimeo.com', 'dailymotion.com',
    'hotstar.com', 'jiocinema.com', 'sonyliv.com', 'zee5.com',
    'mxplayer.in', 'crunchyroll.com', 'peacocktv.com', 'hbomax.com',
    'max.com', 'paramountplus.com', 'discoveryplus.com', 'tubi.tv',
    'pluto.tv', 'roku.com', 'funimation.com', 'curiositystream.com',

    # ===== SOCIAL MEDIA =====
    'facebook.com', 'fb.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'reddit.com', 'pinterest.com', 'tumblr.com',
    'snapchat.com', 'tiktok.com', 'quora.com', 'threads.net',
    'mastodon.social', 'bsky.app', 'clubhouse.com', 'meetup.com',
    'deviantart.com', 'flickr.com', 'behance.net', 'dribbble.com',
    'producthunt.com', 'hackerrank.com', 'leetcode.com',
    'codeforces.com', 'codechef.com', 'topcoder.com',

    # ===== MESSAGING & COMMUNICATION =====
    'whatsapp.com', 'web.whatsapp.com', 'telegram.org', 'telegram.me',
    'discord.com', 'discord.gg', 'signal.org', 'zoom.us',
    'slack.com', 'skype.com', 'teams.microsoft.com', 'meet.google.com',
    'webex.com', 'viber.com', 'line.me', 'kakaocorp.com',
    'wechat.com',

    # ===== E-COMMERCE & PAYMENTS =====
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de',
    'amazon.co.jp', 'amazon.ca', 'amazon.com.au', 'amazon.fr',
    'flipkart.com', 'myntra.com', 'ajio.com', 'meesho.com',
    'snapdeal.com', 'nykaa.com', 'lenskart.com', 'tatacliq.com',
    'jiomart.com', 'bigbasket.com', 'grofers.com', 'blinkit.com',
    'ebay.com', 'ebay.co.uk', 'walmart.com', 'target.com',
    'bestbuy.com', 'costco.com', 'aliexpress.com', 'alibaba.com',
    'shopify.com', 'etsy.com', 'wayfair.com', 'overstock.com',
    'wish.com', 'shein.com', 'ikea.com', 'homedepot.com',
    'lowes.com', 'newegg.com', 'zappos.com', 'asos.com',
    'zara.com', 'hm.com', 'uniqlo.com', 'nike.com', 'adidas.com',
    'puma.com', 'reebok.com', 'decathlon.com',
    'paypal.com', 'stripe.com', 'razorpay.com', 'payu.in',
    'cashfree.com', 'instamojo.com', 'venmo.com', 'wise.com',
    'revolut.com', 'klarna.com', 'afterpay.com',

    # ===== TECHNOLOGY & DEVELOPER =====
    'github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
    'stackoverflow.com', 'stackexchange.com', 'serverfault.com',
    'superuser.com', 'askubuntu.com',
    'npmjs.com', 'pypi.org', 'rubygems.org', 'crates.io',
    'nuget.org', 'packagist.org', 'hub.docker.com', 'docker.com',
    'kubernetes.io', 'terraform.io', 'ansible.com',
    'vercel.com', 'netlify.com', 'heroku.com', 'railway.app',
    'render.com', 'fly.io', 'supabase.com', 'firebase.google.com',
    'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
    'console.aws.amazon.com', 'digitalocean.com', 'linode.com',
    'vultr.com', 'cloudflare.com', 'akamai.com', 'fastly.com',
    'replit.com', 'codepen.io', 'jsfiddle.net', 'codesandbox.io',
    'kaggle.com', 'huggingface.co', 'openai.com', 'anthropic.com',
    'colab.research.google.com', 'jupyter.org', 'anaconda.com',
    'jetbrains.com', 'visualstudio.com', 'code.visualstudio.com',
    'developer.mozilla.org', 'w3schools.com', 'freecodecamp.org',
    'geeksforgeeks.org', 'tutorialspoint.com', 'javatpoint.com',

    # ===== MICROSOFT ECOSYSTEM =====
    'microsoft.com', 'office.com', 'office365.com', 'live.com',
    'outlook.com', 'outlook.live.com', 'hotmail.com',
    'onedrive.live.com', 'onedrive.com', 'sharepoint.com',
    'xbox.com', 'msn.com', 'bing.com', 'linkedin.com',
    'windowsupdate.com', 'microsoftstore.com',
    'powerbi.com', 'dynamics.com', 'azurewebsites.net',

    # ===== APPLE ECOSYSTEM =====
    'apple.com', 'icloud.com', 'itunes.apple.com',
    'support.apple.com', 'developer.apple.com',
    'music.apple.com', 'tv.apple.com', 'books.apple.com',
    'apps.apple.com',

    # ===== GOOGLE ECOSYSTEM =====
    'gmail.com', 'drive.google.com', 'docs.google.com',
    'sheets.google.com', 'slides.google.com', 'forms.google.com',
    'maps.google.com', 'play.google.com', 'accounts.google.com',
    'translate.google.com', 'calendar.google.com',
    'photos.google.com', 'news.google.com', 'earth.google.com',
    'sites.google.com', 'groups.google.com', 'scholar.google.com',
    'analytics.google.com', 'ads.google.com', 'trends.google.com',
    'fonts.google.com', 'developers.google.com',
    'cloud.google.com', 'console.cloud.google.com',
    'blogger.com', 'blogspot.com',

    # ===== NEWS & MEDIA =====
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com',
    'theguardian.com', 'reuters.com', 'apnews.com',
    'washingtonpost.com', 'forbes.com', 'bloomberg.com',
    'cnbc.com', 'foxnews.com', 'abcnews.go.com',
    'nbcnews.com', 'cbsnews.com', 'usatoday.com',
    'wsj.com', 'economist.com', 'ft.com', 'time.com',
    'huffpost.com', 'buzzfeed.com', 'vice.com', 'vox.com',
    'techcrunch.com', 'theverge.com', 'wired.com', 'arstechnica.com',
    'engadget.com', 'mashable.com', 'cnet.com', 'zdnet.com',
    'tomshardware.com', 'pcmag.com', 'howtogeek.com',
    # Indian news
    'ndtv.com', 'timesofindia.indiatimes.com', 'timesofindia.com',
    'hindustantimes.com', 'thehindu.com', 'indiatoday.in',
    'indianexpress.com', 'news18.com', 'firstpost.com',
    'livemint.com', 'moneycontrol.com', 'economictimes.com',
    'business-standard.com', 'theprint.in', 'thewire.in',
    'scroll.in', 'republic.world', 'aajtak.in',
    'abplive.com', 'zeenews.india.com',

    # ===== EDUCATION =====
    'wikipedia.org', 'wikimedia.org', 'wiktionary.org',
    'khanacademy.org', 'coursera.org', 'udemy.com', 'edx.org',
    'skillshare.com', 'pluralsight.com', 'lynda.com',
    'udacity.com', 'codecademy.com', 'brilliant.org',
    'duolingo.com', 'memrise.com', 'babbel.com',
    'unacademy.com', 'byjus.com', 'vedantu.com',
    'toppr.com', 'testbook.com', 'gradeup.co',
    'mit.edu', 'stanford.edu', 'harvard.edu', 'yale.edu',
    'princeton.edu', 'columbia.edu', 'berkeley.edu',
    'ox.ac.uk', 'cam.ac.uk', 'iitb.ac.in', 'iitd.ac.in',
    'iitm.ac.in', 'iisc.ac.in', 'bits-pilani.ac.in',
    'nptel.ac.in', 'swayam.gov.in', 'ugc.ac.in',
    'researchgate.net', 'academia.edu', 'jstor.org',
    'sciencedirect.com', 'springer.com', 'nature.com',
    'ieee.org', 'acm.org', 'arxiv.org',

    # ===== MUSIC =====
    'spotify.com', 'open.spotify.com', 'soundcloud.com',
    'music.apple.com', 'music.youtube.com', 'deezer.com',
    'tidal.com', 'pandora.com', 'last.fm',
    'gaana.com', 'jiosaavn.com', 'wynk.in', 'hungama.com',

    # ===== SOFTWARE & PRODUCTIVITY =====
    'adobe.com', 'creativecloud.adobe.com', 'canva.com',
    'figma.com', 'sketch.com', 'invisionapp.com',
    'notion.so', 'notion.com', 'trello.com', 'asana.com',
    'monday.com', 'clickup.com', 'basecamp.com', 'jira.atlassian.com',
    'atlassian.com', 'confluence.atlassian.com',
    'dropbox.com', 'box.com', 'wetransfer.com',
    'evernote.com', 'todoist.com', 'airtable.com',
    'miro.com', 'lucidchart.com', 'draw.io',
    'grammarly.com', 'deepl.com', 'wordreference.com',
    'lastpass.com', '1password.com', 'bitwarden.com', 'dashlane.com',
    'norton.com', 'mcafee.com', 'kaspersky.com', 'avast.com',
    'malwarebytes.com', 'bitdefender.com',

    # ===== FINANCE & BANKING (India) =====
    'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com',
    'icicibank.com', 'axisbank.com', 'kotak.com',
    'kotakbank.com', 'bankofbaroda.in', 'pnbindia.in',
    'canarabank.com', 'unionbankofindia.co.in',
    'indianbank.in', 'bankofindia.co.in', 'iob.in',
    'idbibank.in', 'federalbank.co.in', 'rbl.bank',
    'yesbank.in', 'indusind.com', 'dbs.com',
    'paytm.com', 'phonepe.com', 'gpay.app',
    'freecharge.in', 'mobikwik.com', 'bharatpe.com',
    'cred.club', 'groww.in', 'zerodha.com', 'upstox.com',
    'angelone.in', 'kite.zerodha.com', 'coin.zerodha.com',
    'smallcase.com', 'mutualfundindia.com',
    'policybazaar.com', 'coverfox.com', 'acko.com',
    'rbi.org.in', 'sebi.gov.in', 'npci.org.in',
    'incometax.gov.in', 'gst.gov.in',

    # ===== FINANCE & BANKING (Global) =====
    'bankofamerica.com', 'chase.com', 'jpmorgan.com',
    'wellsfargo.com', 'citi.com', 'citibank.com',
    'goldmansachs.com', 'morganstanley.com',
    'barclays.com', 'hsbc.com', 'standardchartered.com',
    'deutschebank.com', 'bnpparibas.com', 'ubs.com',
    'creditsuisse.com', 'americanexpress.com', 'amex.com',
    'discover.com', 'capitalone.com', 'ally.com',
    'schwab.com', 'fidelity.com', 'vanguard.com',
    'tdameritrade.com', 'etrade.com', 'robinhood.com',
    'coinbase.com', 'binance.com', 'kraken.com',
    'blockchain.com', 'metamask.io',

    # ===== TRAVEL & TRANSPORT =====
    'makemytrip.com', 'goibibo.com', 'irctc.co.in',
    'booking.com', 'airbnb.com', 'expedia.com',
    'tripadvisor.com', 'trivago.com', 'kayak.com',
    'skyscanner.com', 'agoda.com', 'hotels.com',
    'cleartrip.com', 'yatra.com', 'ixigo.com', 'redbus.in',
    'uber.com', 'lyft.com', 'ola.com', 'rapido.bike',
    'indigo.in', 'airindia.com', 'spicejet.com',
    'goair.in', 'vistara.com', 'emirates.com',
    'qatarairways.com', 'singaporeair.com', 'united.com',
    'delta.com', 'aa.com', 'britishairways.com',
    'lufthansa.com', 'southwest.com', 'ryanair.com',
    'easyjet.com',

    # ===== FOOD DELIVERY & RESTAURANTS =====
    'zomato.com', 'swiggy.com', 'ubereats.com',
    'doordash.com', 'grubhub.com', 'postmates.com',
    'dunzo.com', 'dominos.co.in', 'dominos.com',
    'pizzahut.co.in', 'mcdonalds.com', 'starbucks.com',
    'kfc.com', 'subway.com', 'burgerking.com',

    # ===== GOVERNMENT (India) =====
    'india.gov.in', 'mygov.in', 'digitalindia.gov.in',
    'uidai.gov.in', 'aadhaar.gov.in', 'digilocker.gov.in',
    'umang.gov.in', 'cowin.gov.in', 'nrega.nic.in',
    'epfindia.gov.in', 'passportindia.gov.in',
    'indianrailways.gov.in', 'nta.ac.in',
    'cbse.gov.in', 'ugc.ac.in',

    # ===== GOVERNMENT (Global) =====
    'gov.uk', 'usa.gov', 'whitehouse.gov',
    'irs.gov', 'ssa.gov', 'cdc.gov', 'nih.gov',
    'who.int', 'un.org', 'europa.eu',

    # ===== GAMING =====
    'steam.com', 'steampowered.com', 'store.steampowered.com',
    'epicgames.com', 'ea.com', 'origin.com',
    'playstation.com', 'xbox.com', 'nintendo.com',
    'roblox.com', 'minecraft.net', 'mojang.com',
    'blizzard.com', 'battle.net', 'ubisoft.com',
    'riotgames.com', 'leagueoflegends.com', 'valorant.com',
    'supercell.com', 'ign.com', 'gamespot.com',
    'polygon.com', 'kotaku.com',

    # ===== CLOUD STORAGE & FILE SHARING =====
    'drive.google.com', 'onedrive.com', 'dropbox.com',
    'box.com', 'mega.nz', 'mediafire.com',
    'wetransfer.com', 'pcloud.com', 'sync.com',

    # ===== JOB PORTALS =====
    'naukri.com', 'indeed.com', 'glassdoor.com',
    'monster.com', 'shine.com', 'timesjobs.com',
    'instahyre.com', 'hirist.com', 'angel.co',
    'wellfound.com', 'ziprecruiter.com', 'dice.com',
    'upwork.com', 'freelancer.com', 'fiverr.com',
    'toptal.com', 'guru.com',

    # ===== HEALTH & FITNESS =====
    'practo.com', 'apollo247.com', '1mg.com', 'pharmeasy.in',
    'netmeds.com', 'healthifyme.com', 'curefit.com',
    'webmd.com', 'mayoclinic.org', 'healthline.com',
    'nih.gov', 'who.int', 'fitbit.com', 'myfitnesspal.com',
    'strava.com',

    # ===== REAL ESTATE =====
    'magicbricks.com', '99acres.com', 'housing.com',
    'nobroker.in', 'commonfloor.com', 'squareyards.com',
    'zillow.com', 'realtor.com', 'redfin.com', 'trulia.com',

    # ===== MISCELLANEOUS POPULAR =====
    'medium.com', 'substack.com', 'wordpress.com', 'wordpress.org',
    'wix.com', 'squarespace.com', 'weebly.com',
    'blogger.com', 'ghost.org', 'hashnode.dev',
    'dev.to', 'hackernoon.com',
    'archive.org', 'web.archive.org', 'imdb.com',
    'rottentomatoes.com', 'metacritic.com',
    'craigslist.org', 'yelp.com', 'justdial.com',
    'sulekha.com', 'indiamart.com', 'tradeindia.com',
    'olx.in', 'quikr.com',
    'change.org', 'gofundme.com', 'kickstarter.com',
    'patreon.com', 'buymeacoffee.com',
    'linktr.ee', 'bit.ly', 'tinyurl.com',
    'speedtest.net', 'fast.com',
    'virustotal.com', 'haveibeenpwned.com',
}


def is_safelisted(url):
    """Check if the URL belongs to a trusted domain.
    Only the domain (authority) part is checked — everything
    after the first slash is completely ignored."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Strip www. prefix for matching
        if domain.startswith('www.'):
            domain = domain[4:]

        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith('.' + trusted):
                return True
    except Exception:
        pass
    return False


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():

    # =========================
    # GET URL INPUT
    # =========================

    url = request.form['url']

    # Auto-add HTTPS if missing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    # =========================
    # FEATURE EXTRACTION
    # =========================

    features = extract_features(url)

    # =========================
    # TRUSTED DOMAIN SAFELIST CHECK
    # =========================
    # If the domain is a well-known trusted site, skip ML + heuristics
    # entirely and return Safe. This prevents false positives for long
    # YouTube channel URLs, Amazon product links, Google results, etc.

    if is_safelisted(url):
        explanations = generate_explanation(features)
        # Prepend a safelist explanation
        explanations.insert(0, {
            'message': 'This URL belongs to a verified trusted domain — automatically marked safe',
            'severity': 'safe'
        })
        return render_template(
            'result.html',
            prediction='Safe Website',
            risk_score=0,
            confidence=98,
            url=url,
            explanations=explanations
        )

    # Convert features into DataFrame (matches training format)
    final_features = pd.DataFrame([features])

    # =========================
    # MACHINE LEARNING PREDICTION
    # =========================

    prediction = model.predict(final_features)[0]

    # Get prediction probabilities
    # Model classes: [0, 1] → 0 = Phishing, 1 = Safe
    probabilities = model.predict_proba(final_features)[0]

    # FIX: index 0 = phishing probability, index 1 = safe probability
    phishing_probability = probabilities[0]
    safe_probability = probabilities[1]

    # Base risk score driven by ML phishing probability (0 to 100)
    risk_score = int(phishing_probability * 100)

    # =========================
    # RULE-BASED HEURISTICS
    # =========================

    # FIX: Consistent keyword list (merged 'banking' from feature_extraction.py)
    suspicious_keywords = [
        'login',
        'verify',
        'secure',
        'account',
        'update',
        'banking',
        'paypal',
        'signin',
        'password',
        'bank'
    ]

    keyword_score = 0

    # Suspicious keyword detection
    for word in suspicious_keywords:
        if word in url.lower():
            keyword_score += 8

    # Multiple hyphens
    if url.count('-') >= 2:
        keyword_score += 15

    # HTTP instead of HTTPS
    if url.startswith('http://'):
        keyword_score += 20

    # Long suspicious URL
    if len(url) > 60:
        keyword_score += 10

    # Too many digits
    digit_count = sum(c.isdigit() for c in url)
    if digit_count >= 3:
        keyword_score += 10

    # Brand impersonation — FIX: skip legitimate domains like google.com itself
    suspicious_brands = [
        'paypal',
        'facebook',
        'amazon',
        'bank'
    ]

    for brand in suspicious_brands:
        if brand in url.lower():
            keyword_score += 5

    # =========================
    # FINAL RISK SCORE
    # =========================

    risk_score = min(risk_score + keyword_score, 100)

    # =========================
    # FINAL DECISION & CONFIDENCE
    # =========================

    # FIX: Removed redundant early confidence calculation
    # FIX: All confidence values now correctly use phishing_probability or safe_probability

    if risk_score >= 80:
        result = "Phishing Website"
        confidence = min(round((risk_score + phishing_probability * 100) / 2, 2), 98)

    elif risk_score >= 45:
        result = "Suspicious Website"
        confidence = min(round((risk_score + phishing_probability * 100) / 2, 2), 98)

    else:
        result = "Safe Website"
        # FIX: Use safe_probability for confidence when site is safe
        confidence = min(round(safe_probability * 100, 2), 98)

    # =========================
    # EXPLAINABILITY
    # =========================

    explanations = generate_explanation(features)

    # =========================
    # RENDER RESULT PAGE
    # =========================

    return render_template(
        'result.html',
        prediction=result,
        risk_score=risk_score,
        confidence=confidence,
        url=url,
        explanations=explanations
    )


if __name__ == '__main__':
    app.run(debug=True)