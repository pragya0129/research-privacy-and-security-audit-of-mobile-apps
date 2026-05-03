import pandas as pd
from google_play_scraper import Sort, reviews
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
import time

APP_PACKAGES = [
    'nic.goi.aarogyasetu',
    'com.adobe.scan.android',
    'com.ril.ajio',
    'com.alibaba.aliexpresshd',
    'com.amazon.mShop.android.shopping',
    'com.apollo.patientapp',
    'com.apple.android.music',
    'com.bewakoof.bewakoof',
    'com.bigbasket.mobileapp',
    'com.brave.browser',
    'mobi.mgeek.TunnyBrowser',
    'com.ebay.mobile',
    'com.facebook.katana',
    'org.mozilla.firefox',
    'com.fitbit.FitbitMobile',
    'com.hm.goe',
    'in.startv.hotstaronly',
    'com.camerasideas.instashot',
    'com.instagram.android',
    'cris.org.in.prs.ima',
    'com.ixigo',
    'com.jpl.jiomart',
    'com.makemytrip',
    'com.myfitnesspal.android',
    'com.netflix.mediaclient',
    'com.nordvpn.android',
    'com.olacabs.customer',
    'com.opera.mini.native',
    'com.pinterest',
    'com.amazon.avod.thirdpartyclient',
    'com.puma.ecom.app',
    'com.rapido.passenger',
    'in.redbus.android',
    'com.reddit.frontpage',
    'org.thoughtcrime.securesms',
    'com.sonyliv',
    'com.spotify.music',
    'com.chengcheng.FreeVPN',
    'in.swiggy.android',
    'com.aranoah.healthkart.plus',
    'org.telegram.messenger',
    'org.torproject.torbrowser',
    'free.vpn.unblock.proxy.turbovpn',
    'com.udemy.android',
    'com.whatsapp',
    'com.whereismytrain.android',
    'com.twitter.android',
    'com.zeptoconsumerapp',
    'com.application.zomato',
    'com.adobe.reader',
    'cm.aptoide.pt',
    'com.grofers.customerapp',
    'com.bt.bms',
    'com.brevistay.customer',
    'com.bumble.app',
    'com.emn8.mobilem8.nativeapp.bk',
    'com.android.chrome',
    'com.dreamplug.androidapp',
    'com.digilocker.android',
    'com.application.zomato.district',
    'com.github.android',
    'com.ncrtc',
    'com.google.android.apps.labs.language.tailwind',
    'ai.perplexity.app.android',
    'com.Splitwise.SplitwiseMobile',
    'com.instagram.barcelona',
    'com.shazam.android',
    'com.poncho.eatclub',
    'com.Slack',
    'ch.protonvpn.android',
    'com.nis.app',
    'com.google.android.apps.authenticator2',
    'com.x8bit.bitwarden',
    'com.trello',
    'com.zerodha.kite3',
    'com.google.android.youtube',
    'com.linkedin.android',
    'com.duckduckgo.mobile.android',
    'com.paypal.android.p2pmobile',
    'com.valvesoftware.android.steam.community',
    'com.lenskart.app',
    'com.snapchat.android'
]

PRIVACY_SECURITY_KEYWORDS = {
    "Camera": ["camera", "photo", "video", "record"],
    "Location": ["location", "gps", "tracking", "track"],
    "Microphone": ["microphone", "mic", "audio", "listening"],
    "Contacts": ["contacts", "phonebook"],
    "SMS": ["sms", "message", "text", "otp"],
    "Data_Privacy": ["privacy", "data", "personal data", "information"],
    "Tracking_Ads": ["tracker", "tracking", "ads", "advertisement", "analytics"],
    "Security_Issues": ["hack", "hacked", "breach", "leak", "unsafe"],
    "Network_Security": ["http", "cleartext", "insecure", "network"],
    "Cryptography": ["encryption", "crypto", "decrypt"],
    "App_Integrity": ["debug", "debuggable", "tamper", "reverse"]
}

analyzer = SentimentIntensityAnalyzer()



def analyze_app_reviews(package_name):
    print(f"\nAnalyzing reviews for {package_name}")

    try:
        result, _ = reviews(
            package_name,
            lang='en',
            country='us',
            sort=Sort.NEWEST,
            count=5000
        )
    except Exception as e:
        print(f"Error fetching reviews: {e}")
        return None

    category_stats = {
        category: {"count": 0, "sentiment_sum": 0}
        for category in PRIVACY_SECURITY_KEYWORDS
    }


    for r in result:
        content = str(r['content']).lower()
        sentiment = analyzer.polarity_scores(content)['compound']

        for category, keywords in PRIVACY_SECURITY_KEYWORDS.items():
            if any(keyword in content for keyword in keywords):
                category_stats[category]["count"] += 1
                category_stats[category]["sentiment_sum"] += sentiment

    row = {"Package Name": package_name}

    for category, stats in category_stats.items():
        if stats["count"] > 0:
            avg_sentiment = stats["sentiment_sum"] / stats["count"]
            trust_score = (avg_sentiment + 1) * 50
        else:
            trust_score = 50  

        row[f"{category}_Trust_Score"] = round(trust_score, 2)
        row[f"{category}_Review_Count"] = stats["count"]

    return row


print("\n--- STARTING USER PERCEPTION DATASET CREATION ---")

dataset = []

for app in APP_PACKAGES:
    app_row = analyze_app_reviews(app)
    if app_row:
        dataset.append(app_row)
    time.sleep(1)


df = pd.DataFrame(dataset)
df.to_csv("User_Perception_Privacy_Dataset.csv", index=False)

print("\n--- DATASET CREATED SUCCESSFULLY ---")
print(df.head())
print("\nSaved as: User_Perception_Privacy_Dataset.csv")