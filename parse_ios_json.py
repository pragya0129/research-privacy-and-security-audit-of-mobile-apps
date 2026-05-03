import json
import pandas as pd
import os
import glob
import plistlib
import io

INPUT_FOLDER = 'json_reports/ios'       
OUTPUT_FILE = 'MobSF_iOS_Final_Dataset.xlsx' 


COLUMNS = [
    "App Name", "Bundle Identifier", "Version", "Platform", "IPA File Name", "Hash",
    "Tracker Count", "Tracker Names", "Ad SDK Count", "Analytics SDK Count",
    "Total Permissions", "Dangerous Permissions", "Uses Camera", "Uses Location (When In Use)", "Uses Location (Always)", "Uses Mic", "Uses Contacts",
    "Target SDK Version", 
    "WebView JavaScript Enabled",
    "PII Collected Types",
    "App Tracking Transparency (ATT) Required",
    "Uses IDFA",
    "ATS Exception Present",
    "Push Notification Usage",
    "Uses Custom URL Schemes",
]


AD_SDKS = ['admob', 'unityads', 'facebook_ads', 'mopub', 'appsflyer', 'ironsource', 'applovin', 'vungle', 'chartboost', 'adcolony']
ANALYTICS_SDKS = ['firebase', 'google_analytics', 'crashlytics', 'mixpanel', 'amplitude', 'adjust', 'newrelic', 'comscore', 'facebook_analytics', 'branch']

def detect_sdks(trackers_list):
    ad_count = 0
    analytics_count = 0
    
    for t in trackers_list:
        name = str(t.get('name', '')).lower()
        if any(x in name for x in AD_SDKS):
            ad_count += 1
        elif any(x in name for x in ANALYTICS_SDKS):
            analytics_count += 1
            
    return ad_count, analytics_count

def parse_ios_report(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
    except Exception as e:
        print(f"  [!] Error reading file: {e}")
        return None

    # Skip Android reports if mixed in same folder
    if 'apk' in str(report.get('app_type', '')).lower():
        print(f"  [i] Skipping {os.path.basename(file_path)} (Android)")
        return None

    row = {col: None for col in COLUMNS}

    
    row['App Name'] = report.get('app_name', 'Unknown')
    row['Bundle Identifier'] = report.get('bundle_id', 'Unknown')
    row['Version'] = report.get('app_version')
    row['IPA File Name'] = report.get('file_name', 'Unknown')
    row['Hash'] = report.get('md5') or report.get('hash', 'Unknown')
    row['Platform'] = 'iOS'
    row['Target SDK Version'] = report.get('sdk_name')

    row['Tracker Count'] = report.get('detected_trackers') or report.get('trackers', {}).get('detected_trackers', 0)
    
    trackers_data = report.get('trackers')
    tracker_obj_list = []
    if isinstance(trackers_data, list):
        tracker_obj_list = [t for t in trackers_data if isinstance(t, dict)]
    elif isinstance(trackers_data, dict):
        tracker_obj_list = trackers_data.get('trackers', [])
    
    tracker_names = [t.get('name', '') for t in tracker_obj_list]
    row['Tracker Names'] = ", ".join(tracker_names[:10])
    
    ad, analytics = detect_sdks(tracker_obj_list)
    row['Ad SDK Count'] = ad
    row['Analytics SDK Count'] = analytics

   
    perms = report.get('permissions', {})
    if isinstance(perms, list): 
        perm_keys = [p.get('name', '') for p in perms]
        perm_text = " ".join(perm_keys).lower()
    else:
        perm_keys = list(perms.keys())
        perm_text = " ".join(perm_keys).lower()

    row['Uses Camera'] = 'nscamerausagedescription' in perm_text
    row['Uses Location (When In Use)'] = False
    row['Uses Location (Always)'] = False

    info_plist = report.get('info_plist', '')
    plist = {}
    if isinstance(info_plist, str):
        try:
            plist = plistlib.loads(info_plist.encode('utf-8'))
        except Exception:
            plist = {}

    if 'NSLocationWhenInUseUsageDescription' in plist:
        row['Uses Location (When In Use)'] = True
    if (
        'NSLocationAlwaysUsageDescription' in plist or
        'NSLocationAlwaysAndWhenInUseUsageDescription' in plist
    ):
        row['Uses Location (Always)'] = True
        
    
    row['Uses Mic'] = 'nsmicrophoneusagedescription' in perm_text
    row['Uses Contacts'] = 'nscontactsusagedescription' in perm_text

    row["Total Permissions"] = 0
    row["Dangerous Permissions"] = 0

    permissions = report.get("permissions", {})

    if isinstance(permissions, dict):
        row["Total Permissions"] = len(permissions)

        dangerous_count = 0
        for perm, details in permissions.items():
            if isinstance(details, dict):
                if details.get("status", "").lower() == "dangerous":
                    dangerous_count += 1

        row["Dangerous Permissions"] = dangerous_count


    row['App Tracking Transparency (ATT) Required'] = False
    plist = {}
    info_plist = report.get('info_plist', '')

    if isinstance(info_plist, str):
        try:
            plist = plistlib.loads(info_plist.encode('utf-8'))
            if 'NSUserTrackingUsageDescription' in plist:
                row['App Tracking Transparency (ATT) Required'] = True
        except Exception:
            pass
    
    row['Uses IDFA'] = False
    strings = report.get('strings', [])
    if isinstance(strings, list):
        for s in strings:
            if 'ASIdentifierManager' in s or 'advertisingIdentifier' in s:
                row['Uses IDFA'] = True
                break

    if not row['Uses IDFA']:
        if 'NSUserTrackingUsageDescription' in plist:
            tracking_domains = report.get('privacy_tracking_domains', [])
            if isinstance(tracking_domains, list) and len(tracking_domains) > 0:
                row['Uses IDFA'] = True



    row['Uses Custom URL Schemes'] = False
    info_plist = report.get('info_plist', '')
    plist = {}
    if isinstance(info_plist, str):
        try:
            plist = plistlib.loads(info_plist.encode('utf-8'))
        except Exception:
            plist = {}

    url_types = plist.get('CFBundleURLTypes', [])
    if isinstance(url_types, list) and len(url_types) > 0:
        row['Uses Custom URL Schemes'] = True
    
    row['ATS Exception Present'] = False
    info_plist = report.get('info_plist', '')
    try:
        plist = plistlib.loads(info_plist.encode('utf-8'))
        ats = plist.get('NSAppTransportSecurity', {})
        if ats.get('NSAllowsArbitraryLoads') is True:
            row['ATS Exception Present'] = True
        elif ats.get('NSAllowsArbitraryLoadsInWebContent') is True:
            row['ATS Exception Present'] = True
        elif ats.get('NSAllowsArbitraryLoadsForMedia') is True:
            row['ATS Exception Present'] = True
        elif ats.get('NSExceptionDomains'):
            row['ATS Exception Present'] = True
    except Exception:
        pass
        
        
    row['Push Notification Usage'] = False

    strings = report.get('strings', [])

    if isinstance(strings, list):
        for s in strings:
            if s.strip() == 'aps-environment' or 'aps-environment' in s:
                row['Push Notification Usage'] = True
                break

    row['WebView JavaScript Enabled'] = False

    strings = report.get('strings', [])

    JS_HINTS = [
        'evaluateJavaScript',
        'JavaScript',
        'JSExecutor',
        'webkit',
        'WKWebView'
    ]

    if isinstance(strings, list):
        for s in strings:
            for hint in JS_HINTS:
                if hint in s:
                    row['WebView JavaScript Enabled'] = True
                    break
            if row['WebView JavaScript Enabled']:
                break


    
    pii = []
    if row.get('Uses Location (When In Use)') or row.get('Uses Location (Always)'):
        pii.append('Location')
    if row['Uses Contacts']: pii.append('Contacts')
    if 'nsphotolibraryusagedescription' in perm_text: pii.append('Photos')
    row['PII Collected Types'] = ", ".join(pii)


    for col in COLUMNS:
        if row[col] is None:
             if any(x in col for x in ['Uses ', 'Required', 'Present', 'Usage', 'Enabled']):
                 row[col] = False

    return row

def main():
    if not os.path.exists(INPUT_FOLDER):
        print(f"Error: Folder '{INPUT_FOLDER}' not found.")
        return

    files = [f for f in os.listdir(INPUT_FOLDER) if f.endswith('.json')]
    print(f"--- Found {len(files)} iOS reports. Starting batch processing ---")
    
    dataset = []

    for index, file_name in enumerate(files):
        print(f"[{index+1}/{len(files)}] Parsing {file_name}...")
        file_path = os.path.join(INPUT_FOLDER, file_name)
        
        row_data = parse_ios_report(file_path)
        if row_data:
            dataset.append(row_data)

    if dataset:
        print("\nSaving to Excel...")
        df = pd.DataFrame(dataset)
        df = df[COLUMNS]
        df.to_excel(OUTPUT_FILE, index=False)
        print(f"--- SUCCESS! Saved to: {OUTPUT_FILE}")
    else:
        print("No valid iOS data extracted.")

if __name__ == "__main__":
    main()
