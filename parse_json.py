import json
import pandas as pd
import os
import glob


INPUT_FOLDER = 'json_reports/android'      
OUTPUT_FILE = 'MobSF_Final_Dataset.xlsx' 

COLUMNS = [
    "App Name", "Package Name", "Version", "Platform", "File Name", "Hash",
    
    "Total Permissions", "Dangerous Permissions",
    "Tracker Count", "Hardcoded Secrets", 
    "High Severity Issues", 
    "Cleartext Traffic","Exported Components", "Allow Backup",
    "Uses Camera", "Uses Location", "Uses Mic", "Uses Contacts",
    "Uses SMS", "Tracker Names",
    "Target SDK Version",
    "Network Security Config Present",
    "Certificate Pinning Implemented",
    "Exported Providers Count",
    "Uses Weak Cryptography",
    "WebView JavaScript Enabled",
    "PII Collected Types",
    "Ad SDK Count",
    "Analytics SDK Count",
    "Uses Dynamic Code Loading",
    "Browsable Activities Present"
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

def detect_pii(full_text_perms, code_findings):
    
    pii = []
    
    # Check Permissions
    if 'location' in full_text_perms or 'gps' in full_text_perms: pii.append('Location')
    if 'contacts' in full_text_perms: pii.append('Contacts')
    if 'camera' in full_text_perms: pii.append('Image/Video')
    if 'record_audio' in full_text_perms: pii.append('Audio')
    if 'read_sms' in full_text_perms: pii.append('SMS')
    if 'read_phone_state' in full_text_perms: pii.append('DeviceID')
    
    code_text = str(code_findings).lower()
    if 'email' in code_text: pii.append('Email')
    if 'password' in code_text: pii.append('Credentials')
    
    return ", ".join(sorted(list(set(pii))))

def parse_report_robust(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
    except Exception as e:
        print(f"  [!] Error reading file: {e}")
        return None

    row = {col: None for col in COLUMNS}

    row['App Name'] = report.get('app_name', 'Unknown')
    row['Package Name'] = report.get('package_name', 'Unknown')
    row['Version'] = report.get('version_name') or report.get('version', 'Unknown')
    row['File Name'] = report.get('file_name', 'Unknown')
    row['Hash'] = report.get('md5') or report.get('hash', 'Unknown')
    
    scan_type = report.get('app_type') or report.get('scan_type', '')
    if 'ipa' in scan_type.lower() or str(row['File Name']).endswith('.ipa'):
        row['Platform'] = 'iOS'
    else:
        row['Platform'] = 'Android'

    row['Target SDK Version'] = report.get('target_sdk', 'Unknown')

    row['Tracker Count'] = report.get('detected_trackers') or report.get('trackers', {}).get('detected_trackers', 0)
    
    trackers_data = report.get('trackers')
    tracker_obj_list = []
    
    if isinstance(trackers_data, list):
        tracker_obj_list = [t for t in trackers_data if isinstance(t, dict)]
    elif isinstance(trackers_data, dict):
        tracker_obj_list = trackers_data.get('trackers', [])
        
    tracker_names = [t.get('name', '') for t in tracker_obj_list]
    row['Tracker Names'] = ", ".join(tracker_names[:10])

    ad_count, analytics_count = detect_sdks(tracker_obj_list)
    row['Ad SDK Count'] = ad_count
    row['Analytics SDK Count'] = analytics_count

    row['Hardcoded Secrets'] = len(report.get('secrets', []))

    high_count = 0
    # Manifest
    manifest_summary = report.get('manifest_summary') or report.get('manifest_analysis', {}).get('manifest_summary')
    if manifest_summary and isinstance(manifest_summary, dict):
        high_count += manifest_summary.get('high', 0)
    else:
        ma = report.get('manifest_analysis', [])
        if isinstance(ma, list):
            for item in ma:
                if isinstance(item, dict) and str(item.get('severity')).lower() == 'high': high_count += 1

    # Network
    network_summary = report.get('network_summary') or report.get('network_security', {}).get('network_summary')
    if network_summary and isinstance(network_summary, dict):
        high_count += network_summary.get('high', 0)
    else:
        ns = report.get('network_security', {})
        if isinstance(ns, dict) and ns.get('network_security_config') is False: high_count += 1

    # Certificate
    cert_summary = report.get('certificate_summary') or report.get('certificate_analysis', {}).get('certificate_summary')
    if cert_summary and isinstance(cert_summary, dict):
        high_count += cert_summary.get('high', 0)

    # Binary Analysis (Unique)
    unique_binary_issues = set()
    binary_data = report.get('binary_analysis', [])
    if isinstance(binary_data, list):
        for file_info in binary_data:
            if not isinstance(file_info, dict): continue
            for check_key, check_val in file_info.items():
                if isinstance(check_val, dict) and 'severity' in check_val:
                    if str(check_val['severity']).lower() == 'high':
                        unique_binary_issues.add(check_key)
    high_count += len(unique_binary_issues)

    # Code Analysis (Unique)
    unique_code_issues = set()
    code_data = report.get('code_analysis', {})
    if isinstance(code_data, dict):
        for key, issue in code_data.items():
            if not isinstance(issue, dict): continue
            meta = issue.get('metadata', {})
            if str(meta.get('severity', '')).lower() == 'high':
                name = issue.get('name') or issue.get('title') or key
                unique_code_issues.add(name)
    high_count += len(unique_code_issues)

    row['High Severity Issues'] = high_count

    row['Uses Weak Cryptography'] = False
    row['WebView JavaScript Enabled'] = False
    
    if isinstance(code_data, dict):
        for key, issue in code_data.items():
            if not isinstance(issue, dict): continue
            desc = str(issue.get('description', '')).lower()
            ref = str(issue.get('metadata', {}).get('ref', '')).lower()
            
            if 'md5' in desc or 'des' in desc or 'ecb' in desc or 'weak_crypto' in ref:
                row['Uses Weak Cryptography'] = True
            
            if 'setjavascriptenabled' in desc and 'true' in desc:
                row['WebView JavaScript Enabled'] = True

    


    ma_list = report.get('manifest_analysis', [])
    if isinstance(ma_list, dict):
        ma_list = ma_list.get('manifest_analysis', [])

    row['Exported Components'] = row.get('Exported Components', 0)
    row['Exported Providers Count'] = row.get('Exported Providers Count', 0)
    row['Allow Backup'] = False
    row['Debuggable'] = False



    row['Cleartext Traffic'] = False

    ma = report.get('manifest_analysis', {})

    findings = ma.get('manifest_findings', [])

    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue

            title = str(item.get('title', '')).lower()
            desc = str(item.get('description', '')).lower()
            rule = str(item.get('rule', '')).lower()

            text = title + " " + desc + " " + rule

            if 'cleartext' in text:
                row['Cleartext Traffic'] = True
                break


    ns = report.get('network_security', {})

    if isinstance(ns, dict):
        network_findings = ns.get('network_findings', [])

        if isinstance(network_findings, list):
            for f in network_findings:
                desc = str(f.get('description', '')).lower()
                if 'http://' in desc:
                    row['Cleartext Traffic'] = True
                    break



    row['Exported Components'] = 0
    row['Exported Providers Count'] = 0

    ma = report.get('manifest_analysis', {})

    findings = ma.get('manifest_findings', [])

    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue

            title = str(item.get('title', '')).lower()
            desc = str(item.get('description', '')).lower()
            rule = str(item.get('rule', '')).lower()

            text = title + " " + desc + " " + rule

            if 'android:exported=true' in text:

            
                row['Exported Components'] += 1

                
                if 'provider' in text:
                    row['Exported Providers Count'] += 1

    row['Allow Backup'] = False

    ma = report.get('manifest_analysis', {})
    findings = ma.get('manifest_findings', [])

    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue

            title = str(item.get('title', '')).lower()
            desc = str(item.get('description', '')).lower()
            rule = str(item.get('rule', '')).lower()

            text = title + " " + desc + " " + rule

           
            if 'allowbackup' in text:
                row['Allow Backup'] = True
                break


    row['Network Security Config Present'] = False

    ma = report.get('manifest_analysis', {})
    findings = ma.get('manifest_findings', [])

    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue

            title = str(item.get('title', '')).lower()
            desc = str(item.get('description', '')).lower()
            rule = str(item.get('rule', '')).lower()

            text = title + " " + desc + " " + rule

            
            if 'networksecurityconfig' in text:
                row['Network Security Config Present'] = True
                break


    row['Certificate Pinning Implemented'] = False

    ns = report.get('network_security', {})

    if isinstance(ns, dict):
        findings = ns.get('network_findings', [])

        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue

                desc = str(f.get('description', '')).lower()
                title = str(f.get('title', '')).lower()

                text = title + " " + desc

                if (
                    'certificate pinning' in text or
                    'ssl pinning' in text or
                    'public key pinning' in text or
                    'pinning detected' in text
                ):
                    row['Certificate Pinning Implemented'] = True
                    break




  
    row['Uses Weak Cryptography'] = False

    weak_keywords = ['md5', 'sha1', 'des', '3des', 'rc4', 'ecb', 'weak crypto', 'insecure crypto']

    crypto = report.get('crypto_analysis', {})
    if isinstance(crypto, dict):
        for val in crypto.values():
            text = str(val).lower()
            if any(k in text for k in weak_keywords):
                row['Uses Weak Cryptography'] = True
                break

    if not row['Uses Weak Cryptography']:
        code_data = report.get('code_analysis', {})
        if isinstance(code_data, dict):
            for issue in code_data.values():
                text = (
                    str(issue.get('title', '')) +
                    str(issue.get('description', '')) +
                    str(issue.get('rule', '')) +
                    str(issue.get('name', ''))
                ).lower()

                if any(k in text for k in weak_keywords):
                    row['Uses Weak Cryptography'] = True
                    break

    if not row['Uses Weak Cryptography']:
        binary = report.get('binary_analysis', [])
        if isinstance(binary, list):
            for item in binary:
                if any(k in str(item).lower() for k in weak_keywords):
                    row['Uses Weak Cryptography'] = True
                    break


    row['WebView JavaScript Enabled'] = False

    android_api = report.get('android_api', {})

    if isinstance(android_api, dict):
        if (
            'api_webview' in android_api and
            'api_javascript_interface_methods' in android_api
        ):
            row['WebView JavaScript Enabled'] = True



    row['Uses Dynamic Code Loading'] = False

    android_api = report.get('android_api', {})

    if isinstance(android_api, dict):

        # Strong indicators
        if 'api_dexloading' in android_api:
            row['Uses Dynamic Code Loading'] = True

        if 'api_dex_manipulate' in android_api:
            row['Uses Dynamic Code Loading'] = True

        if not row['Uses Dynamic Code Loading']:
            if 'api_java_reflection' in android_api:
                row['Uses Dynamic Code Loading'] = True

    row['Browsable Activities Present'] = False

    browsable = report.get('browsable_activities', {})

    if isinstance(browsable, dict) and len(browsable) > 0:
        row['Browsable Activities Present'] = True


    perms = report.get('permissions', {})
    perm_strings = []
    
    if isinstance(perms, list): # Android
        row['Total Permissions'] = len(perms)
        dang_count = 0
        for p in perms:
            if isinstance(p, dict):
                p_name = p.get('name', '') or p.get('title', '')
                perm_strings.append(p_name.lower())
                if p.get('status') == 'dangerous': dang_count += 1
        row['Dangerous Permissions'] = dang_count
    elif isinstance(perms, dict): # iOS
        row['Total Permissions'] = len(perms)
        dang_count = 0
        for p in perms.values():
            if isinstance(p, dict):
                p_desc = p.get('description', '')
                perm_strings.append(p_desc.lower())
                if p.get('status') == 'dangerous': dang_count += 1
        row['Dangerous Permissions'] = dang_count

    full_text = " ".join(perm_strings)
    row['Uses Camera'] = 'camera' in full_text
    row['Uses Location'] = any(x in full_text for x in ['location', 'gps', 'fine', 'coarse'])
    row['Uses Mic'] = any(x in full_text for x in ['record_audio', 'mic', 'microphone'])
    row['Uses Contacts'] = 'contacts' in full_text
    row['Uses SMS'] = 'sms' in full_text
    
    row['PII Collected Types'] = detect_pii(full_text, code_data)

    for col in ['Exported Components', 'Exported Providers Count', 'Ad SDK Count', 'Analytics SDK Count']:
        if row[col] is None: row[col] = 0
        
    for col in COLUMNS:
        if row[col] is None:
             if any(x in col for x in ['Uses ', 'Cleartext', 'Backup', 'Debuggable', 'Present', 'Implemented', 'Enabled', 'Weak']):
                 row[col] = False

    return row

def main():

    if not os.path.exists(INPUT_FOLDER):
        print(f"Error: The folder '{INPUT_FOLDER}' does not exist.")
        print(f"Please create the folder '{INPUT_FOLDER}' and put your .json files in it.")
        return


    files = [f for f in os.listdir(INPUT_FOLDER) if f.endswith('.json')]
    
    if not files:
        print(f"No .json files found in '{INPUT_FOLDER}'.")
        return

    print(f"--- Found {len(files)} JSON reports. Starting batch processing ---")
    
    dataset = []

    for index, file_name in enumerate(files):
        print(f"[{index+1}/{len(files)}] Parsing {file_name}...")
        file_path = os.path.join(INPUT_FOLDER, file_name)
        
        row_data = parse_report_robust(file_path)
        if row_data:
            dataset.append(row_data)

    if dataset:
        print("\nSaving to Excel...")
        df = pd.DataFrame(dataset)
        
        df = df[COLUMNS]
        
        df.to_excel(OUTPUT_FILE, index=False)
        print(f"--- SUCCESS! Processed {len(dataset)} apps. ---")
        print(f"Saved to: {os.path.abspath(OUTPUT_FILE)}")
    else:
        print("No valid data could be extracted from the files.")

if __name__ == "__main__":
    main()
