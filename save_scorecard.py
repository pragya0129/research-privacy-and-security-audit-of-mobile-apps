import requests
import os
import json
import re

# --- CONFIGURATION ---
# 1. MobSF URL
MOBSF_URL = 'http://localhost:8000'

# 2. Your API Key (Replace with your actual key)
API_KEY = '8c6bf9b24a259109d0ff54c77498237576bd24761494d01bb1e57b5b9d5db0c3'

# 3. Output Folder
OUTPUT_FOLDER = 'app_scorecard'

def get_all_scans():
    """Fetches ALL apps by looping through history pages."""
    all_scans = []
    page = 1
    headers = {'Authorization': API_KEY}
    
    print("Fetching scan history...")

    while True:
        try:
            # Request scan history with pagination
            response = requests.get(f'{MOBSF_URL}/api/v1/scans?page={page}&page_size=100', headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                
                # Support both 'content' (New) and 'scans' (Old) keys
                current_page_scans = data.get('content', data.get('scans', []))
                
                if not current_page_scans:
                    break 
                
                all_scans.extend(current_page_scans)
                print(f"  -> Page {page}: Found {len(current_page_scans)} apps...")
                
                # Check if there are more pages
                if 'num_pages' in data:
                    if page >= data['num_pages']:
                        break
                else:
                    break # Assume no pagination if num_pages is missing
                
                page += 1
            else:
                print(f"Error fetching history: {response.status_code}")
                break
        except Exception as e:
            print(f"Connection Error: {e}")
            break
            
    return all_scans

def get_scorecard(file_hash, app_name):
    """Fetches the Scorecard JSON for a specific hash."""
    url = f'{MOBSF_URL}/api/v1/scorecard'
    headers = {'Authorization': API_KEY}
    data = {'hash': file_hash}
    
    try:
        response = requests.post(url, data=data, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 422:
            print(f"  [!] Scorecard not generated yet for {app_name}")
            return None
        else:
            print(f"  [!] API Error {response.status_code} for {app_name}")
            return None
            
    except Exception as e:
        print(f"  [!] Connection Error for {app_name}: {e}")
        return None

def sanitize_filename(name):
    """Cleans filename for saving."""
    return re.sub(r'[\\/*?:"<>|]', "", str(name)).replace(" ", "_").strip()

def main():
    # 1. Create Output Folder
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
        print(f"Created folder: {OUTPUT_FOLDER}")

    # 2. Get Scan History
    scans = get_all_scans()
    if not scans:
        print("No scans found in history.")
        return

    print(f"\nProcessing {len(scans)} apps...\n")

    # 3. Download Scorecards
    for index, app in enumerate(scans):
        # Handle Uppercase Keys (Specific to your MobSF version)
        file_hash = app.get('MD5') or app.get('md5') or app.get('hash')
        
        if not file_hash:
            print(f"[{index+1}] Skipping (No hash found)")
            continue

        # Smart Naming (APP_NAME -> FILE_NAME -> PACKAGE_NAME)
        raw_name = app.get('APP_NAME')
        if not raw_name or raw_name == "Unknown":
            raw_name = app.get('FILE_NAME')
        if not raw_name:
            raw_name = app.get('PACKAGE_NAME')
        if not raw_name:
            raw_name = "unknown_app"

        safe_name = sanitize_filename(raw_name)
        output_filename = f"{safe_name}_scorecard.json"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)

        # Skip if already exists
        if os.path.exists(output_path):
            print(f"[{index+1}/{len(scans)}] Skipping {safe_name} (Exists)")
            continue

        print(f"[{index+1}/{len(scans)}] Downloading Scorecard: {safe_name}...")
        
        scorecard_json = get_scorecard(file_hash, safe_name)
        
        if scorecard_json:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(scorecard_json, f, indent=4)
            print("  -> Saved.")

    print(f"\n--- DONE! Scorecards saved in '{OUTPUT_FOLDER}' ---")

if __name__ == "__main__":
    main()
