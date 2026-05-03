import requests
import os
import json
import re

# --- CONFIGURATION ---
MOBSF_URL = 'http://localhost:8000'
API_KEY = '8c6bf9b24a259109d0ff54c77498237576bd24761494d01bb1e57b5b9d5db0c3'
OUTPUT_FOLDER = 'json_reports'

def get_all_scans():
    """Fetches ALL apps by looping through pages."""
    all_scans = []
    page = 1
    headers = {'Authorization': API_KEY}
    
    print("Fetching scan history...")

    while True:
        try:
            # Check page 1, 2, 3...
            response = requests.get(f'{MOBSF_URL}/api/v1/scans?page={page}&page_size=100', headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                # Support both 'content' (New MobSF) and 'scans' (Old MobSF)
                current_page_scans = data.get('content', data.get('scans', []))
                
                if not current_page_scans:
                    break 
                
                all_scans.extend(current_page_scans)
                print(f"  -> Page {page}: Found {len(current_page_scans)} apps...")
                
                if 'num_pages' in data and page >= data['num_pages']:
                    break
                elif 'num_pages' not in data: # Legacy support
                    break
                
                page += 1
            else:
                print(f"Error fetching history: {response.status_code}")
                break
        except Exception as e:
            print(f"Connection Error: {e}")
            break
            
    return all_scans

def download_report(file_hash, file_name):
    headers = {'Authorization': API_KEY}
    data = {'hash': file_hash}
    try:
        response = requests.post(f'{MOBSF_URL}/api/v1/report_json', data=data, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def sanitize_filename(name):
    # Remove invalid characters for filenames
    return re.sub(r'[\\/*?:"<>|]', "", str(name)).replace(" ", "_").strip()

def main():
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    scans = get_all_scans()
    if not scans:
        print("No scans found.")
        return

    print(f"\nProcessing {len(scans)} apps...\n")

    for index, app in enumerate(scans):
        # 1. Get Hash (Using UPPERCASE key from your debug log)
        file_hash = app.get('MD5') or app.get('md5') or app.get('hash')
        if not file_hash: 
            print(f"[{index+1}] Skipping (No hash found)")
            continue

        # 2. SMART NAME RESOLUTION (Fixed for UPPERCASE keys)
        # Check APP_NAME first, then FILE_NAME, then PACKAGE_NAME
        raw_name = app.get('APP_NAME')
        
        if not raw_name or raw_name == "Unknown":
            raw_name = app.get('FILE_NAME')
            
        if not raw_name:
            raw_name = app.get('PACKAGE_NAME')
            
        if not raw_name:
            raw_name = "unknown_app"

        # 3. Create Filename
        safe_name = sanitize_filename(raw_name)
        output_filename = f"{safe_name}_{file_hash[:8]}.json"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)

        if os.path.exists(output_path):
            print(f"[{index+1}] Skipping {safe_name} (Exists)")
            continue

        print(f"[{index+1}] Downloading: {safe_name}...")
        report = download_report(file_hash, safe_name)
        
        if report:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4)
            print("  -> Saved.")

    print(f"\nDone! Check '{OUTPUT_FOLDER}' folder.")

if __name__ == "__main__":
    main()
