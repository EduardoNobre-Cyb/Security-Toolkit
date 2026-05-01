import requests
import hashlib
import os

api_key = "77a1b44dc96bae47ecb8ac2f42449c5ee237ccab6e8cc2f35b3dec1cc6b5b913"

print("VirusTotal File Checker")
print("1. Check file hash (faster, more private)")
print("2. Upload and scan file (for new/unknown files)")
choice = input("Choose option (1/2): ")

if choice == "1":
    # Option 1: Check existing hash
    file_path = input("Enter file path: ")
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found!")
    else:
        print("Calculating file hash...")
        file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
        print(f"SHA256: {file_hash}")
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        
        print("Checking with VirusTotal...")
        response = requests.get(url, headers=headers)

        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            print(f"\nResults:")
            print(f"Malicious: {stats['malicious']}")
            print(f"Suspicious: {stats['suspicious']}")
            print(f"Undetected: {stats['undetected']}")
            print(f"Harmless: {stats['harmless']}")

            # Filter and display malicious results
            results = data['data']['attributes']['last_analysis_results']
            malicious_results = []
            for engine, result in results.items():
                if result['category'] == 'malicious':
                    malicious_results.append({
                        'engine': engine,
                        'detection': result['result']
                    })

            if malicious_results:
                print(f"\n⚠️ Detected by {len(malicious_results)} engines:")
                for item in malicious_results:
                    print(f"  - {item['engine']}: {item['detection']}")
            
            if stats['malicious'] > 0:
                print("\n⚠️ WARNING: File flagged as malicious!")
            else:
                print("\n✓ File appears clean.")
        elif response.status_code == 404:
            print("File hash not found in VirusTotal database. Try option 2 to upload and scan.")
        else:
            print(f"Error: {response.status_code} - {response.text}")

elif choice == "2":
    # Option 2: Upload and scan file
    file_path = input("Enter file path: ")
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found!")
    else:
        print("Uploading file to VirusTotal...")
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": api_key}
        
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, headers=headers, files=files)
        
        if response.status_code == 200:
            data = response.json()
            analysis_id = data['data']['id']
            print(f"\nFile uploaded successfully!")
            print(f"Analysis ID: {analysis_id}")
            print("Note: Analysis may take a few minutes. Check results later.")
        else:
            print(f"Error: {response.status_code} - {response.text}")
else:
    print("Invalid choice!")