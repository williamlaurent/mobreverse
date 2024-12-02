# stop recoded code kids
# github.com/williamlaurent
# just for education or ethical hacking

import os
import zipfile
import shutil
import re
from bs4 import BeautifulSoup

def detect_hardcoded_keys(apk_path):
    extracted_path = apk_path.replace(".apk", "")
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall(extracted_path)

    key_patterns = [
        r'api_key=[\w-]+',
        r'secret_key=[\w-]+',
        r'token=[\w-]+',
        r'password=[\w-]+',
        r'encryption_key=[\w-]+'
    ]

    hardcoded_keys = []

    for root, dirs, files in os.walk(extracted_path):
        for file in files:
            if file.endswith('.xml') or file.endswith('.smali'):
                with open(os.path.join(root, file), 'r', errors='ignore') as f:
                    content = f.read()
                    for pattern in key_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            hardcoded_keys.extend(matches)

    shutil.rmtree(extracted_path)

    return hardcoded_keys

def identify_excessive_permissions(apk_path):
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        with zip_ref.open('AndroidManifest.xml') as manifest_file:
            manifest_content = manifest_file.read().decode('utf-8', errors='ignore')

    soup = BeautifulSoup(manifest_content, 'xml')
    permissions = soup.find_all('uses-permission')

    excessive_permissions = []

    for permission in permissions:
        perm = permission.get('android:name')
        if perm:
            excessive_permissions_list = [
                'android.permission.READ_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.CALL_PHONE',
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.READ_EXTERNAL_STORAGE'
            ]
            if perm in excessive_permissions_list:
                excessive_permissions.append(perm)

    return excessive_permissions

def static_analysis(apk_path):
    extracted_path = apk_path.replace(".apk", "")
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall(extracted_path)

    analyzed_files = []

    for root, dirs, files in os.walk(extracted_path):
        for file in files:
            analyzed_files.append((file, os.path.getsize(os.path.join(root, file))))

    shutil.rmtree(extracted_path)

    return analyzed_files

def repackaging_detection(apk_path):
    # Placeholder for repackaging detection logic
    return "Repackaging detection not implemented"

if __name__ == "__main__":
    apk_path = "CHANGE APK HERE.apk"

    print("Detected Hardcoded Keys:")
    hardcoded_keys = detect_hardcoded_keys(apk_path)
    for key in hardcoded_keys:
        print(key)

    print("\nExcessive Permissions:")
    excessive_permissions = identify_excessive_permissions(apk_path)
    for perm in excessive_permissions:
        print(perm)

    print("\nStatic Analysis (Files Listed):")
    analyzed_files = static_analysis(apk_path)
    for file, size in analyzed_files:
        print(f"{file} - {size} bytes")

    print("\nRepackaging Detection:")
    repackaging_result = repackaging_detection(apk_path)
    print(repackaging_result)
