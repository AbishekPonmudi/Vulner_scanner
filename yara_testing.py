# This is written by Havox@ CYberNet #
# @CopyRight under MIT LICENCE #
# Author = "@HaVoX#"
# $+++++++++++++++++++++++++++++++++++++++++++++++++++++++$#

# import os
# import pefile

# # List of suspicious strings for each malware type
# HEURISTIC_STRINGS = {
#     'Trojan_Generic': [
#         b'This program cannot be run in DOS mode',
#         b'maliciousfunction',
#         b'backdoor',
#         b'rat',
#         b'keylogger'
#     ],
#     'Ransomware_Generic': [
#         b'Your files have been encrypted',
#         b'All your files are encrypted',
#         b'Decrypt your files',
#         b'.locked',
#         b'.crypt',
#         b'.enc'
#     ],
#     'Spyware_Generic': [
#         b'CaptureScreenshot',
#         b'KeyLogger',
#         b'StealPassword',
#         b'BrowserHistory'
#     ],
#     'Worm_Generic': [
#         b'SpreadToNetwork',
#         b'CopyToUSB',
#         b'NetworkPropagation',
#         b'EmailSpread'
#     ],
#     'ExploitKit_Generic': [
#         b'Exploit',
#         b'Shellcode',
#         b'ExploitPayload',
#         b'ExploitKit'
#     ],
#     'Packed_Malware_Generic': [
#         b'UPX0',
#         b'MEW',
#         b'FSG',
#         b'PECompact',
#         b'ASPack'
#     ],
#     'KnownMalwareFamily': [
#         b'\xE8\x00\x00\x00\x00\x5D\xC3',
#         b'\x6A\x40\x68\x00\x30\x00\x00',
#         b'\x60\x89\xE5\x31\xC0\x64\x8B\x50\x30',
#         b'\x68\x8D\x4C\x24\x04\x89\xE1\x6A\x10'
#     ],
#     'Obfuscated_Malware_Generic': [
#         b'Function1',
#         b'Function2',
#         b'EncodedPayload',
#         b'ObfuscatedCode',
#         b'\x8B\x45\x0C\x89\x45\xFC\x8B\x45\x10'
#     ],
#     'Polymorphic_Malware_Generic': [
#         b'PolymorphicEngine',
#         b'CodeMutation',
#         b'VariableEncryption'
#     ],
#     'Fileless_Malware_Generic': [
#         b'Powershell',
#         b'Invoke-Mimikatz',
#         b'ReflectiveLoader'
#     ]
# }

# def is_suspicious_file(file_path):
#     try:
#         if not os.access(file_path, os.R_OK):
#             return None  # Skip files that cannot be read

#         pe = pefile.PE(file_path)
        
#         # Check for high entropy sections (indicative of packing)
#         for section in pe.sections:
#             if section.get_entropy() > 7.5:
#                 return 'Packed_Malware_Generic'

#         # Check for suspicious imports
#         if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
#             suspicious_imports = ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc']
#             for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                 for imp in entry.imports:
#                     if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
#                         return 'Trojan_Generic'

#         # Check for unusual section names
#         for section in pe.sections:
#             section_name = section.Name.decode('utf-8', 'ignore').strip()
#             if section_name not in ['.text', '.data', '.rdata']:
#                 return 'Obfuscated_Malware_Generic'

#         # Check for suspicious strings in file content
#         with open(file_path, 'rb') as f:
#             content = f.read()
#             for malware_type, strings in HEURISTIC_STRINGS.items():
#                 if any(s in content for s in strings):
#                     return malware_type

#         return None
    
#     except pefile.PEFormatError:
#         return None
#     except PermissionError:
#         return None  # Skip files that cannot be accessed due to permission errors
#     except Exception as e:
#         print(f"Error processing file {file_path}: {e}")
#         return None

# def scan_files(directory="C:\\"):
#     suspicious_files = {}
#     for root, _, files in os.walk(directory):
#         for file in files:
#             file_path = os.path.join(root, file)
#             try:
#                 result = is_suspicious_file(file_path)
#                 if result:
#                     if file_path not in suspicious_files:
#                         suspicious_files[file_path] = []
#                     suspicious_files[file_path].append(result)
#             except PermissionError:
#                 print(f"Permission denied: {file_path}")  # Log the permission error
#             except Exception as e:
#                 print(f"Error scanning file {file_path}: {e}")  # Log other errors
#     return suspicious_files

# # Example usage
# suspicious_files = scan_files()
# if suspicious_files:
#     print("Malware files found:")
#     for file, types in suspicious_files.items():
#         print(f"{file}")
#         for malware_type in types:
#             print(f"  - {malware_type}")
# else:
#     print("No suspicious files found.")


# import yara
# import os

# def scan_file(file_path, rule_path):
#     try:
#         # Compile the YARA rules
#         rules = yara.compile(filepath=rule_path)
#         # Match the rules against the file
#         matches = rules.match(file_path)
#         if matches:
#             print(f"Malware file found: {file_path}")
#             # matches the files with the YARA rules 
#             for match in matches:
#                 print(f"- Types : {match.rule} , Location : {file_path}")
#         else:
#             print(f"No malware found in: {file_path}")
    
#     except yara.Error as e:
#         print(f"Error scanning {file_path}: {e}")

# file_path = "windows11.exe"
# rule_path = r"rules_yara.yar"

# scan_file(file_path, rule_path)

# # if __name__ == "__main__":
# #     root = ["C:\\"] if os.name = 'nt' else ['/']



# YARA WORKING SCRIPT WITH THE INTEGRATION OF THE PEFILE HEADER DETECTION 

# import os
# import yara
# import pefile
# import logging

# # Set up logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Path to the YARA rules file
# YARA_RULES_FILE = "rules_yara.yar"

# # Load YARA rules
# try:
#     rules = yara.compile(filepath=YARA_RULES_FILE)
# except yara.SyntaxError as e:
#     logging.error(f"YARA syntax error: {e}")
#     exit(1)

# def scan_with_yara(file_path):
#     try:
#         matches = rules.match(file_path)
#         return matches
#     except yara.Error as e:
#         logging.error(f"YARA error scanning file {file_path}: {e}")
#         return None

# def analyze_with_pefile(file_path):
#     try:
#         pe = pefile.PE(file_path)

#         # Check for high entropy sections (indicative of packing)
#         for section in pe.sections:
#             if section.get_entropy() > 7.5:
#                 return "Packed_Malware_Generic"

#         # Check for suspicious imports
#         if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
#             suspicious_imports = ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc']
#             for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                 for imp in entry.imports:
#                     if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
#                         return "Trojan_Generic"

#         # Check for unusual section names
#         for section in pe.sections:
#             section_name = section.Name.decode('utf-8', 'ignore').strip()
#             if section_name not in ['.text', '.data', '.rdata']:
#                 return "Obfuscated_Malware_Generic"

#         return None
#     except pefile.PEFormatError:
#         return None
#     except PermissionError:
#         logging.warning(f"Permission denied: {file_path}")
#         return None
#     except Exception as e:
#         logging.error(f"Error analyzing file with pefile {file_path}: {e}")
#         return None

# def scan_directory(directory):
#     suspicious_files = {}
#     for root, _, files in os.walk(directory):
#         for file in files:
#             file_path = os.path.join(root, file)
#             try:
#                 yara_matches = scan_with_yara(file_path)
#                 pefile_analysis = analyze_with_pefile(file_path)

#                 if yara_matches or pefile_analysis:
#                     if file_path not in suspicious_files:
#                         suspicious_files[file_path] = []

#                     if yara_matches:
#                         suspicious_files[file_path].extend(str(match) for match in yara_matches)

#                     if pefile_analysis:
#                         suspicious_files[file_path].append(pefile_analysis)

#             except PermissionError:
#                 logging.warning(f"Permission denied: {file_path}")
#             except Exception as e:
#                 logging.error(f"Error scanning file {file_path}: {e}")
#     return suspicious_files

# # Example usage
# if __name__ == "__main__":
#     directory_to_scan = "C:\\"  # Set the directory you want to scan
#     logging.info(f"Starting scan in directory: {directory_to_scan}")
#     suspicious_files = scan_directory(directory_to_scan)
#     if suspicious_files:
#         logging.info("Malware files found:")
#         for file, types in suspicious_files.items():
#             logging.info(f"{file}")
#             for malware_type in types:
#                 logging.info(f"  - {malware_type}")
#     else:
#         logging.info("No suspicious files found.")


# ADDING PE AND YARA WITH EXIXTING SIGNATURE FILE SCANNING AND HASH SCANNING CODE 

import hashlib
import os
import sys
import logging
import win32com.shell.shell as shell
import yara
import pefile
from tqdm import tqdm

# Set this code to run as admin using the python
ADMIN = "adadmin"
if sys.argv[-1] != ADMIN:
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([script] + sys.argv[1:] + [ADMIN])
    shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)

# Load YARA rules
YARA_RULES_FILE = "rules_yara.yar"
try:
    rules = yara.compile(filepath=YARA_RULES_FILE)
except yara.SyntaxError as e:
    logging.error(f"YARA syntax error: {e}")
    exit(1)

# Load malicious hashes from the idx file
def load_malicious_hashes(file_path='malicious_hashes.idx'):
    malicious_hashes = set()
    try:
        with open(file_path, 'r') as f:
            for line in f:
                hash = line.split('|')[0].strip()
                if hash:
                    malicious_hashes.add(hash)
    except FileNotFoundError:
        print(f"{file_path} not found. Please make sure the file exists.")
    return malicious_hashes

# Calculate the hash of the file in the system with the root files
def cal_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte in iter(lambda: f.read(4096), b""):
                sha256.update(byte)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        print(f"Skipping the file {file_path}: {e}")
        return None

# Scan a file with YARA rules
def scan_with_yara(file_path):
    try:
        matches = rules.match(file_path)
        return matches
    except yara.Error as e:
        logging.error(f"YARA error scanning file {file_path}: {e}")
        return None

# Analyze a file with PEfile
def analyze_with_pefile(file_path):
    try:
        pe = pefile.PE(file_path)
        # Check for high entropy sections (indicative of packing)
        for section in pe.sections:
            if section.get_entropy() > 7.5:
                return "Packed_Malware_Generic"
        # Check for suspicious imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            suspicious_imports = ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc']
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
                        return "Trojan_Generic"
        # Check for unusual section names
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip()
            if section_name not in ['.text', '.data', '.rdata']:
                return "Obfuscated_Malware_Generic"
        return None
    except pefile.PEFormatError:
        return None
    except PermissionError:
        logging.warning(f"Permission denied: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error analyzing file with pefile {file_path}: {e}")
        return None

# Scan the root directory for the malicious content with file path and hash values from the table or API
def scan_directory(root):
    file_paths = []
    for dirpath, _, filenames in os.walk(root):
        for file in filenames:
            file_paths.append(os.path.join(dirpath, file))
    return file_paths

# Determine the system status based on the count of malicious files detected
def determine_system_status(malicious_count):
    if malicious_count == 0:
        return "Everything up to date"
    elif malicious_count < 10:
        return "Normal"
    elif malicious_count < 50:
        return "Warning"
    else:
        return "Critical"

# Main function to scan files for malicious content
if __name__ == "__main__":
    root_dir = ['C:\\'] if os.name == 'nt' else ['/']
    malicious_hashes = load_malicious_hashes()
    total_files = 0
    malicious_count = 0
    malicious_files = []

    # Gather all file paths
    file_paths = []
    for root in root_dir:
        file_paths.extend(scan_directory(root))
    total_files = len(file_paths)

    # Scan files with progress bar
    with tqdm(total=total_files, desc="Scanning Files", unit="file") as pbar:
        for file_path in file_paths:
            results = []

            # Scan with hash
            file_hash = cal_hash(file_path)
            if file_hash and file_hash in malicious_hashes:
                results.append(f"Hash match: {file_path} - {file_hash}")

            # Scan with YARA
            yara_matches = scan_with_yara(file_path)
            if yara_matches:
                for match in yara_matches:
                    results.append(f"YARA match: {file_path} - {match}")

            # Scan with PEfile
            pefile_analysis = analyze_with_pefile(file_path)
            if pefile_analysis:
                results.append(f"PEfile analysis: {file_path} - {pefile_analysis}")

            if results:
                malicious_files.extend(results)
                malicious_count += 1

            pbar.update(1)

    # Display the results
    print(f"\nScanning complete. {malicious_count} malicious files detected.")
    for result in malicious_files:
        print(result)
    system_status = determine_system_status(malicious_count)
    print(f"System status: {system_status}")

    # Print the paths of detected malicious files
    if malicious_files:
        print("\nMalicious file paths:")
        for result in malicious_files:
            print(result)

