import platform
import subprocess
import socket
import os
from tqdm import tqdm

def detect_os():
    return platform.system(), platform.version()

def check_open_ports(target):
    open_ports = []
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_firewall():
    if platform.system() == "Windows":
        firewall_status = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                                         stdout=subprocess.PIPE, text=True)
        return firewall_status.stdout
    elif platform.system() == "Linux":
        firewall_status = subprocess.run(["iptables", "-L"],
                                         stdout=subprocess.PIPE, text=True)
        return firewall_status.stdout
    else:
        return "Firewall status not supported on this OS."

def check_bios_info():
    if platform.system() == "Windows":
        bios_info = subprocess.run(["wmic", "bios", "get", "Caption,Version,SerialNumber"],
                                    stdout=subprocess.PIPE, text=True)
        return bios_info.stdout
    elif platform.system() == "Linux":
        bios_info = subprocess.run(["dmidecode", "-t", "bios"],
                                    stdout=subprocess.PIPE, text=True)
        return bios_info.stdout
    else:
        return "BIOS information not supported on this OS."

def check_os_version():
    if platform.system() == "Windows":
        os_version_info = subprocess.run(["systeminfo"], stdout=subprocess.PIPE, text=True)
        return os_version_info.stdout
    elif platform.system() == "Linux":
        os_version_info = subprocess.run(["lsb_release", "-a"], stdout=subprocess.PIPE, text=True)
        return os_version_info.stdout
    else:
        return "OS version information not supported on this OS."

def check_kernel_info():
    if platform.system() == "Windows":
        return "Kernel information not applicable to Windows."
    elif platform.system() == "Linux":
        kernel_info = subprocess.run(["uname", "-a"], stdout=subprocess.PIPE, text=True)
        return kernel_info.stdout
    else:
        return "Kernel information not supported on this OS."

def file_scan():
    total_files = sum(len(files) for _, _, files in os.walk("C:\\"))
    progress = tqdm(total=total_files, unit="file", desc="File Scan", position=0, leave=True)

    vulnerabilities_found = False

    try:
        for foldername, _, filenames in os.walk("C:\\"):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                # Simulate scanning by updating the progress bar
                progress.update(1)

                # Check for vulnerabilities or malicious files (Replace this with actual scanning logic)
                if "malicious" in filename:
                    vulnerabilities_found = True
                    print(f"Vulnerability found: {file_path}")
        progress.close()

        if vulnerabilities_found:
            return "File scan completed. Vulnerabilities found."
        else:
            return "File scan completed. No vulnerable files detected."

    except Exception as e:
        return f"Error during file scan: {str(e)}"

def network_scan(target_ip):
    try:
        result = subprocess.run(["nmap", "-sn", target_ip], stdout=subprocess.PIPE, text=True)
        return result.stdout
    except FileNotFoundError:
        return "Nmap is not installed. Please install it to perform network scanning."

def application_scan():
    try:
        result = subprocess.run(["lynis", "--check-all"], stdout=subprocess.PIPE, text=True)
        return result.stdout
    except FileNotFoundError:
        return "Lynis is not installed. Please install it to perform application scanning."

def main():
    print("[+] Initializing program")
    print("-" * 40)

    print("1. Scan using IP")
    print("2. Install and scan")

    option = input("Choose an option: ")

    if option == "1":
        target_ip = input("Enter the target IP address: ")
        os_name, os_version = detect_os()
        print(f"  - Detecting OS... [DONE]\n"
              f"    - Operating system: {os_name}\n"
              f"    - Operating system version: {os_version}")
    elif option == "2":
        target_ip = "127.0.0.1"  # Use localhost as the target for local installation
        print("Installing and scanning on the same device...")
        os_name, os_version = detect_os()
        print(f"  - Detecting OS... [DONE]\n"
              f"    - Operating system: {os_name}\n"
              f"    - Operating system version: {os_version}")
    else:
        print("Invalid option. Exiting.")
        return

    print("-" * 40)
    print("Boot and services")
    print("-" * 40)

    print("-" * 40)
    print("Users, Groups and Authentication")
    print("-" * 40)

    print("-" * 40)
    print("Software: Firewalls")
    print("-" * 40)
    firewall_status = check_firewall()
    print(firewall_status)

    print("-" * 40)
    print("Checking BIOS Information")
    print("-" * 40)
    bios_info = check_bios_info()
    print(bios_info)

    print("-" * 40)
    print("Checking OS Version")
    print("-" * 40)
    os_version_info = check_os_version()
    print(os_version_info)

    print("-" * 40)
    print("Checking Kernel Information")
    print("-" * 40)
    kernel_info = check_kernel_info()
    print(kernel_info)

    print("-" * 40)
    print("Checking Open Ports")
    print("-" * 40)
    open_ports = check_open_ports(target_ip)
    print("\n+------------+    +------------+")
    print("| Open Ports       Vulnerability |")
    print("+------------+    +------------+")
    for port in open_ports:
        print(f"| {str(port):<6}          Your_Vulnerability_Here |")
    print("+------------+    +------------+")

    print("-" * 40)
    print("File Scan")
    print("-" * 40)
    file_scan_result = file_scan()
    print(file_scan_result)

    print("-" * 40)
    print("Network Scan")
    print("-" * 40)
    network_scan_result = network_scan(target_ip)
    print(network_scan_result)

    print("-" * 40)
    print("Application Scan")
    print("-" * 40)
    application_scan_result = application_scan()
    print(application_scan_result)

if __name__ == "__main__":
    main()
