import re
import json
import csv
import requests
from collections import defaultdict
from datetime import datetime

def extract_log_data(log_file_path):
    """
    Log faylından IP ünvanlarını, tarixləri və HTTP metodlarını çıxarır.
    """
    log_data = []
    ip_failure_count = defaultdict(int)
    
    with open(log_file_path, 'r') as file:
        for line in file:
            # Regex ilə log məlumatlarını çıxarma
            match = re.search(r'(\d+\.\d+\.\d+\.\d+) .* \[(.*?)\] "(.*?)" (\d+)', line)
            
            if match:
                ip_address = match.group(1)
                date_str = match.group(2)
                http_method = match.group(3).split()[0]
                status_code = (match.group(4))
                
                # Uğursuz giriş cəhdlərini hesablama
                #for num in range(400,500):

                if status_code.startswith('4'):
                        ip_failure_count[ip_address] += 1
                
                log_data.append({
                    'ip_address': ip_address,
                    'date': date_str,
                    'http_method': http_method,
                    'status_code': status_code
                    })
    
        return log_data, ip_failure_count

def find_failed_login_ips(ip_failure_count, threshold=5):
    """
    5-dən çox uğursuz giriş cəhdi olan IP ünvanlarını müəyyən edir.
    """
    return {ip: count for ip, count in ip_failure_count.items() if count > threshold}

def check_threat_intelligence(ip_addresses):
    """
    IP ünvanlarını təhdid kəşfiyyatı üçün yoxlayır.
    Nümunə üçün sadə bir funksiya (gerçək bir API ilə əvəz edilə bilər)
    """
    threat_ips = []
    for ip in ip_addresses:
        threat_ips.append(ip)
    return threat_ips

def write_json_file(data, filename):
    """
    Məlumatları JSON faylına yazır.
    """
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def write_text_file(data, filename):
    """
    Məlumatları mətn faylına yazır.
    """
    with open(filename, 'w') as f:
        for ip, count in data.items():
            f.write(f"IP: {ip}, Uğursuz Cəhdlər: {count}\n")

def write_csv_file(log_data, filename):
    """
    Məlumatları CSV faylına yazır.
    """
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP Ünvanı', 'Tarix', 'HTTP Metodu', 'Uğursuz Cəhdlər']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for entry in log_data:
            writer.writerow({
                'IP Ünvanı': entry['ip_address'],
                'Tarix': entry['date'],
                'HTTP Metodu': entry['http_method'],
                'Uğursuz Cəhdlər': 0  # Əlavə hesablama məntiqinə görə dəyişdirilə bilər
            })

def main():
    # Log faylı yolu
    log_file_path = 'server_logs.txt'
    
    # Log məlumatlarını çıxarma
    log_data, ip_failure_count = extract_log_data(log_file_path)
    
    # Uğursuz giriş cəhdləri olan IP ünvanları
    failed_login_ips = find_failed_login_ips(ip_failure_count)
    write_json_file(failed_login_ips, 'failed_logins.json')
    
    # Təhdid kəşfiyyatı
    threat_ips = check_threat_intelligence(list(ip_failure_count.keys()))
    write_json_file(threat_ips, 'threat_ips.json')
    
    # Birləşdirilmiş təhlükəsizlik məlumatları
    combined_security_data = {
        'failed_logins': failed_login_ips,
        'threat_ips': threat_ips
    }
    write_json_file(combined_security_data, 'combined_security_data.json')
    
    # Mətn faylına yazma
    write_text_file(ip_failure_count, 'log_analysis.txt')
    
    # CSV faylına yazma
    write_csv_file(log_data, 'log_analysis.csv')

if __name__ == "__main__":
    main()
