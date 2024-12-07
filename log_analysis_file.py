import sys
import re
import csv
from collections import Counter

def parse_log_file(log_file): #log_file reading function
    ip_requests = Counter()
    endpoints = Counter()
    failed_logins = Counter()
    
    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP Address
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)# IP Address
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1
            
            # Extract Endpoint
            endpoint_match = re.search(r'\"[A-Z]+\s(\S+)', line) #Path
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoints[endpoint] += 1
            
            # Check for Failed Login
            if '401' in line or 'Invalid credentials' in line: #failed login count  
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoints, failed_logins


def save_to_csv(ip_requests, most_accessed, failed_logins, output_file='log_analysis_results.csv'):
   # CSV file save function
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        
        writer.writerow(["IP Address", "Request Count"]) #Counting Requests per IP Address:
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])# Identifying the Most Frequently Accessed Endpoint
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])#Detecting Suspicious Activity
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])


def main():
    if len(sys.argv) < 2:
        print("Usage: python log_analysis.py [threshold] <log_file>")
        sys.exit(1)
    
    try:
        # Default threshold to 10 if not provided
        if len(sys.argv) == 2:
            threshold = 10
            log_file = sys.argv[1]
        else:
            threshold = int(sys.argv[1])
            log_file = sys.argv[2]
    except ValueError:
        print("Threshold must be an integer.")
        sys.exit(1)

    try:
        
        ip_requests, endpoints, failed_logins = parse_log_file(log_file)# Parse log file
        
        print("IP Address           Request Count")# Sort and display results
        for ip, count in ip_requests.most_common():
            print(f"{ip:<20} {count}")

        most_accessed = endpoints.most_common(1)[0]
        print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        flagged_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
        for ip, count in flagged_ips.items():
            print(f"{ip:<20} {count}")
        
       
        save_to_csv(ip_requests, most_accessed, flagged_ips) # Save results to CSV
        print("\nResults saved to 'log_analysis_results.csv'")
    
    except FileNotFoundError:
        print(f"Log file '{log_file}' not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
