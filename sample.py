import re
import csv
from collections import Counter

def read_log_file(file_path):
    """Reads the log file line by line and returns the content."""
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
        return logs
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []
    
def extract_ip_addresses(logs):
    """Extracts all IP addresses from the log entries."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_addresses = []
    for log in logs:
        match = re.search(ip_pattern, log)
        if match:
            ip_addresses.append(match.group())
    return ip_addresses

def count_requests_by_ip(ip_addresses):
    """Counts the number of requests made by each IP address."""
    return Counter(ip_addresses)

def display_results(ip_counts):
    """Displays the results in a formatted table."""
    print(f"{'IP Address':<20}{'Request Count':<15}")
    print("-" * 35)
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20}{count:<15}")

def extract_endpoints(logs):
    """Extracts all endpoints (URLs or paths) from the log entries."""
    # Assuming the log format includes a URL or resource path as part of the entry
    # Example: "2024-12-05 10:23:45, INFO, 192.168.0.1, GET /home"
    endpoint_pattern = r'(GET|POST|PUT|DELETE)\s(/[\w\-/]*)'
    endpoints = []
    for log in logs:
        match = re.search(endpoint_pattern, log)
        if match:
            endpoints.append(match.group(2))  # Extract the URL path
    return endpoints

def find_most_frequent_endpoint(endpoints):
    """Finds the most frequently accessed endpoint."""
    endpoint_counts = Counter(endpoints)
    most_frequent = endpoint_counts.most_common(1)
    return most_frequent[0] if most_frequent else None

def extract_failed_logins(logs):
    """Extracts IP addresses associated with failed login attempts."""
    # Assuming log format contains HTTP status code or failure message
    # Example: "2024-12-05 10:23:45, INFO, 192.168.1.100, Invalid credentials"
    failure_pattern = r'(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b).*?(Invalid credentials|401)'
    failed_ips = []
    for log in logs:
        match = re.search(failure_pattern, log)
        if match:
            failed_ips.append(match.group("ip"))
    return failed_ips

def detect_suspicious_ips(failed_ips, threshold=10):
    """Identifies IPs exceeding the failed login attempt threshold."""
    ip_counts = Counter(failed_ips)
    suspicious_ips = {ip: count for ip, count in ip_counts.items() if count > threshold}
    return suspicious_ips

def display_results1(suspicious_ips):
    """Displays flagged IP addresses and their failed login counts."""
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<25}")
        print("-" * 45)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<25}")
    else:
        print("No suspicious activity detected.")

def save_to_csv(ip_counts, most_frequent, suspicious_ips):
    """Saves the results to a CSV file."""
    with open("log_analysis_results.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if most_frequent:
            writer.writerow([most_frequent[0], most_frequent[1]])

        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def main():
    # Path to the log file
    file_path = "C:\\Users\\Nidhi\\OneDrive\\Desktop\\sample.log"
    # Step 1: Read the log file
    logs = read_log_file(file_path)

    # Step 2: Extract IP addresses
    ip_addresses = extract_ip_addresses(logs)

    # Step 3: Count requests by IP
    ip_counts = count_requests_by_ip(ip_addresses)

    # Step 4: Display the results
    display_results(ip_counts)

    # Step 5: Extract endpoints
    endpoints = extract_endpoints(logs)

    # Step 6: Find the most frequently accessed endpoint
    most_frequent = find_most_frequent_endpoint(endpoints)

    # Step 7: Display the result
    if most_frequent:
        endpoint, count = most_frequent
        print(f"Most Frequently Accessed Endpoint:")
        print(f"{endpoint} (Accessed {count} times)")
    else:
        print("No endpoints found in the log file.")

    threshold=10

    failed_ips = extract_failed_logins(logs)

    # Step 8: Detect suspicious IPs
    suspicious_ips = detect_suspicious_ips(failed_ips, threshold)

    # Step 9: Display the results
    print("Suspicious Activity Detected:")
    display_results1(suspicious_ips)

    # Step 10: Save results to CSV
    save_to_csv(ip_counts, most_frequent, suspicious_ips)
    print("\nResults saved to 'log_analysis_results.csv'.")


if __name__ == "__main__":
    main()
