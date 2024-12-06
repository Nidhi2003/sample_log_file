# sample_log_file
# Objective:
This script is analyzing a log file to:

Find how many requests each IP address has made.
Identify the most frequently accessed endpoint (e.g., /home, /login).
Detect suspicious activity, such as repeated failed login attempts.

# Code Breakdown:
# Step 1: 
Read the Log File
The function read_log_file:

Opens the log file and reads its contents line by line.
If the file isn't found, it shows an error message.

# Step 2: 
Extract IP Addresses
The function extract_ip_addresses:

Finds all IP addresses (like 192.168.1.1) in the logs using a pattern (regular expression).
Returns a list of these IPs.

# Step 3: 
Count Requests by Each IP
The function count_requests_by_ip:

Counts how many times each IP appears using Python's Counter.
Example: If an IP appears 5 times, it means that IP made 5 requests.

# Step 4: 
Display Request Counts
The function `display
