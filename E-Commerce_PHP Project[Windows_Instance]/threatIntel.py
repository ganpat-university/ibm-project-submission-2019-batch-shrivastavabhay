import re
import datetime
from collections import deque

# Set the threshold for suspicious request frequency
THRESHOLD = 10

# Set the regular expression patterns for different types of requests
SQL_INJECTION_PATTERN = r"(?i)(union|select|from|where|and|or|group by|order by|having)"
XSS_PATTERN = r"(?i)(<script|alert\(|onerror|javascript)"

# Set the list of suspicious IP addresses
SUSPICIOUS_IPS = ["10.0.0.1", "192.168.0.1", "127.0.0.1"]

# Set the list of suspicious user agents
SUSPICIOUS_UAS = ["Wget", "curl", "python", "python-requests"]

# Set the window size for anomaly detection
WINDOW_SIZE = 100

# Set the threshold for anomaly detection
ANOMALY_THRESHOLD = 3.0

# Define a function to parse the log file and detect suspicious requests
def detect_malicious_requests(log_file_path):
    # Create a deque to store the timestamps of the most recent requests
    request_times = deque(maxlen=WINDOW_SIZE)
    # Create a dictionary to store the frequency of requests by IP address
    ip_frequency = {}
    # Open the log file
    with open(log_file_path, "r") as log_file:
        # Loop through each line in the log file
        for line in log_file:
            # Split the line into its fields
            fields = line.split()
            # Extract the IP address, user agent, and request path from the fields
            ip_address = fields[0]
            user_agent = fields[11]
            request_path = fields[6]
            # Extract the timestamp from the fields and convert it to a datetime object
            timestamp_str = " ".join(fields[3:5])
            timestamp = datetime.datetime.strptime(timestamp_str, "[%d/%b/%Y:%H:%M:%S %z]")
            # Check if the IP address or user agent is suspicious
            if ip_address in SUSPICIOUS_IPS or user_agent in SUSPICIOUS_UAS:
                print(f"Suspicious request detected at {timestamp}: {line}")
            else:
                # Check if the request path matches any of the suspicious patterns
                if re.search(SQL_INJECTION_PATTERN, request_path) or re.search(XSS_PATTERN, request_path):
                    print(f"Suspicious request detected at {timestamp}: {line}")
                else:
                    # Add the timestamp to the deque of recent requests
                    request_times.append(timestamp)
                    # Increment the frequency count for the IP address
                    ip_frequency[ip_address] = ip_frequency.get(ip_address, 0) + 1
                    # Check if the frequency of requests from the IP address exceeds the threshold
                    if ip_frequency[ip_address] >= THRESHOLD:
                        print(f"Suspicious request frequency detected at {timestamp}: {line}")
                    # Check if the number of requests in the recent time window is anomalous
                    if len(request_times) == WINDOW_SIZE:
                        time_window = (request_times[-1] - request_times[0]).total_seconds()
                        request_rate = WINDOW_SIZE / time_window
                        if request_rate > ANOMALY_THRESHOLD:
                            print(f"Anomalous request rate detected at {timestamp}: {line}")

# Call the detect_malicious_requests function on the server log file
detect_malicious_requests("/path/to/server.log")
