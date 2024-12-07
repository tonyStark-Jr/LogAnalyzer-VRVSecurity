import re
from collections import Counter
import csv
import argparse
import sys

class LogAnalyzer:
    """
    A class to analyze web server log files for various metrics such as
    requests per IP address, most frequently accessed endpoints, and
    detection of suspicious activities like brute force login attempts.
    """

    def __init__(self, log_file='sample.log', csv_file='log_analysis_results.csv', failed_login_threshold=10):
        """
        Initializes the LogAnalyzer with configuration parameters.

        Args:
            log_file (str): Path to the log file to be analyzed.
            csv_file (str): Path to the output CSV file.
            failed_login_threshold (int): Threshold for failed login attempts to flag suspicious activity.
        """
        self.log_file = log_file
        self.csv_file = csv_file
        self.failed_login_threshold = failed_login_threshold

        # Initialize counters
        self.ip_counter = Counter()
        self.endpoint_counter = Counter()
        self.failed_login_counter = Counter()

        # Regular expression pattern to parse log lines
        self.log_pattern = re.compile(
            r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>GET|POST|PUT|DELETE|PATCH) (?P<endpoint>\S+) HTTP/\d\.\d" '
            r'(?P<status>\d{3}) \d+(?: "(?P<message>[^"]+)")?'
        )

    def parse_log_line(self, line):
        """
        Parses a single line of the log file using regex.

        Args:
            line (str): A single line from the log file.

        Returns:
            dict or None: A dictionary with keys: ip, timestamp, method, endpoint, status, message
                          Returns None if the line doesn't match the pattern.
        """
        match = self.log_pattern.match(line)
        if match:
            return match.groupdict()
        return None

    def count_requests_per_ip(self):
        """
        Counts the number of requests made by each IP address.

        Returns:
            list of tuples: Sorted list of IP addresses and their request counts in descending order.
        """
        try:
            with open(self.log_file, 'r') as file:
                for line in file:
                    parsed = self.parse_log_line(line)
                    if not parsed:
                        continue  # Skip lines that don't match the pattern

                    ip = parsed['ip']
                    self.ip_counter[ip] += 1

            # Return sorted list
            return self.ip_counter.most_common()
        except FileNotFoundError:
            print(f"Error: The log file '{self.log_file}' was not found.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while counting requests per IP: {e}")
            sys.exit(1)

    def most_frequently_accessed_endpoint(self):
        """
        Identifies the most frequently accessed endpoint.

        Returns:
            tuple: The endpoint and its access count.
        """
        try:
            with open(self.log_file, 'r') as file:
                for line in file:
                    parsed = self.parse_log_line(line)
                    if not parsed:
                        continue

                    endpoint = parsed['endpoint']
                    self.endpoint_counter[endpoint] += 1

            if self.endpoint_counter:
                return self.endpoint_counter.most_common(1)[0]
            else:
                return ('N/A', 0)
        except FileNotFoundError:
            print(f"Error: The log file '{self.log_file}' was not found.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while identifying the most accessed endpoint: {e}")
            sys.exit(1)

    def detect_suspicious_activity(self):
        """
        Detects potential brute force login attempts based on failed login attempts.

        Returns:
            list of tuples: IP addresses and their failed login counts exceeding the threshold.
        """
        try:
            with open(self.log_file, 'r') as file:
                for line in file:
                    parsed = self.parse_log_line(line)
                    if not parsed:
                        continue
                    

                    ip = parsed['ip']
                    status = parsed['status']
                    message = parsed.get('message', '')

                    # Detect failed login attempts
                    if status == '401':
                        self.failed_login_counter[ip] += 1
                        continue
                    if message is None:
                        continue
                    if 'invalid credentials' in message.lower():
                        self.failed_login_counter[ip] += 1

            # Filter IPs exceeding the threshold
            suspicious_ips = [
                (ip, count) for ip, count in self.failed_login_counter.items()
                if count > self.failed_login_threshold
            ]

            # Sort descending by count
            suspicious_ips_sorted = sorted(suspicious_ips, key=lambda x: x[1], reverse=True)
            return suspicious_ips_sorted
        except FileNotFoundError:
            print(f"Error: The log file '{self.log_file}' was not found.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while detecting suspicious activity: {e}")
            sys.exit(1)

    def save_to_csv(self, results):
        """
        Saves the analysis results to a CSV file with structured sections.

        Args:
            results (dict): A dictionary containing all analysis results.
        """
        try:
            with open(self.csv_file, 'w', newline='') as file:
                writer = csv.writer(file)

                # Write Requests per IP
                writer.writerow(['Requests per IP Address'])
                writer.writerow(['IP Address', 'Request Count'])
                for ip, count in results['requests_per_ip']:
                    writer.writerow([ip, count])
                writer.writerow([])  # Empty line for separation

                # Write Most Accessed Endpoint
                writer.writerow(['Most Frequently Accessed Endpoint'])
                writer.writerow(['Endpoint', 'Access Count'])
                endpoint, count = results['most_accessed_endpoint']
                writer.writerow([endpoint, count])
                writer.writerow([])  # Empty line for separation

                # Write Suspicious Activity
                writer.writerow(['Suspicious Activity Detected'])
                writer.writerow(['IP Address', 'Failed Login Count'])
                for ip, count in results['suspicious_activity']:
                    writer.writerow([ip, count])

            print(f"\nResults have been saved to '{self.csv_file}'")
        except Exception as e:
            print(f"An error occurred while saving to CSV: {e}")
            sys.exit(1)

    def run_all_analyses(self):
        """
        Executes all analysis tasks and compiles the results.

        Returns:
            dict: A dictionary containing all analysis results.
        """
        requests_per_ip = self.count_requests_per_ip()
        most_endpoint = self.most_frequently_accessed_endpoint()
        suspicious_activity = self.detect_suspicious_activity()

        results = {
            'requests_per_ip': requests_per_ip,
            'most_accessed_endpoint': most_endpoint,
            'suspicious_activity': suspicious_activity
        }

        return results

    def display_all_results(self, results):
        """
        Displays all analysis results in the terminal in a clear and organized format.

        Args:
            results (dict): The analysis results.
        """
        print("\n" + "="*50)
        print("Requests per IP Address:")
        print("="*50)
        print(f"{'IP Address':<20} {'Request Count':<15}")
        for ip, count in results['requests_per_ip']:
            print(f"{ip:<20} {count:<15}")

        print("\n" + "="*50)
        print("Most Frequently Accessed Endpoint:")
        print("="*50)
        endpoint, count = results['most_accessed_endpoint']
        print(f"{endpoint} (Accessed {count} times)")

        print("\n" + "="*50)
        print("Suspicious Activity Detected:")
        print("="*50)
        if results['suspicious_activity']:
            print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
            for ip, count in results['suspicious_activity']:
                print(f"{ip:<20} {count:<25}")
        else:
            print("No suspicious activity detected based on the current threshold.")
