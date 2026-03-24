"""
Author: Jui-Wen Chiang
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""
import socket
import threading
import sqlite3
import os
import platform
import datetime


print("=" * 50)
print("Python Version: ", platform.python_version())
print("Operating System: ",os.name)

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


class NetworkTool:
    # constructor
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # This is the advantage of encapsulation; it restricts direct external access to and modification of properties within a class. 
    # The @property decorator exposes the property as read-only. 
    # When external modification is required, the @<attribute>.setter decorator allows external, safe, and validated logic to modify the property.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            raise ValueError("Target cannot be an empty string")
        else:
            self.__target = value

    # destructor
    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# The PortScanner reuses the parent NetworkTool’s initialization code through. (target property and its setter) 
# PortScanner only adds what is unique to it (self.scan_results and self.lock).
# This avoids duplicating the parent’s setup logic and keeps the code easier to maintain.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()


    # destructor
    def __del__(self):
        super().__del__()
        print("PortScanner instance destroyed")


    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # If a socket error occurs, the program would crash immediately and stop scanning all remaining ports. 
        # The threading lock might also never be released, causing other threads to freeze.
        #  With try-except, the error is caught and logged, allowing the other threads to continue scanning normally.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((self.target, port))
            service_name = common_ports.get(port, "Unknown")

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            with self.lock:
                self.scan_results.append((port, status, service_name))

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()


    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]


    # Q2: Why do we use threading instead of scanning one port at a time?
    # The bottleneck of port scanning is waiting for network responses, which takes a long time. 
    # Threading allows us to scan multiple ports simultaneously, greatly reducing the total time. 
    # Dividing the work to get it done faster.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT
            port INTEGER
            status TEXT
            service TEXT
            scan_date TEXT
            )"""
        )
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")



def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                _, target, port, status, service, scan_date = row
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
        conn.close()
    except (sqlite3.Error, sqlite3.OperationalError):
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    print("-" * 50)
    target_ip = input("Please enter a target IP address (default: 127.0.0.1): ")
    if target_ip == "":
        target_ip = "127.0.0.1"

    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Please enter a starting port number (integer between 1 and 1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Please enter a ending port number (integer from starting port to 1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    
    port_scanner = PortScanner(target_ip)
    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    port_scanner.scan_range(start_port, end_port)
    open_ports = port_scanner.get_open_ports()

    print(f"--- Scan Results for {target_ip} ---")
    if open_ports:
        for port, status, service in open_ports:
            print(f"Port {port}: {status} ({service})")
    else:
        print("No open ports found.")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target_ip, open_ports)

    history_scan = input("Would you like to see past scan history? (yes/no): ")
    if history_scan == "yes":
        load_past_scans()
    else:
        print("Program ended")
    print("=" * 50)


# Q5: New Feature Proposal
# I want to add a customizable list of open ports for user-specified services. 
# Users input interested services (e.g., HTTP, SSH, MySQL), then filter scan results 
# where status is 'Open' and service matches user input using list comprehension. 
# This lets users focus only on relevant services they care about, greatly improving the user experience.
# Diagram: See diagram_101571949.png in the repository root
