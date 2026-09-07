import re
import time
from collections import defaultdict, deque

from email_alert_manager import EmailAlertManager
from firewall_manager import FirewallManager


class TrafficMonitor:
    LOG_PATTERN = re.compile(
        r'(?P<ip>\S+) .*? "\s*(?P<method>\S+) '
        r'(?P<path>\S+) \S+" (?P<status>\d{3})'
    )

    def __init__(self, config):
        self.config = config
        self.requests = deque()
        self.firewall = FirewallManager(config)
        self.alerts = EmailAlertManager(config)

    def calculate_risk(self, total_requests, current_ip_count,
                       current_endpoint_count, total_errors):
        risk_score = 0
        reasons = []
        rules = (
            (total_requests > self.config.TOTAL_REQUEST_THRESHOLD, 20,
             "High overall traffic"),
            (current_ip_count > self.config.IP_REQUEST_THRESHOLD, 40,
             "High request rate from one IP"),
            (current_endpoint_count > self.config.ENDPOINT_THRESHOLD, 20,
             "Repeated endpoint requests"),
            (total_errors > self.config.ERROR_THRESHOLD, 20,
             "High HTTP error activity"),
        )
        for matches, points, reason in rules:
            if matches:
                risk_score += points
                reasons.append(reason)
        return risk_score, reasons

    def write_alert(self, alert_time, ip, method, path, status, total_requests,
                    current_ip_count, risk_score, reasons):
        with open(self.config.ALERT_LOG, "a") as alert_file:
            alert_file.write(f"\n[{alert_time}] HIGH RISK DETECTED\n")
            alert_file.write(f"IP: {ip}\nMethod: {method}\nPath: {path}\n")
            alert_file.write(f"Status: {status}\nTotal Requests: {total_requests}\n")
            alert_file.write(f"Requests From IP: {current_ip_count}\n")
            alert_file.write(f"Risk Score: {risk_score}\nReasons:\n")
            for reason in reasons:
                alert_file.write(f"- {reason}\n")
            alert_file.write("-" * 50 + "\n")

    def handle_high_risk(self, alert_time, ip, method, path, status,
                         total_requests, current_ip_count, risk_score, reasons):
        print("STATUS:  HIGH RISK")
        print("\n SUSPICIOUS ACTIVITY DETECTED!\n\nReasons:")
        for reason in reasons:
            print(f"- {reason}")
        self.firewall.ban_ip(ip, reason="; ".join(reasons))
        if self.alerts.can_send():
            self.write_alert(alert_time, ip, method, path, status,
                             total_requests, current_ip_count, risk_score, reasons)
            print("\n Alert saved to alerts.log")
            self.alerts.send(alert_time, ip, method, path, status,
                             total_requests, current_ip_count, risk_score, reasons)
        else:
            remaining = int(self.config.ALERT_COOLDOWN -
                            (time.time() - self.alerts.last_alert_time))
            print(f"Alert cooldown active. Next email available in {remaining}s.")

    def process_line(self, line):
        match = self.LOG_PATTERN.search(line)
        if not match:
            return
        ip = match.group("ip")
        method = match.group("method")
        path = match.group("path")
        status = int(match.group("status"))
        now = time.time()
        self.requests.append((now, ip, path, status))
        while self.requests and now - self.requests[0][0] > self.config.WINDOW_SIZE:
            self.requests.popleft()

        ip_counts = defaultdict(int)
        endpoint_counts = defaultdict(int)
        total_errors = 0
        for _, request_ip, request_path, request_status in self.requests:
            ip_counts[request_ip] += 1
            endpoint_counts[request_path] += 1
            if request_status >= 400:
                total_errors += 1

        total_requests = len(self.requests)
        current_ip_count = ip_counts[ip]
        current_endpoint_count = endpoint_counts[path]
        risk_score, reasons = self.calculate_risk(
            total_requests, current_ip_count, current_endpoint_count, total_errors
        )
        print("\n" + "=" * 50)
        print(f"NEW REQUEST\nIP: {ip}\nMethod: {method}\nPath: {path}\nStatus: {status}")
        print("\nTRAFFIC ANALYSIS")
        print(f"Total requests in last {self.config.WINDOW_SIZE}s: {total_requests}")
        print(f"Requests from this IP: {current_ip_count}")
        print(f"Requests to this endpoint: {current_endpoint_count}")
        print(f"HTTP errors: {total_errors}\n\nRISK SCORE: {risk_score}")

        if risk_score >= self.config.HIGH_RISK_SCORE:
            self.handle_high_risk(
                time.strftime("%Y-%m-%d %H:%M:%S"), ip, method, path, status,
                total_requests, current_ip_count, risk_score, reasons
            )
        elif risk_score >= self.config.SUSPICIOUS_SCORE:
            print("STATUS:  SUSPICIOUS\n\nReasons:")
            for reason in reasons:
                print(f"- {reason}")
        else:
            print("STATUS:  NORMAL")

    def run(self):
        if not self.firewall.setup_chain():
            print(" Firewall setup failed. Monitor will not start.")
            return
        print("=" * 50)
        print("REAL-TIME HTTP TRAFFIC MONITOR")
        print("PROJECT 2 - DETECT → RESPOND")
        print("=" * 50)
        print(f"Watching: {self.config.LOG_FILE}")
        print(f"Window size: {self.config.WINDOW_SIZE}s")
        print(f"Alert cooldown: {self.config.ALERT_COOLDOWN}s")
        print(f"Ban duration: {self.config.BAN_DURATION}s")
        print(f"Allowlisted IPs: {self.config.ALLOWLIST}")
        print(f"Active bans restored: {len(self.firewall.active_bans)}")
        print("\nMonitoring started...\n")
        with open(self.config.LOG_FILE, "r") as log_file:
            log_file.seek(0, 2)
            while True:
                self.firewall.check_expired_bans()
                line = log_file.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                self.process_line(line)
