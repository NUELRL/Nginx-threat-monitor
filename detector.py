
import time
import re
import smtplib
import subprocess
import ipaddress
import json
import os
import tempfile
from collections import deque, defaultdict
from email.message import EmailMessage


# ============================================================
# CONFIGURATION
# ============================================================

class Config:

    LOG_FILE = "/var/log/nginx/access.log"
    ALERT_LOG = "alerts.log"
    BAN_LOG = "bans.log"
    BAN_STATE_FILE = "bans.json"

    WINDOW_SIZE = 60

    TOTAL_REQUEST_THRESHOLD = 50
    IP_REQUEST_THRESHOLD = 20
    ENDPOINT_THRESHOLD = 15
    ERROR_THRESHOLD = 10

    HIGH_RISK_SCORE = 60
    SUSPICIOUS_SCORE = 30

    ALERT_COOLDOWN = 60
    SENDER_EMAIL = ""
    RECEIVER_EMAIL = ""
    APP_PASSWORD = os.getenv("DDOS_MONITOR_APP_PASSWORD")

    BAN_DURATION = 300
    MAX_ACTIVE_BANS = 100

    MAX_BANS_PER_MINUTE = 20
    BAN_RATE_WINDOW = 60

    IPTABLES = "/usr/sbin/iptables"
    CHAIN_NAME = "DDOS_MONITOR"

    ALLOWLIST = {
        "",
    }

    COMMAND_TIMEOUT = 5


# ============================================================
# FIREWALL MANAGER
# ============================================================

class FirewallManager:

    def __init__(self, config):
        self.config = config
        self.active_bans = {}
        self.ban_timestamps = deque()
        self.load_state()

    def _run(self, arguments):
        command = ["sudo", self.config.IPTABLES] + arguments
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=self.config.COMMAND_TIMEOUT
        )

    def _try_run(self, arguments):
        try:
            return self._run(arguments)
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                OSError) as error:
            print(f" iptables command failed: {error}")
            return None

    @staticmethod
    def _valid_public_ipv4(ip):
        try:
            address = ipaddress.ip_address(ip)
            return address.version == 4 and address.is_global
        except ValueError:
            return False

    def log_event(self, action, ip, reason=""):
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(self.config.BAN_LOG, "a") as log_file:
                log_file.write(
                    f"[{timestamp}] {action} IP={ip} REASON={reason}\n"
                )
        except OSError as error:
            print(f" Failed to write ban log: {error}")

    def save_state(self):
        directory = os.path.dirname(
            os.path.abspath(self.config.BAN_STATE_FILE)
        )

        try:
            fd, temporary_path = tempfile.mkstemp(
                prefix=".bans-",
                dir=directory
            )

            try:
                with os.fdopen(fd, "w") as file:
                    json.dump(self.active_bans, file, indent=4)
                    file.flush()
                    os.fsync(file.fileno())

                os.replace(
                    temporary_path,
                    self.config.BAN_STATE_FILE
                )

            except Exception:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass
                raise

        except OSError as error:
            print(f" Failed to save ban state: {error}")

    def load_state(self):
        try:
            with open(self.config.BAN_STATE_FILE, "r") as file:
                saved_bans = json.load(file)

            if not isinstance(saved_bans, dict):
                raise ValueError("Ban state must be a JSON object")

            now = time.time()
            loaded = 0

            for ip, expiry_time in saved_bans.items():
                if not self._valid_public_ipv4(ip):
                    continue
                if ip in self.config.ALLOWLIST:
                    continue

                try:
                    expiry_time = float(expiry_time)
                except (TypeError, ValueError):
                    continue

                if expiry_time > now:
                    self.active_bans[ip] = expiry_time
                    loaded += 1

                if loaded >= self.config.MAX_ACTIVE_BANS:
                    break

            print(f"Loaded {loaded} active ban(s) from state.")

        except FileNotFoundError:
            print("No existing ban state found.")

        except (OSError, json.JSONDecodeError, ValueError) as error:
            print(f" Failed to load ban state: {error}")

    def setup_chain(self):
        result = subprocess.run(
            [
                "sudo", self.config.IPTABLES,
                "-L", self.config.CHAIN_NAME, "-n"
            ],
            capture_output=True,
            text=True,
            timeout=self.config.COMMAND_TIMEOUT
        )

        if result.returncode != 0:
            if self._try_run(
                ["-N", self.config.CHAIN_NAME]
            ) is None:
                print(f" Unable to create {self.config.CHAIN_NAME}")
                return False

            print(
                f"Created iptables chain: {self.config.CHAIN_NAME}"
            )

        try:
            input_rules = subprocess.run(
                [
                    "sudo", self.config.IPTABLES,
                    "-S", "INPUT"
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=self.config.COMMAND_TIMEOUT
            ).stdout

        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                OSError) as error:
            print(f" Unable to inspect INPUT chain: {error}")
            return False

        jump_rule = f"-A INPUT -j {self.config.CHAIN_NAME}"

        if jump_rule not in input_rules:
            if self._try_run(
                [
                    "-I", "INPUT", "1",
                    "-j", self.config.CHAIN_NAME
                ]
            ) is None:
                return False

            print(
                f"Connected INPUT -> {self.config.CHAIN_NAME}"
            )

        self.ensure_allowlist_rules()
        self.restore_active_bans()
        self.check_expired_bans()

        return True

    def ensure_allowlist_rules(self):
        for ip in self.config.ALLOWLIST:
            if not self._valid_public_ipv4(ip):
                raise ValueError(f"Invalid allowlist IPv4: {ip}")

            result = subprocess.run(
                [
                    "sudo", self.config.IPTABLES,
                    "-C", self.config.CHAIN_NAME,
                    "-s", ip, "-j", "RETURN"
                ],
                capture_output=True,
                text=True,
                timeout=self.config.COMMAND_TIMEOUT
            )

            if result.returncode != 0:
                if self._try_run(
                    [
                        "-I", self.config.CHAIN_NAME, "1",
                        "-s", ip, "-j", "RETURN"
                    ]
                ) is not None:
                    print(f"Allowlisted IP: {ip}")

    def restore_active_bans(self):
        restored = 0
        now = time.time()

        for ip, expiry_time in list(self.active_bans.items()):
            if expiry_time <= now:
                self.active_bans.pop(ip, None)
                continue

            result = subprocess.run(
                [
                    "sudo", self.config.IPTABLES,
                    "-C", self.config.CHAIN_NAME,
                    "-s", ip, "-j", "DROP"
                ],
                capture_output=True,
                text=True,
                timeout=self.config.COMMAND_TIMEOUT
            )

            if result.returncode != 0:
                if self._try_run(
                    [
                        "-A", self.config.CHAIN_NAME,
                        "-s", ip, "-j", "DROP"
                    ]
                ) is not None:
                    restored += 1

        self.save_state()

        if restored:
            print(f"Restored {restored} firewall ban(s).")

    def _cleanup_ban_rate_limit(self):
        cutoff = time.time() - self.config.BAN_RATE_WINDOW

        while (
            self.ban_timestamps
            and self.ban_timestamps[0] < cutoff
        ):
            self.ban_timestamps.popleft()

    def can_create_ban(self):
        self._cleanup_ban_rate_limit()
        return (
            len(self.ban_timestamps)
            < self.config.MAX_BANS_PER_MINUTE
        )

    def ban_ip(self, ip, reason="High risk traffic"):
        if not self._valid_public_ipv4(ip):
            print(
                f"Skipping invalid/non-public IPv4: {ip}"
            )
            return False

        if ip in self.config.ALLOWLIST:
            print(
                f" {ip} is allowlisted. Not banning."
            )
            return False

        if ip in self.active_bans:
            return False

        if len(self.active_bans) >= self.config.MAX_ACTIVE_BANS:
            print(" Maximum active bans reached.")
            return False

        if not self.can_create_ban():
            print(
                "⚠️Ban rate limit reached. No new ban created."
            )
            return False

        result = subprocess.run(
            [
                "sudo", self.config.IPTABLES,
                "-C", self.config.CHAIN_NAME,
                "-s", ip, "-j", "DROP"
            ],
            capture_output=True,
            text=True,
            timeout=self.config.COMMAND_TIMEOUT
        )

        if result.returncode != 0:
            if self._try_run(
                [
                    "-A", self.config.CHAIN_NAME,
                    "-s", ip, "-j", "DROP"
                ]
            ) is None:
                return False

        self.active_bans[ip] = (
            time.time() + self.config.BAN_DURATION
        )
        self.ban_timestamps.append(time.time())
        self.save_state()

        self.log_event("BAN", ip, reason)

        print(
            f" IP BANNED: {ip} "
            f"for {self.config.BAN_DURATION} seconds"
        )
        return True

    def unban_ip(self, ip):
        result = subprocess.run(
            [
                "sudo", self.config.IPTABLES,
                "-C", self.config.CHAIN_NAME,
                "-s", ip, "-j", "DROP"
            ],
            capture_output=True,
            text=True,
            timeout=self.config.COMMAND_TIMEOUT
        )

        if result.returncode == 0:
            if self._try_run(
                [
                    "-D", self.config.CHAIN_NAME,
                    "-s", ip, "-j", "DROP"
                ]
            ) is None:
                return False

        self.active_bans.pop(ip, None)
        self.save_state()
        self.log_event(
            "UNBAN",
            ip,
            "Ban expired or removed"
        )

        print(f" IP UNBANNED: {ip}")
        return True

    def check_expired_bans(self):
        now = time.time()

        expired_ips = [
            ip
            for ip, expiry_time in self.active_bans.items()
            if now >= expiry_time
        ]

        for ip in expired_ips:
            self.unban_ip(ip)


# ============================================================
# EMAIL ALERT MANAGER
# ============================================================

class EmailAlertManager:

    def __init__(self, config):

        self.config = config

        self.last_alert_time = 0

    # --------------------------------------------------------
    # Check cooldown
    # --------------------------------------------------------

    def can_send(self):

        return (
            time.time()
            - self.last_alert_time
            >= self.config.ALERT_COOLDOWN
        )

    # --------------------------------------------------------
    # Send email
    # --------------------------------------------------------

    def send(
        self,
        alert_time,
        ip,
        method,
        path,
        status,
        total_requests,
        current_ip_count,
        risk_score,
        reasons
    ):

        message = EmailMessage()

        message["Subject"] = (
            " HIGH RISK TRAFFIC DETECTED"
        )

        message["From"] = (
            self.config.SENDER_EMAIL
        )

        message["To"] = (
            self.config.RECEIVER_EMAIL
        )

        reason_text = "\n".join(
            f"- {reason}"
            for reason in reasons
        )

        message.set_content(
            f""" HIGH RISK HTTP TRAFFIC DETECTED

Time: {alert_time}

IP Address: {ip}
Method: {method}
Path: {path}
Status: {status}

Total Requests in {self.config.WINDOW_SIZE}s: {total_requests}
Requests From IP: {current_ip_count}

Risk Score: {risk_score}

Reasons:
{reason_text}

This alert was generated by your
Real-Time HTTP Traffic Monitor.
"""
        )

        if not self.config.APP_PASSWORD:
            print(
                " DDOS_MONITOR_APP_PASSWORD is not set."
            )
            return False

        try:

            with smtplib.SMTP_SSL(
                "smtp.gmail.com",
                465,
                timeout=10
            ) as smtp:

                smtp.login(
                    self.config.SENDER_EMAIL,
                    self.config.APP_PASSWORD
                )

                smtp.send_message(
                    message
                )

            print(
                " Email alert sent successfully!"
            )

            self.last_alert_time = time.time()

            return True

        except Exception as error:

            print(
                " Failed to send email alert:"
            )

            print(error)

            return False


# ============================================================
# TRAFFIC MONITOR
# ============================================================

class TrafficMonitor:

    LOG_PATTERN = re.compile(
        r'(?P<ip>\S+) .*? "\s*'
        r'(?P<method>\S+) '
        r'(?P<path>\S+) \S+" '
        r'(?P<status>\d{3})'
    )

    def __init__(self, config):

        self.config = config

        # Sliding window

        self.requests = deque()

        # Managers

        self.firewall = FirewallManager(
            config
        )

        self.alerts = EmailAlertManager(
            config
        )

    # --------------------------------------------------------
    # Calculate risk score
    # --------------------------------------------------------

    def calculate_risk(
        self,
        total_requests,
        current_ip_count,
        current_endpoint_count,
        total_errors
    ):

        risk_score = 0

        reasons = []

        # Rule 1

        if (
            total_requests
            > self.config.TOTAL_REQUEST_THRESHOLD
        ):

            risk_score += 20

            reasons.append(
                "High overall traffic"
            )

        # Rule 2

        if (
            current_ip_count
            > self.config.IP_REQUEST_THRESHOLD
        ):

            risk_score += 40

            reasons.append(
                "High request rate from one IP"
            )

        # Rule 3

        if (
            current_endpoint_count
            > self.config.ENDPOINT_THRESHOLD
        ):

            risk_score += 20

            reasons.append(
                "Repeated endpoint requests"
            )

        # Rule 4

        if (
            total_errors
            > self.config.ERROR_THRESHOLD
        ):

            risk_score += 20

            reasons.append(
                "High HTTP error activity"
            )

        return (
            risk_score,
            reasons
        )

    # --------------------------------------------------------
    # Save alert
    # --------------------------------------------------------

    def write_alert(
        self,
        alert_time,
        ip,
        method,
        path,
        status,
        total_requests,
        current_ip_count,
        risk_score,
        reasons
    ):

        with open(
            self.config.ALERT_LOG,
            "a"
        ) as alert_file:

            alert_file.write(
                f"\n[{alert_time}] "
                f"HIGH RISK DETECTED\n"
            )

            alert_file.write(
                f"IP: {ip}\n"
            )

            alert_file.write(
                f"Method: {method}\n"
            )

            alert_file.write(
                f"Path: {path}\n"
            )

            alert_file.write(
                f"Status: {status}\n"
            )

            alert_file.write(
                f"Total Requests: "
                f"{total_requests}\n"
            )

            alert_file.write(
                f"Requests From IP: "
                f"{current_ip_count}\n"
            )

            alert_file.write(
                f"Risk Score: "
                f"{risk_score}\n"
            )

            alert_file.write(
                "Reasons:\n"
            )

            for reason in reasons:

                alert_file.write(
                    f"- {reason}\n"
                )

            alert_file.write(
                "-" * 50 + "\n"
            )

    # --------------------------------------------------------
    # Handle high risk
    # --------------------------------------------------------

    def handle_high_risk(
        self,
        alert_time,
        ip,
        method,
        path,
        status,
        total_requests,
        current_ip_count,
        risk_score,
        reasons
    ):

        print(
            "STATUS:  HIGH RISK"
        )

        print(
            "\n SUSPICIOUS ACTIVITY DETECTED!"
        )

        print("\nReasons:")

        for reason in reasons:

            print(
                f"- {reason}"
            )

        # ----------------------------------------------------
        # PROJECT 2 MITIGATION
        # ----------------------------------------------------

        self.firewall.ban_ip(
            ip,
            reason="; ".join(reasons)
        )

        # ----------------------------------------------------
        # PROJECT 1 ALERTING
        # ----------------------------------------------------

        if self.alerts.can_send():

            self.write_alert(
                alert_time,
                ip,
                method,
                path,
                status,
                total_requests,
                current_ip_count,
                risk_score,
                reasons
            )

            print(
                "\n Alert saved to alerts.log"
            )

            self.alerts.send(
                alert_time,
                ip,
                method,
                path,
                status,
                total_requests,
                current_ip_count,
                risk_score,
                reasons
            )

        else:

            remaining = int(
                self.config.ALERT_COOLDOWN
                - (
                    time.time()
                    - self.alerts.last_alert_time
                )
            )

            print(
                f"\ Alert cooldown active. "
                f"Next email available in "
                f"{remaining}s."
            )

    # --------------------------------------------------------
    # Process one Nginx log line
    # --------------------------------------------------------

    def process_line(self, line):

        match = self.LOG_PATTERN.search(
            line
        )

        if not match:

            return

        ip = match.group("ip")

        method = match.group("method")

        path = match.group("path")

        status = int(
            match.group("status")
        )

        now = time.time()

        # Add request

        self.requests.append(
            (
                now,
                ip,
                path,
                status
            )
        )

        # Remove expired requests

        while (
            self.requests
            and now
            - self.requests[0][0]
            > self.config.WINDOW_SIZE
        ):

            self.requests.popleft()

        # ----------------------------------------------------
        # Analyze traffic
        # ----------------------------------------------------

        ip_counts = defaultdict(int)

        endpoint_counts = defaultdict(int)

        total_errors = 0

        for (
            timestamp,
            request_ip,
            request_path,
            request_status
        ) in self.requests:

            ip_counts[
                request_ip
            ] += 1

            endpoint_counts[
                request_path
            ] += 1

            if request_status >= 400:

                total_errors += 1

        # Statistics

        total_requests = len(
            self.requests
        )

        current_ip_count = (
            ip_counts[ip]
        )

        current_endpoint_count = (
            endpoint_counts[path]
        )

        # ----------------------------------------------------
        # Risk score
        # ----------------------------------------------------

        risk_score, reasons = (
            self.calculate_risk(
                total_requests,
                current_ip_count,
                current_endpoint_count,
                total_errors
            )
        )

        # ----------------------------------------------------
        # Display
        # ----------------------------------------------------

        print(
            "\n" + "=" * 50
        )

        print(
            "NEW REQUEST"
        )

        print(
            f"IP: {ip}"
        )

        print(
            f"Method: {method}"
        )

        print(
            f"Path: {path}"
        )

        print(
            f"Status: {status}"
        )

        print(
            "\nTRAFFIC ANALYSIS"
        )

        print(
            f"Total requests in last "
            f"{self.config.WINDOW_SIZE}s: "
            f"{total_requests}"
        )

        print(
            f"Requests from this IP: "
            f"{current_ip_count}"
        )

        print(
            f"Requests to this endpoint: "
            f"{current_endpoint_count}"
        )

        print(
            f"HTTP errors: "
            f"{total_errors}"
        )

        print(
            f"\nRISK SCORE: "
            f"{risk_score}"
        )

        # ----------------------------------------------------
        # Risk classification
        # ----------------------------------------------------

        if (
            risk_score
            >= self.config.HIGH_RISK_SCORE
        ):

            alert_time = time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            self.handle_high_risk(
                alert_time,
                ip,
                method,
                path,
                status,
                total_requests,
                current_ip_count,
                risk_score,
                reasons
            )

        elif (
            risk_score
            >= self.config.SUSPICIOUS_SCORE
        ):

            print(
                "STATUS:  SUSPICIOUS"
            )

            print(
                "\nReasons:"
            )

            for reason in reasons:

                print(
                    f"- {reason}"
                )

        else:

            print(
                "STATUS:  NORMAL"
            )

    # --------------------------------------------------------
    # Start monitor
    # --------------------------------------------------------

    def run(self):

        # Prepare firewall

        if not self.firewall.setup_chain():
            print(
                " Firewall setup failed. "
                "Monitor will not start."
            )
            return

        print(
            "=" * 50
        )

        print(
            "REAL-TIME HTTP "
            "TRAFFIC MONITOR"
        )

        print(
            "PROJECT 2 - DETECT → RESPOND"
        )

        print(
            "=" * 50
        )

        print(
            f"Watching: "
            f"{self.config.LOG_FILE}"
        )

        print(
            f"Window size: "
            f"{self.config.WINDOW_SIZE}s"
        )

        print(
            f"Alert cooldown: "
            f"{self.config.ALERT_COOLDOWN}s"
        )

        print(
            f"Ban duration: "
            f"{self.config.BAN_DURATION}s"
        )

        print(
            f"Allowlisted IPs: "
            f"{self.config.ALLOWLIST}"
        )

        print(
            f"Active bans restored: "
            f"{len(self.firewall.active_bans)}"
        )

        print(
            "\nMonitoring started...\n"
        )

        # Open Nginx log

        with open(
            self.config.LOG_FILE,
            "r"
        ) as log_file:

            # Start at end of file

            log_file.seek(
                0,
                2
            )

            while True:

                # Check expired bans

                self.firewall.check_expired_bans()

                # Read new log entry

                line = (
                    log_file.readline()
                )

                if not line:

                    time.sleep(
                        0.1
                    )

                    continue

                # Process request

                self.process_line(
                    line
                )


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    config = Config()

    monitor = TrafficMonitor(
        config
    )

    monitor.run()
