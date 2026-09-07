import ipaddress
import json
import os
import subprocess
import tempfile
import time
from collections import deque


class FirewallManager:
    def __init__(self, config):
        self.config = config
        self.active_bans = {}
        self.ban_timestamps = deque()
        self.load_state()

    def _run(self, arguments):
        return subprocess.run(
            ["sudo", self.config.IPTABLES] + arguments,
            check=True, capture_output=True, text=True,
            timeout=self.config.COMMAND_TIMEOUT
        )

    def _try_run(self, arguments):
        try:
            return self._run(arguments)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
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
                log_file.write(f"[{timestamp}] {action} IP={ip} REASON={reason}\n")
        except OSError as error:
            print(f" Failed to write ban log: {error}")

    def save_state(self):
        directory = os.path.dirname(os.path.abspath(self.config.BAN_STATE_FILE))
        try:
            fd, temporary_path = tempfile.mkstemp(prefix=".bans-", dir=directory)
            try:
                with os.fdopen(fd, "w") as file:
                    json.dump(self.active_bans, file, indent=4)
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(temporary_path, self.config.BAN_STATE_FILE)
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
                if not self._valid_public_ipv4(ip) or ip in self.config.ALLOWLIST:
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

    def _iptables_check(self, ip, target="DROP"):
        return subprocess.run(
            ["sudo", self.config.IPTABLES, "-C", self.config.CHAIN_NAME,
             "-s", ip, "-j", target],
            capture_output=True, text=True, timeout=self.config.COMMAND_TIMEOUT
        )

    def setup_chain(self):
        result = subprocess.run(
            ["sudo", self.config.IPTABLES, "-L", self.config.CHAIN_NAME, "-n"],
            capture_output=True, text=True, timeout=self.config.COMMAND_TIMEOUT
        )
        if result.returncode != 0:
            if self._try_run(["-N", self.config.CHAIN_NAME]) is None:
                print(f" Unable to create {self.config.CHAIN_NAME}")
                return False
            print(f"Created iptables chain: {self.config.CHAIN_NAME}")
        try:
            input_rules = subprocess.run(
                ["sudo", self.config.IPTABLES, "-S", "INPUT"], check=True,
                capture_output=True, text=True, timeout=self.config.COMMAND_TIMEOUT
            ).stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
            print(f" Unable to inspect INPUT chain: {error}")
            return False
        if f"-A INPUT -j {self.config.CHAIN_NAME}" not in input_rules:
            if self._try_run(["-I", "INPUT", "1", "-j", self.config.CHAIN_NAME]) is None:
                return False
            print(f"Connected INPUT -> {self.config.CHAIN_NAME}")
        self.ensure_allowlist_rules()
        self.restore_active_bans()
        self.check_expired_bans()
        return True

    def ensure_allowlist_rules(self):
        for ip in self.config.ALLOWLIST:
            if not self._valid_public_ipv4(ip):
                raise ValueError(f"Invalid allowlist IPv4: {ip}")
            if self._iptables_check(ip, "RETURN").returncode != 0:
                if self._try_run(["-I", self.config.CHAIN_NAME, "1", "-s", ip, "-j", "RETURN"]):
                    print(f"Allowlisted IP: {ip}")

    def restore_active_bans(self):
        restored = 0
        now = time.time()
        for ip, expiry_time in list(self.active_bans.items()):
            if expiry_time <= now:
                self.active_bans.pop(ip, None)
                continue
            if self._iptables_check(ip).returncode != 0:
                if self._try_run(["-A", self.config.CHAIN_NAME, "-s", ip, "-j", "DROP"]):
                    restored += 1
        self.save_state()
        if restored:
            print(f"Restored {restored} firewall ban(s).")

    def _cleanup_ban_rate_limit(self):
        cutoff = time.time() - self.config.BAN_RATE_WINDOW
        while self.ban_timestamps and self.ban_timestamps[0] < cutoff:
            self.ban_timestamps.popleft()

    def can_create_ban(self):
        self._cleanup_ban_rate_limit()
        return len(self.ban_timestamps) < self.config.MAX_BANS_PER_MINUTE

    def ban_ip(self, ip, reason="High risk traffic"):
        if not self._valid_public_ipv4(ip):
            print(f"Skipping invalid/non-public IPv4: {ip}")
            return False
        if ip in self.config.ALLOWLIST:
            print(f" {ip} is allowlisted. Not banning.")
            return False
        if ip in self.active_bans or len(self.active_bans) >= self.config.MAX_ACTIVE_BANS:
            return False
        if not self.can_create_ban():
            print("Ban rate limit reached. No new ban created.")
            return False
        if self._iptables_check(ip).returncode != 0:
            if self._try_run(["-A", self.config.CHAIN_NAME, "-s", ip, "-j", "DROP"]) is None:
                return False
        self.active_bans[ip] = time.time() + self.config.BAN_DURATION
        self.ban_timestamps.append(time.time())
        self.save_state()
        self.log_event("BAN", ip, reason)
        print(f" IP BANNED: {ip} for {self.config.BAN_DURATION} seconds")
        return True

    def unban_ip(self, ip):
        if self._iptables_check(ip).returncode == 0:
            if self._try_run(["-D", self.config.CHAIN_NAME, "-s", ip, "-j", "DROP"]) is None:
                return False
        self.active_bans.pop(ip, None)
        self.save_state()
        self.log_event("UNBAN", ip, "Ban expired or removed")
        print(f" IP UNBANNED: {ip}")
        return True

    def check_expired_bans(self):
        now = time.time()
        for ip in [ip for ip, expiry in self.active_bans.items() if now >= expiry]:
            self.unban_ip(ip)
