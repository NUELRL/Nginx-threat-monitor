import os


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
    ALLOWLIST = {""}
    COMMAND_TIMEOUT = 5
