from config import Config
from traffic_monitor import TrafficMonitor


if __name__ == "__main__":
    config = Config()
    monitor = TrafficMonitor(config)
    monitor.run()
