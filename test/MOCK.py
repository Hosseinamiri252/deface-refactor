# test/mock_test.py

import threading
import time

# Mock RedisConfig
class MockRedis:
    def connect(self):
        print("[MOCK Redis] Connected")
        return True

    def add_to_queue(self, queue_name, data):
        print(f"[MOCK Redis] Added to {queue_name}: {data}")

    def publish_event(self, channel, data):
        print(f"[MOCK Redis] Published on {channel}: {data}")

# Mock PermissionMonitor
class MockPermissionMonitor:
    def start(self):
        print("[MOCK] PermissionMonitor started (simulate change)")
        time.sleep(1)
        print("[MOCK] Permission change detected")

    def stop(self):
        print("[MOCK] PermissionMonitor stopped")

# Mock FileOperationsMonitor
class MockFileOperationsMonitor:
    def start(self):
        print("[MOCK] FileOperationsMonitor started (simulate change)")
        time.sleep(1)
        print("[MOCK] File change detected")

    def stop(self):
        print("[MOCK] FileOperationsMonitor stopped")

# Mock RsyncBackup
class MockRsyncBackup:
    def __init__(self, ssh_config, source, backup_path=None, delete=False):
        pass

    def run_restore_loop(self, stop_event):
        print("[MOCK] RsyncBackup restore loop running...")
        for i in range(3):
            if stop_event.is_set():
                break
            print(f"[MOCK] Simulated restore {i}")
            time.sleep(1)
        print("[MOCK] RsyncBackup loop finished")

# Glue تست
class MockManager:
    def __init__(self):
        self.stop_event = threading.Event()
        self.redis = MockRedis()
        self.monitors = [
            MockPermissionMonitor(),
            MockFileOperationsMonitor()
        ]
        self.rsync = MockRsyncBackup({}, "/mock/source")

    def start(self):
        self.redis.connect()

        t1 = threading.Thread(target=self.monitors[0].start)
        t2 = threading.Thread(target=self.monitors[1].start)
        t3 = threading.Thread(target=self.rsync.run_restore_loop, args=(self.stop_event,))

        t1.start()
        t2.start()
        t3.start()

        time.sleep(5)
        self.stop()

    def stop(self):
        self.stop_event.set()
        for m in self.monitors:
            m.stop()
        print("[MOCK] Manager stopped.")

if __name__ == "__main__":
    m = MockManager()
    m.start()
