# core/manager.py
import os
import threading
from datetime import datetime
from rich.console import Console

from permission_monitoring import PermissionMonitor  # ماژول آماده
from ssh import FileOperationsMonitor                # ماژول آماده
from rsync import RsyncBackup                        # اگر ماژول rsync داری
from custum-redis import RedisConfig                        # ماژول آماده

console = Console()

class AntiDefacementManager:
    def __init__(self, config):
        self.config = config
        self.console = console
        self.stop_event = threading.Event()
        self.monitors = []
        self.redis = None

        # مسیر لاگ و بکاپ
        self.backup_dir = f"logs_{self.config['host']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.backup_dir, exist_ok=True)

    def setup_redis(self):
        if self.config.get("use_redis"):
            self.redis = RedisConfig(
                host=self.config['redis_host'],
                port=self.config['redis_port'],
                password=self.config['redis_password']
            )
            if self.redis.connect():
                console.print("[green]✓ Redis connected[/green]")
            else:
                console.print("[yellow]Redis connection failed, fallback to local mode[/yellow]")
                self.redis = None

    def start_monitors(self):
        # Perm Monitor
        perm_monitor = PermissionMonitor(
            ssh_config=self.config['ssh'],
            monitor_config=self.config['perm_config'],
            db_name=os.path.join(self.backup_dir, "permissions.db")
        )
        self.monitors.append(perm_monitor)
        threading.Thread(target=perm_monitor.start, daemon=True).start()

        # File Monitor
        file_monitor = FileOperationsMonitor(
            ssh_config=self.config['ssh'],
            monitor_config=self.config['file_config'],
            db_name=os.path.join(self.backup_dir, "files.db")
        )
        self.monitors.append(file_monitor)
        threading.Thread(target=file_monitor.start, daemon=True).start()

        console.print("[green]✓ Monitors started[/green]")

    def start_restore(self):
        if self.config['mode'] == "active":
            rsync = RsyncBackup(
                ssh_config=self.config['ssh'],
                source=self.config['path'],
                backup_path=self.config['backup_path']
            )
            rsync.run_restore_loop(stop_event=self.stop_event)
            console.print("[green]✓ Active restore loop started[/green]")

    def start(self):
        console.print("[cyan]Starting Anti-Defacement System...[/cyan]")
        self.setup_redis()
        self.start_monitors()
        if self.config['mode'] == "active":
            self.start_restore()
        try:
            while not self.stop_event.is_set():
                pass  # فقط نگه می‌داره
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        console.print("[yellow]Stopping Anti-Defacement...[/yellow]")
        self.stop_event.set()
        for monitor in self.monitors:
            if hasattr(monitor, "stop"):
                monitor.stop()
        console.print("[green]✓ All stopped[/green]")
