# core/manager.py
import os
import threading
from datetime import datetime
from rich.console import Console

# ماژول‌های دیگر رو بارگذاری می‌کنیم
try:
    from permission_monitoring import PermissionMonitor, SSHConfig, MonitorConfig
except ImportError:
    print("Warning: permission_monitoring module not found")
    PermissionMonitor = None
    SSHConfig = None
    MonitorConfig = None

try:
    from ssh import FileOperationsMonitor
except ImportError:
    print("Warning: ssh module not found")
    FileOperationsMonitor = None

try:
    from rsync import RsyncBackup
except ImportError:
    print("Warning: rsync module not found")
    RsyncBackup = None

try:
    from red import RedisConfig
except ImportError:
    print("Warning: red module not found")
    RedisConfig = None

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
        if self.config.get("use_redis") and RedisConfig:
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
        else:
            console.print("[yellow]Redis not configured or module not available[/yellow]")

    def start_monitors(self):
        if not (SSHConfig and MonitorConfig):
            console.print("[yellow]SSH or Monitor config classes not available[/yellow]")
            return

        # تبدیل دیکشنری‌ها به dataclassها
        ssh_config = SSHConfig(**self.config['ssh'])
        perm_config = MonitorConfig(**self.config['perm_config'])
        file_config = MonitorConfig(**self.config['file_config'])

        # Permission Monitor
        if PermissionMonitor:
            perm_monitor = PermissionMonitor(
                ssh_config=ssh_config,
                monitor_config=perm_config,
                db_path=os.path.join(self.backup_dir, "permissions.db")
            )

            # Redis به مانیتور تزریق می‌کنیم
            if self.redis:
                perm_monitor.redis = self.redis

            self.monitors.append(perm_monitor)
            threading.Thread(target=perm_monitor.start, daemon=True).start()

        # File Operations Monitor
        if FileOperationsMonitor:
            file_monitor = FileOperationsMonitor(
                ssh_config=ssh_config,
                monitor_config=file_config,
                db_path=os.path.join(self.backup_dir, "files.db")
            )
            self.monitors.append(file_monitor)
            threading.Thread(target=file_monitor.start, daemon=True).start()

        console.print("[green]✓ Monitors started[/green]")

    def start_restore(self):
        if self.config['mode'] == "active" and RsyncBackup:
            rsync = RsyncBackup(
                ssh_config=self.config['ssh'],
                source=self.config['path'],
                backup_path=self.config['backup_path']
            )
            threading.Thread(target=rsync.run_restore_loop, args=(self.stop_event,), daemon=True).start()
            console.print("[green]✓ Active restore loop started[/green]")
        else:
            console.print("[yellow]Active mode not available or RsyncBackup not found[/yellow]")

    def start(self):
        console.print("[cyan]Starting Anti-Defacement System...[/cyan]")
        self.setup_redis()
        self.start_monitors()
        if self.config['mode'] == "active":
            self.start_restore()
        try:
            while not self.stop_event.is_set():
                pass
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        console.print("[yellow]Stopping Anti-Defacement...[/yellow]")
        self.stop_event.set()
        for monitor in self.monitors:
            if hasattr(monitor, "stop"):
                monitor.stop()
        console.print("[green]✓ All stopped[/green]")
