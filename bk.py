#!/usr/bin/env python3

import os
import sys
import time
import argparse
import threading
import json
import logging
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich.logging import RichHandler
import getpass
import paramiko
import redis
from rq import Queue
import json

# Import the modules from the existing scripts
from permission_monitoring import SSHConfig as PermSSHConfig, MonitorConfig as PermMonitorConfig, PermissionMonitor
from ssh import SSHConfig as FileSSHConfig, MonitorConfig as FileMonitorConfig, FileOperationsMonitor
import rsync

console = Console()





    def connect(self):
        """Establish Redis connection"""
        try:
            self.connection = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=True
            )
            # Test connection
            self.connection.ping()
            console.print(f"[green]✓ Connected to Redis at {self.host}:{self.port}[/green]")
            
            # Create RQ queue for job management
            self.queue = Queue(connection=self.connection)
            return True
        except Exception as e:
            console.print(f"[red]Failed to connect to Redis: {str(e)}[/red]")
            return False
    
    def publish_event(self, channel, event_data):
        """Publish event to Redis channel"""
        if self.connection:
            try:
                self.connection.publish(channel, json.dumps(event_data))
                return True
            except Exception as e:
                console.print(f"[red]Failed to publish to Redis: {str(e)}[/red]")
                return False
    
    def add_to_queue(self, queue_name, data):
        """Add data to Redis queue"""
        if self.connection:
            try:
                self.connection.lpush(queue_name, json.dumps(data))
                return True
            except Exception as e:
                console.print(f"[red]Failed to add to Redis queue: {str(e)}[/red]")
                return False
    
    def get_from_queue(self, queue_name, timeout=1):
        """Get data from Redis queue (blocking)"""
        if self.connection:
            try:
                result = self.connection.brpop(queue_name, timeout=timeout)
                if result:
                    return json.loads(result[1])
                return None
            except Exception as e:
                console.print(f"[red]Failed to get from Redis queue: {str(e)}[/red]")
                return None

class AntiDefacement:
    def __init__(self, ssh_user, ssh_host, ssh_port, path, mode="passive", 
             ssh_key=None, ssh_password=None, interval=1, backup_path=None,
             redis_host='localhost', redis_port=6379, redis_password=None, use_redis=False):
    # ... your existing code ...
    
    # Redis configuration
    self.use_redis = use_redis
    self.redis_config = None
    if use_redis:
        self.redis_config = RedisConfig(
            host=redis_host,
            port=redis_port,
            password=redis_password
        )
        if not self.redis_config.connect():
            console.print("[yellow]Warning: Redis connection failed, falling back to local queues[/yellow]")
            self.use_redis = False
        """
        Initialize the Anti-Defacement monitoring system
        
        Args:
            ssh_user: SSH username
            ssh_host: SSH host (IP or domain)
            ssh_port: SSH port
            path: Path to monitor on the remote system
            mode: 'passive' for logging only, 'active' for automatic restoration
            ssh_key: Path to SSH private key
            ssh_password: SSH password (if not using key-based auth)
            interval: Monitoring interval in seconds
            backup_path: Custom path for storing backups on the remote server (active mode only)
        """
        self.ssh_user = ssh_user
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.path = path
        self.mode = mode
        self.ssh_key = ssh_key
        self.ssh_password = ssh_password
        self.interval = interval
        self.custom_backup_path = backup_path
        
        # Create a directory to store logs (not backups, since we'll use the remote machine)
        self.backup_dir = f"logs_{ssh_host}_{ssh_port}_{path.replace('/', '_')}"
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
        # Main SSH config that will be used for the restore operations
        self.ssh_config = {
            'host': ssh_host,
            'port': int(ssh_port),
            'username': ssh_user,
            'password': ssh_password,
            'key_path': ssh_key
        }
        
        # Configuration for the different monitors
        self.perm_ssh_config = PermSSHConfig(
            host=ssh_host,
            port=int(ssh_port),
            username=ssh_user,
            password=ssh_password,
            key_path=ssh_key
        )
        
        self.perm_monitor_config = PermMonitorConfig(
            path=path,
            interval=interval,
            recursive=True,
            ignore_patterns=[".git", "__pycache__", ".env"]
        )
        
        self.file_ssh_config = FileSSHConfig(
            host=ssh_host,
            port=int(ssh_port),
            username=ssh_user,
            password=ssh_password,
            key_path=ssh_key
        )
        
        self.file_monitor_config = FileMonitorConfig(
            path=path,
            interval=interval,
            recursive=True,
            ignore_patterns=[".git", "__pycache__", ".env"]
        )
        
        # Reference to all running monitors for cleanup
        self.monitors = []
        self.stop_event = threading.Event()
        
        # Path for the remote backup (will be set in _setup_initial_backup)
        self.remote_backup_path = None

    def _queue_event(self, event_type, event_data):
    """Queue an event either to Redis or local queue"""
    event = {
        'timestamp': datetime.now().isoformat(),
        'type': event_type,
        'host': self.ssh_host,
        'path': self.path,
        'data': event_data
    }
    
    if self.use_redis and self.redis_config:
        # Send to Redis
        queue_name = f"antidefacement:{self.ssh_host}:{event_type}"
        self.redis_config.add_to_queue(queue_name, event)
        
        # Also publish to channel for real-time monitoring
        channel = f"antidefacement:events:{self.ssh_host}"
        self.redis_config.publish_event(channel, event)
    else:
        # Log locally as before
        self.logger.info(f"[{event_type.upper()}] {json.dumps(event_data)}")

def _process_redis_events(self):
    """Background thread to process Redis events"""
    if not (self.use_redis and self.redis_config):
        return
    
    def redis_processor():
        queue_names = [
            f"antidefacement:{self.ssh_host}:permission",
            f"antidefacement:{self.ssh_host}:file_change",
            f"antidefacement:{self.ssh_host}:restore"
        ]
        
        while not self.stop_event.is_set():
            for queue_name in queue_names:
                event = self.redis_config.get_from_queue(queue_name, timeout=1)
                if event:
                    # Process the event
                    event_type = event.get('type', 'unknown')
                    if event_type == 'restore' and self.mode == 'active':
                        console.print(f"[bold green]Redis: Restore event processed for {event['data']}[/bold green]")
                    else:
                        console.print(f"[blue]Redis: {event_type} event - {event['data']}[/blue]")
    
    # Start Redis processor thread
    thread = threading.Thread(target=redis_processor)
    thread.daemon = True
    thread.start()

    def _setup_logging(self):
        """Setup logging for the anti-defacement system"""
        log_file = os.path.join(self.backup_dir, "anti_defacement.log")
        
        # Configure root logger with minimal format
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=[
                logging.FileHandler(log_file)
            ]
        )
        
        # Configure rich handler separately with minimal format
        rich_handler = RichHandler(
            rich_tracebacks=True, 
            console=console,
            show_path=False,  # Hide file path
            show_time=False,  # Hide timestamp (Rich console will add its own)
            markup=True
        )
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        
        # Get logger and add handler
        self.logger = logging.getLogger("AntiDefacement")
        self.logger.addHandler(rich_handler)
        
        # Remove propagation to avoid duplicate messages
        self.logger.propagate = False
        
        self.logger.info(f"Starting Anti-Defacement System for {self.ssh_host}:{self.path}")
        self.logger.info(f"Mode: {self.mode.upper()} - {'Automatic restoration' if self.mode == 'active' else 'Logging only'}")

    def _setup_initial_backup(self):
        """Create initial backup of the monitored path directly on the remote machine if in active mode"""
        if self.mode == "active":
            console.print(f"[bold green]Setting up initial backup on the remote server for {self.path}...[/bold green]")
            try:
                # Create a backup directory on the remote server
                sanitized_source = self.path.strip('/').replace('/', '_')
                
                # Use custom backup path if provided, otherwise use default in /tmp
                if self.custom_backup_path:
                    self.remote_backup_path = self.custom_backup_path
                else:
                    self.remote_backup_path = f"/tmp/anti_defacement_backup_{sanitized_source}"
                    
                # Use SSH to create the backup directory and make an initial copy
                ssh_cmd = f"mkdir -p {self.remote_backup_path} && " + \
                          f"rsync -azq {self.path}/ {self.remote_backup_path}/ && " + \
                          f"echo 'Backup completed to {self.remote_backup_path}'"
                
                # Connect and execute the command
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connect_kwargs = {
                    'hostname': self.ssh_config['host'],
                    'port': self.ssh_config['port'],
                    'username': self.ssh_config['username']
                }
                
                if self.ssh_config['password']:
                    connect_kwargs['password'] = self.ssh_config['password']
                if self.ssh_config['key_path']:
                    connect_kwargs['key_filename'] = os.path.expanduser(self.ssh_config['key_path'])

                self.ssh_client.connect(**connect_kwargs)
                stdin, stdout, stderr = self.ssh_client.exec_command(ssh_cmd)
                
                # Check the output
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                
                if error:
                    raise Exception(error)
                    
                console.print(f"[green]✓ Initial backup completed on remote server: {self.remote_backup_path}[/green]")
                self.logger.info(f"Initial backup created on remote server at {self.remote_backup_path}")
                
                # Save metadata about the backup
                backup_info = {
                    "timestamp": datetime.now().isoformat(),
                    "path": self.path,
                    "host": self.ssh_host,
                    "port": self.ssh_port,
                    "remote_backup_path": self.remote_backup_path
                }
                
                with open(f"{self.backup_dir}/backup_info.json", "w") as f:
                    json.dump(backup_info, f, indent=4)
                
            except Exception as e:
                console.print(f"[bold red]Error creating initial backup: {str(e)}[/bold red]")
                if self.mode == "active":
                    console.print("[bold yellow]Warning: Active mode requires an initial backup. Falling back to passive mode.[/bold yellow]")
                    self.mode = "passive"

    def _start_permission_monitor(self):
        """Start the permission monitoring thread"""
        try:
            db_name = f"{self.backup_dir}/permission_changes.db"
            perm_monitor = PermissionMonitor(
                self.perm_ssh_config,
                self.perm_monitor_config,
                db_name
            )
            self.monitors.append(perm_monitor)
            
            # Create and start the thread, but don't make it a daemon
            thread = threading.Thread(target=perm_monitor.start)
            thread.daemon = False  # Allow the thread to clean up properly
            thread.start()
            
            console.print(f"[green]✓ Permission monitoring started for {self.path}[/green]")
        except Exception as e:
            console.print(f"[red]Error starting permission monitor: {str(e)}[/red]")

    def _start_file_operations_monitor(self):
        """Start the file operations monitoring thread"""
        try:
            db_name = f"{self.backup_dir}/file_operations.db"
            file_monitor = FileOperationsMonitor(
                self.file_ssh_config,
                self.file_monitor_config,
                db_name
            )
            self.monitors.append(file_monitor)
            
            # Create and start the thread, but don't make it a daemon
            thread = threading.Thread(target=file_monitor.start)
            thread.daemon = False  # Allow the thread to clean up properly
            thread.start()
            
            console.print(f"[green]✓ File operations monitoring started for {self.path}[/green]")
        except Exception as e:
            console.print(f"[red]Error starting file operations monitor: {str(e)}[/red]")

    def _start_rsync_monitor(self):
        """Start the restore monitor for active restoration on the remote server"""
        if self.mode == "active":
            try:
                # Get a reference to the console in the enclosing scope
                local_console = console
                local_logger = self.logger
                remote_backup_path = self.remote_backup_path
                monitored_path = self.path
                ssh_config = self.ssh_config
                stop_event = self.stop_event
                
                # Function to restore files from the backup when changes are detected
                def run_restore_monitor():
                    try:
                        local_console.print("[bold green]Starting remote restore monitor...[/bold green]")
                        
                        # Connect to the SSH server
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        
                        connect_kwargs = {
                            'hostname': ssh_config['host'],
                            'port': ssh_config['port'],
                            'username': ssh_config['username']
                        }
                        
                        if ssh_config['password']:
                            connect_kwargs['password'] = ssh_config['password']
                        if ssh_config['key_path']:
                            connect_kwargs['key_filename'] = os.path.expanduser(ssh_config['key_path'])
                            
                        ssh.connect(**connect_kwargs)
                        
                        # Create a function to perform the actual restoration
                        def perform_restore(reason=None):
                            if reason:
                                local_console.print(f"[bold red]⚠ Unauthorized change detected: {reason}[/bold red]")
                                local_logger.warning(f"[RESTORE] {reason}")
                            
                            restore_cmd = f"rsync -azq --delete {remote_backup_path}/ {monitored_path}/"
                            stdin, stdout, stderr = ssh.exec_command(restore_cmd)
                            error = stderr.read().decode().strip()
                            
                            if error:
                                local_console.print(f"[red]Error during restore: {error}[/red]")
                                local_logger.error(f"Restore error: {error}")
                                return False
                            else:
                                if reason:  # Only log success if it was triggered by a specific change
                                    local_console.print(f"[green]✓ Files restored successfully from backup[/green]")
                                    local_logger.info(f"Files successfully restored from backup after detecting: {reason}")
                                return True
                        
                        # Start with an initial restore to ensure everything is in sync
                        perform_restore("Initial synchronization")
                        
                        # Get a baseline of the monitored directory (just a hash of the directory listing)
                        def get_dir_hash():
                            cmd = f"find {monitored_path} -type f -o -type d | sort | md5sum"
                            stdin, stdout, stderr = ssh.exec_command(cmd)
                            dir_hash = stdout.read().decode().strip().split()[0]
                            return dir_hash
                        
                        baseline_hash = get_dir_hash()
                        local_console.print(f"[blue]Baseline established. Monitoring for changes...[/blue]")
                        
                        # Monitor for changes and restore when needed
                        last_restore_time = time.time()
                        last_check_time = time.time()
                        last_full_check_time = time.time()
                        
                        while not stop_event.is_set():
                            try:
                                current_time = time.time()
                                changes_detected = False
                                
                                # Check for recent file changes (fast check)
                                if current_time - last_check_time >= 0.5:  # Check every half second
                                    # Check for new or modified files
                                    check_cmd = (
                                        f"find {monitored_path} -type f -newermt \"$(date -d '1 second ago' '+%Y-%m-%d %H:%M:%S')\" "
                                        f"-o -type d -newermt \"$(date -d '1 second ago' '+%Y-%m-%d %H:%M:%S')\" | head -1"
                                    )
                                    stdin, stdout, stderr = ssh.exec_command(check_cmd)
                                    recent_changes = stdout.read().decode().strip()
                                    
                                    if recent_changes:
                                        changes_detected = True
                                        perform_restore(f"Unauthorized change to {recent_changes}")
                                    
                                    last_check_time = current_time
                                
                                # Do a full directory check periodically (more thorough)
                                if current_time - last_full_check_time >= 3:  # Every 3 seconds
                                    current_hash = get_dir_hash()
                                    if current_hash != baseline_hash:
                                        changes_detected = True
                                        perform_restore("Directory structure changed")
                                        baseline_hash = get_dir_hash()  # Update baseline after restore
                                    
                                    last_full_check_time = current_time
                                
                                # Periodic restore regardless of changes (safety net)
                                if current_time - last_restore_time >= 5:  # Every 5 seconds
                                    perform_restore()
                                    last_restore_time = current_time
                                
                                # Brief sleep to avoid excessive CPU usage
                                time.sleep(0.1)
                                
                            except Exception as inner_e:
                                local_console.print(f"[red]Error during restoration cycle: {str(inner_e)}[/red]")
                                local_logger.error(f"Restoration cycle error: {str(inner_e)}")
                                time.sleep(2)  # Sleep a bit longer on error
                                
                    except Exception as e:
                        local_console.print(f"[red]Error in restore monitor: {str(e)}[/red]")
                        local_logger.error(f"Restore monitor error: {str(e)}")
                    finally:
                        if 'ssh' in locals():
                            ssh.close()
                
                # Create and start the restore monitor thread as a daemon
                thread = threading.Thread(target=run_restore_monitor)
                thread.daemon = True
                thread.start()
                
                console.print(f"[green]✓ Active restoration started for {self.path} using backup at {self.remote_backup_path}[/green]")
                console.print(f"[green]✓ Any unauthorized changes will be instantly reverted[/green]")
            except Exception as e:
                console.print(f"[red]Error starting restore monitor: {str(e)}[/red]")

    def start(self):
        """Start all monitoring components"""
        mode_color = "green" if self.mode == "active" else "yellow"
        
        # Show different panels for active vs passive mode
        if self.mode == "active":
            console.print(Panel(
                f"[bold cyan]Anti-Defacement System[/bold cyan]\n\n"
                f"[green]Host:[/green] {self.ssh_host}:{self.ssh_port}\n"
                f"[green]Path:[/green] {self.path}\n"
                f"[{mode_color}]Mode:[/{mode_color}] [{mode_color}]{self.mode.upper()}[/{mode_color}]\n"
                f"[green]Backup Location:[/green] {self.remote_backup_path}\n"
                f"[green]Interval:[/green] {self.interval} seconds",
                title="Starting Active Monitoring",
                border_style=mode_color
            ))
        else:
            console.print(Panel(
                f"[bold cyan]Anti-Defacement System[/bold cyan]\n\n"
                f"[green]Host:[/green] {self.ssh_host}:{self.ssh_port}\n"
                f"[green]Path:[/green] {self.path}\n"
                f"[{mode_color}]Mode:[/{mode_color}] [{mode_color}]{self.mode.upper()}[/{mode_color}]\n"
                f"[green]Interval:[/green] {self.interval} seconds",
                title="Starting Passive Monitoring",
                border_style=mode_color
            ))
        
        # Setup initial backup if in active mode
        self._setup_initial_backup()
        
        # Start the monitors
        self._start_permission_monitor()
        self._start_file_operations_monitor()
        
        if self.mode == "active":
            console.print("[bold green]▶ Active mode enabled - changes will be automatically reverted[/bold green]")
            console.print(f"[bold green]✓ Initial backup created at {self.remote_backup_path}[/bold green]")
            console.print("[bold green]✓ All changes will be automatically restored within seconds[/bold green]")
            self._start_rsync_monitor()
            
            # Print status update every 2 minutes in active mode
            def active_status_updater():
                counter = 0
                while not self.stop_event.is_set():
                    time.sleep(20)
                    counter += 1
                    if counter % 6 == 0:  # Print status message every 2 minutes
                        console.print(f"[green]Actively protecting {self.path} on {self.ssh_host} (backup: {self.remote_backup_path}) ✓[/green]")
                        self.logger.info(f"Status: Active protection for {self.path} using backup at {self.remote_backup_path}")
            
            # Start status updater thread in active mode
            active_status_thread = threading.Thread(target=active_status_updater)
            active_status_thread.daemon = True
            active_status_thread.start()
        else:
            console.print("[bold yellow]▶ Passive mode enabled - changes will only be logged[/bold yellow]")
            console.print("[bold cyan]Waiting for changes...[/bold cyan]")
            console.print(f"[italic]All detected changes will be logged to: {os.path.join(self.backup_dir, 'anti_defacement.log')}[/italic]")
            self.logger.info("Passive monitoring started")
            
            # Print status update every minute in passive mode
            def status_updater():
                counter = 0
                while not self.stop_event.is_set():
                    time.sleep(15)
                    counter += 1
                    if counter % 20 == 0:  # Print status message every 5 minutes (reduced frequency)
                        console.print(f"[blue]Monitoring {self.path} on {self.ssh_host}...[/blue]")
                        # Don't log these status messages to reduce log spam
            
            # Start status updater thread in passive mode
            status_thread = threading.Thread(target=status_updater)
            status_thread.daemon = True
            status_thread.start()
        
        try:
            # Keep the main thread alive to handle keyboard interrupts
            past_queue_sizes = {}
            last_status_time = time.time()
            
            while not self.stop_event.is_set():
                # Monitor for changes by checking queue sizes
                for i, monitor in enumerate(self.monitors):
                    if hasattr(monitor, 'changes_queue'):
                        current_size = monitor.changes_queue.qsize()
                        previous_size = past_queue_sizes.get(i, 0)
                        
                        if current_size > previous_size:
                            # New changes have been detected
                            new_changes = current_size - previous_size
                            monitor_name = monitor.__class__.__name__
                            
                            # Group events logically - check if it's a file or directory change
                            monitor_type = "directory" if "Directory" in monitor_name else "file"
                            if monitor_name == "PermissionMonitor":
                                change_type = "permission"
                            elif monitor_name == "FileOperationsMonitor":
                                change_type = "content"
                            else:
                                change_type = "system"
                            
                            mode_prefix = "[RESTORE]" if self.mode == "active" else "[LOG]"
                            self.logger.info(f"{mode_prefix} {new_changes} {monitor_type} {change_type} change(s) detected")
                            
                            if self.mode == "active":
                                console.print(f"[bold green]{new_changes} {monitor_type} {change_type} change(s) detected - RESTORING[/bold green]")
                            else:
                                console.print(f"[bold magenta]{new_changes} {monitor_type} {change_type} change(s) detected - LOGGING ONLY[/bold magenta]")
                            
                        past_queue_sizes[i] = current_size
                
                # Very infrequent debug check - no need to log to file
                current_time = time.time()
                if current_time - last_status_time > 300:  # Every 5 minutes
                    self.logger.debug(f"Monitoring active ({self.mode})")
                    last_status_time = current_time
                
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop all monitoring components"""
        console.print("\n[yellow]Stopping Anti-Defacement monitoring...[/yellow]")
        self.stop_event.set()
        
        # Stop all monitors and ensure they clean up properly
        for monitor in self.monitors:
            try:
                if hasattr(monitor, 'stop'):
                    monitor.stop()
                    console.print(f"[green]✓ Stopped monitor: {monitor.__class__.__name__}[/green]")
            except Exception as e:
                console.print(f"[yellow]Warning when stopping monitor: {str(e)}[/yellow]")
        
        # Close SSH connection if it exists
        if hasattr(self, 'ssh_client') and self.ssh_client:
            try:
                self.ssh_client.close()
                console.print("[green]✓ SSH connection closed[/green]")
            except Exception as e:
                console.print(f"[yellow]Warning when closing SSH connection: {str(e)}[/yellow]")
        
        console.print("[green]All monitoring stopped.[/green]")
        
        # Give the threads a moment to clean up
        time.sleep(1)

def get_user_inputs(args):
    """Get user inputs either from command line args or interactive prompts."""

    # Determine Redis usage
    use_redis = args.use_redis
    if not use_redis and not args.user:  # Only ask in interactive mode
        use_redis = Confirm.ask("Do you want to use Redis for queue management?", default=False)

    redis_host = args.redis_host if use_redis else 'localhost'
    redis_port = args.redis_port if use_redis else 6379
    redis_password = args.redis_password if use_redis else None

    # Gather SSH and monitoring parameters
    if not all([args.user, args.host, args.path]):
        console.print("[cyan]Please provide the following information:[/cyan]")

        ssh_user = args.user or Prompt.ask("Enter SSH username")
        ssh_host = args.host or Prompt.ask("Enter SSH host (IP or domain)")
        ssh_port = args.port or Prompt.ask("Enter SSH port", default="22")
        path = args.path or Prompt.ask("Enter path to monitor on remote system")

        # Authentication method
        if not args.key and not args.password:
            auth_method = Prompt.ask(
                "Choose authentication method",
                choices=["password", "key"],
                default="key"
            )
            ssh_key = None
            ssh_password = None
            if auth_method == "password":
                ssh_password = getpass.getpass("Enter SSH password: ")
            else:
                ssh_key = Prompt.ask(
                    "Enter path to SSH private key",
                    default=os.path.expanduser("~/.ssh/id_rsa")
                )
        else:
            ssh_key = args.key
            ssh_password = args.password

        # Monitoring mode
        if not args.mode:
            mode = Prompt.ask(
                "Choose monitoring mode",
                choices=["passive", "active"],
                default="passive"
            )
        else:
            mode = args.mode

        # Backup path for active mode
        backup_path = None
        if mode == "active" and not args.backup_path:
            if Confirm.ask("Do you want to specify a custom backup path on the remote server?", default=False):
                backup_path = Prompt.ask(
                    "Enter backup path on remote server",
                    default="/tmp/anti_defacement_backup"
                )
        else:
            backup_path = args.backup_path

        interval = args.interval or int(Prompt.ask("Enter monitoring interval in seconds", default="1"))

    else:
        ssh_user = args.user
        ssh_host = args.host
        ssh_port = args.port or "22"
        path = args.path
        ssh_key = args.key
        ssh_password = args.password
        mode = args.mode or "passive"
        interval = args.interval or 1
        backup_path = args.backup_path

    return {
        "ssh_user": ssh_user,
        "ssh_host": ssh_host,
        "ssh_port": ssh_port,
        "path": path,
        "ssh_key": ssh_key,
        "ssh_password": ssh_password,
        "mode": mode,
        "interval": interval,
        "backup_path": backup_path,
        "use_redis": use_redis,
        "redis_host": redis_host,
        "redis_port": redis_port,
        "redis_password": redis_password
    }

def main():
    parser = argparse.ArgumentParser(description="Anti-Defacement Monitoring System")
    parser.add_argument("--user", help="SSH username")
    parser.add_argument("--host", help="SSH host (IP or domain)")
    parser.add_argument("--port", help="SSH port (default: 22)")
    parser.add_argument("--path", help="Path to monitor on remote system")
    parser.add_argument("--key", help="Path to SSH private key")
    parser.add_argument("--password", help="SSH password (not recommended, use key-based auth)")
    parser.add_argument("--mode", choices=["passive", "active"], help="Monitoring mode: passive (log only) or active (automatically restore)")
    parser.add_argument("--interval", type=int, help="Monitoring interval in seconds")
    parser.add_argument("--backup-path", help="Custom path for storing backups on the remote server (active mode only)")
    parser.add_argument("--redis-host", default="localhost", help="Redis host")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    parser.add_argument("--redis-password", help="Redis password")
    parser.add_argument("--use-redis", action="store_true", help="Use Redis for queue management")
    args = parser.parse_args()
    
    # Display header
    console.print("\n[bold green]================================[/bold green]")
    console.print("[bold green]   Anti-Defacement System   [/bold green]")
    console.print("[bold green]================================[/bold green]\n")
    
    try:
        # Get configuration inputs
        config = get_user_inputs(args)
        
        # Start the anti-defacement system
        monitor = AntiDefacement(**config)
        monitor.start()
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring cancelled by user[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main() 
