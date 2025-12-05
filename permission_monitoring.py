import paramiko
import time
import json
import logging
import sys
from datetime import datetime
import hashlib
import os
import threading
import queue
from dataclasses import dataclass, asdict
import sqlite3
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from typing import Dict, Optional, List, Tuple
import stat
import getpass

@dataclass
class SSHConfig:
    host: str
    port: int
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None

@dataclass
class MonitorConfig:
    path: str
    interval: int = 1
    recursive: bool = True
    ignore_patterns: List[str] = None

class PermissionMonitor:
    def __init__(self, ssh_config: SSHConfig, monitor_config: MonitorConfig, db_path: str = 'permission_changes.db'):
        self.ssh_config = ssh_config
        self.config = monitor_config
        self.db_path = db_path
        self.stop_event = threading.Event()
        self.changes_queue = queue.Queue()
        self.console = Console()
        self.db_lock = threading.Lock()
        
        # Configure logger with minimal format
        self.logger = logging.getLogger(f"PermMonitor-{ssh_config.host}")
        self.logger.propagate = False  # Prevent duplicate messages
        
        # Add a custom formatter to hide path information
        for handler in logging.root.handlers:
            if isinstance(handler, logging.FileHandler):
                handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
        
        self._setup_ssh()
        self._setup_database()

    def _setup_ssh(self):
        """Enhanced SSH setup with comprehensive authentication handling"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.console.print(f"[cyan]Attempting to connect to {self.ssh_config.host}:{self.ssh_config.port}[/cyan]")
            self.console.print(f"[cyan]Username: {self.ssh_config.username}[/cyan]")
            
            # Debug: Show what authentication info we have
            has_password = bool(self.ssh_config.password)
            has_key = bool(self.ssh_config.key_path)
            self.console.print(f"[cyan]Has password: {has_password}, Has key path: {has_key}[/cyan]")
            
            connect_kwargs = {
                'hostname': self.ssh_config.host,
                'port': self.ssh_config.port,
                'username': self.ssh_config.username,
                'timeout': 30,  # Increase timeout
                'allow_agent': True,
                'look_for_keys': True,
                'banner_timeout': 30,
                'auth_timeout': 30,
            }
            
            auth_success = False
            
            # Method 1: Try with provided password first
            if self.ssh_config.password and not auth_success:
                try:
                    self.console.print("[yellow]Trying password authentication...[/yellow]")
                    temp_kwargs = connect_kwargs.copy()
                    temp_kwargs['password'] = self.ssh_config.password
                    temp_kwargs['look_for_keys'] = False  # Disable key lookup for password auth
                    temp_kwargs['allow_agent'] = False   # Disable agent for password auth
                    
                    self.ssh_client.connect(**temp_kwargs)
                    auth_success = True
                    self.console.print("[green]✓ Password authentication successful[/green]")
                except paramiko.AuthenticationException as e:
                    self.console.print(f"[red]✗ Password authentication failed: {str(e)}[/red]")
                except Exception as e:
                    self.console.print(f"[red]✗ Password authentication error: {str(e)}[/red]")
            
            # Method 2: Try with provided key file
            if self.ssh_config.key_path and not auth_success:
                try:
                    key_path = os.path.expanduser(self.ssh_config.key_path)
                    self.console.print(f"[yellow]Trying key file authentication: {key_path}[/yellow]")
                    
                    if os.path.exists(key_path):
                        # Check key file permissions
                        key_stat = os.stat(key_path)
                        key_perms = oct(key_stat.st_mode)[-3:]
                        self.console.print(f"[cyan]Key file permissions: {key_perms}[/cyan]")
                        
                        temp_kwargs = connect_kwargs.copy()
                        temp_kwargs['key_filename'] = key_path
                        temp_kwargs['look_for_keys'] = False
                        temp_kwargs['allow_agent'] = False
                        
                        self.ssh_client.connect(**temp_kwargs)
                        auth_success = True
                        self.console.print("[green]✓ Key file authentication successful[/green]")
                    else:
                        self.console.print(f"[red]✗ Key file not found: {key_path}[/red]")
                except paramiko.AuthenticationException as e:
                    self.console.print(f"[red]✗ Key file authentication failed: {str(e)}[/red]")
                except Exception as e:
                    self.console.print(f"[red]✗ Key file authentication error: {str(e)}[/red]")
            
            # Method 3: Try SSH agent and default keys
            # Method 5: Interactive password prompt
            if not auth_success:
                self.console.print("[bold yellow]All automatic authentication methods failed![/bold yellow]")
                self.console.print("[yellow]Attempting interactive authentication...[/yellow]")

                for attempt in range(3):
                    try:
                        password = getpass.getpass(
                            f"Password for {self.ssh_config.username}@{self.ssh_config.host} (attempt {attempt + 1}/3): "
                        )
                        if not password.strip():
                            self.console.print("[yellow]Empty password entered, skipping...[/yellow]")
                            continue

                        temp_kwargs = connect_kwargs.copy()
                        temp_kwargs['password'] = password
                        temp_kwargs['look_for_keys'] = False
                        temp_kwargs['allow_agent'] = False

                        self.ssh_client.connect(**temp_kwargs)
                        auth_success = True
                        self.console.print("[green]✓ Manual password authentication successful[/green]")

            # ذخیره پسورد برای استفاده بعدی
                        self.ssh_config.password = password
                        break

                    except paramiko.AuthenticationException:
                        self.console.print(f"[red]✗ Manual password failed (attempt {attempt + 1}/3)[/red]")
                    except Exception as e:
                        self.console.print(f"[red]✗ Manual password error: {str(e)}[/red]")

            if not auth_success:
                self.console.print("[bold red]All authentication methods exhausted![/bold red]")
                self.console.print("[yellow]Please check:")
                self.console.print(" 1. Username is correct")
                self.console.print(" 2. Password is correct")
                self.console.print(" 3. SSH keys exist and have proper permissions (600)")
                self.console.print(" 4. SSH server allows your auth method")
                self.console.print(f" 5. Try manually: ssh {self.ssh_config.username}@{self.ssh_config.host}")
                raise paramiko.AuthenticationException("All authentication methods failed")
                
                for key_path in default_keys:
                    expanded_path = os.path.expanduser(key_path)
                    if os.path.exists(expanded_path):
                        try:
                            self.console.print(f"[yellow]Trying default key: {expanded_path}[/yellow]")
                            temp_kwargs = connect_kwargs.copy()
                            temp_kwargs['key_filename'] = expanded_path
                            temp_kwargs['look_for_keys'] = False
                            temp_kwargs['allow_agent'] = False
                            
                            self.ssh_client.connect(**temp_kwargs)
                            auth_success = True
                            self.console.print(f"[green]✓ Default key successful: {expanded_path}[/green]")
                            break
                        except paramiko.AuthenticationException:
                            self.console.print(f"[red]✗ Default key failed: {expanded_path}[/red]")
                        except Exception as e:
                            self.console.print(f"[red]✗ Default key error: {expanded_path} - {str(e)}[/red]")
            
            # Method 5: Interactive password prompt
            if not auth_success:
                self.console.print("[bold yellow]All automatic authentication methods failed![/bold yellow]")
                self.console.print("[yellow]Attempting interactive authentication...[/yellow]")
                
                # First, let's try to see what auth methods are available
                try:
                    transport = paramiko.Transport((self.ssh_config.host, self.ssh_config.port))
                    transport.connect()
                    auth_methods = transport.auth_none(self.ssh_config.username)
                    self.console.print(f"[cyan]Available authentication methods: {auth_methods}[/cyan]")
                    transport.close()
                except Exception as e:
                    self.console.print(f"[yellow]Could not determine auth methods: {str(e)}[/yellow]")
                
                # Try manual password entry
                for attempt in range(3):
                    try:
                        password = getpass.getpass(f"Password for {self.ssh_config.username}@{self.ssh_config.host} (attempt {attempt + 1}/3): ")
                        if not password.strip():
                            self.console.print("[yellow]Empty password entered, skipping...[/yellow]")
                            continue
                        
                        temp_kwargs = connect_kwargs.copy()
                        temp_kwargs['password'] = password
                        temp_kwargs['look_for_keys'] = False
                        temp_kwargs['allow_agent'] = False
                        
                        self.ssh_client.connect(**temp_kwargs)
                        auth_success = True
                        self.console.print("[green]✓ Manual password authentication successful[/green]")
                        break
                    except paramiko.AuthenticationException:
                        self.console.print(f"[red]✗ Manual password failed (attempt {attempt + 1}/3)[/red]")
                    except Exception as e:
                        self.console.print(f"[red]✗ Manual password error: {str(e)}[/red]")
            
            if not auth_success:
                self.console.print("[bold red]All authentication methods exhausted![/bold red]")
                self.console.print("[yellow]Please check:[/yellow]")
                self.console.print("[yellow]1. Username is correct[/yellow]")
                self.console.print("[yellow]2. Password is correct[/yellow]")
                self.console.print("[yellow]3. SSH key exists and has proper permissions (600)[/yellow]")
                self.console.print("[yellow]4. SSH server allows your authentication method[/yellow]")
                self.console.print("[yellow]5. Try connecting manually with: ssh {}@{}[/yellow]".format(
                    self.ssh_config.username, self.ssh_config.host))
                raise paramiko.AuthenticationException("All authentication methods failed")
            
            # Test the connection
            self.console.print("[cyan]Testing SSH connection...[/cyan]")
            try:
                stdin, stdout, stderr = self.ssh_client.exec_command('echo "SSH connection test"', timeout=10)
                result = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                
                if result == "SSH connection test":
                    self.console.print("[green]✓ SSH connection test successful[/green]")
                else:
                    self.console.print(f"[yellow]⚠ SSH test unexpected result: {result}[/yellow]")
                    if error:
                        self.console.print(f"[yellow]SSH test error: {error}[/yellow]")
            except Exception as e:
                self.console.print(f"[yellow]⚠ SSH test command failed: {str(e)}[/yellow]")
            
            # Setup SFTP
            try:
                self.sftp_client = self.ssh_client.open_sftp()
                self.console.print("[green]✓ SFTP client established[/green]")
            except Exception as e:
                self.console.print(f"[red]✗ SFTP setup failed: {str(e)}[/red]")
                raise
                
        except Exception as e:
            self.console.print(f"[red]SSH connection failed: {str(e)}[/red]")
            if hasattr(self, 'ssh_client'):
                self.ssh_client.close()
            raise

    def _setup_database(self):
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS permission_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT,
                    timestamp REAL,
                    change_type TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    metadata TEXT
                )
            ''')
            self.conn.commit()
        except Exception as e:
            self.console.print(f"[red]Database setup failed: {str(e)}[/red]")
            raise

    def _sftp_walk(self, path):
        files = []
        folders = []
        try:
            for entry in self.sftp_client.listdir_attr(path):
                # Don't skip hidden files that start with '.' - they need monitoring too
                if self._should_ignore(entry.filename):
                    continue
                
                if stat.S_ISDIR(entry.st_mode):
                    folders.append(entry.filename)
                else:
                    files.append(entry.filename)

            yield path, folders, files

            if self.config.recursive:
                for folder in folders:
                    new_path = os.path.join(path, folder)
                    yield from self._sftp_walk(new_path)
                
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not access {path}: {e}[/yellow]")

    def _get_permission_state(self) -> Dict:
        state = {}
        try:
            if not self.config.recursive:
                # Single file/directory monitoring
                attr = self.sftp_client.stat(self.config.path)
                state[self.config.path] = self._get_file_permissions(attr)
            else:
                # Add the base directory itself first
                try:
                    base_attr = self.sftp_client.stat(self.config.path)
                    state[self.config.path] = self._get_file_permissions(base_attr)
                except Exception as e:
                    self.console.print(f"[yellow]Warning: Could not stat base path {self.config.path}: {e}[/yellow]")
                
                # Recursive directory monitoring
                for root, dirs, files in self._sftp_walk(self.config.path):
                    # Monitor directories too, not just files
                    for d in dirs:
                        try:
                            dir_path = os.path.join(root, d)
                            dir_attr = self.sftp_client.stat(dir_path)
                            state[dir_path] = self._get_file_permissions(dir_attr)
                        except Exception as e:
                            self.console.print(f"[yellow]Warning: Could not stat directory {os.path.join(root, d)}: {e}[/yellow]")
                        
                    # Then monitor files
                    for f in files:
                        if self._should_ignore(f):
                            continue
                        path = os.path.join(root, f)
                        try:
                            attr = self.sftp_client.stat(path)
                            state[path] = self._get_file_permissions(attr)
                        except Exception as e:
                            self.console.print(f"[yellow]Warning: Could not stat {path}: {e}[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error getting permission state: {e}[/red]")
        return state

    def _get_file_permissions(self, attr) -> Dict:
        mode = attr.st_mode
        return {
            'mode': stat.S_IMODE(mode),
            'uid': attr.st_uid,
            'gid': attr.st_gid,
            'mtime': attr.st_mtime,
            'is_dir': stat.S_ISDIR(mode)  # Track if it's a directory
        }

    def _should_ignore(self, path: str) -> bool:
        if not self.config.ignore_patterns:
            return False
        return any(pattern in path for pattern in self.config.ignore_patterns)

    def _detect_permission_changes(self, old_state: Dict, new_state: Dict):
        detected_changes = False
        
        for path, new_perms in new_state.items():
            if path not in old_state:
                # Log if it's a directory or file
                is_dir = new_perms.get('is_dir', False)
                entity_type = "directory" if is_dir else "file"
                self._queue_change(path, 'new_' + entity_type, None, json.dumps(new_perms))
                detected_changes = True
                self.logger.info(f"New {entity_type}: {path}")
                continue

            old_perms = old_state[path]
            
            # Check mode (chmod) changes
            if new_perms['mode'] != old_perms['mode']:
                old_mode = oct(old_perms['mode'])[2:]
                new_mode = oct(new_perms['mode'])[2:]
                self._queue_change(
                    path, 
                    'chmod',
                    old_mode,
                    new_mode
                )
                detected_changes = True
                entity_type = "Directory" if new_perms.get('is_dir', False) else "File"
                self.logger.info(f"Permission change: {entity_type} {path} (Mode: {old_mode} → {new_mode})")

            # Check ownership (chown) changes
            if new_perms['uid'] != old_perms['uid'] or new_perms['gid'] != old_perms['gid']:
                old_owner = f"{old_perms['uid']}:{old_perms['gid']}"
                new_owner = f"{new_perms['uid']}:{new_perms['gid']}"
                self._queue_change(
                    path,
                    'chown',
                    old_owner,
                    new_owner
                )
                detected_changes = True
                entity_type = "Directory" if new_perms.get('is_dir', False) else "File"
                self.logger.info(f"Ownership change: {entity_type} {path} (Owner: {old_owner} → {new_owner})")

        # Check for deleted files and directories
        for path in old_state:
            if path not in new_state:
                is_dir = old_state[path].get('is_dir', False)
                entity_type = "directory" if is_dir else "file"
                self._queue_change(path, 'deleted_' + entity_type, json.dumps(old_state[path]), None)
                detected_changes = True
                self.logger.info(f"Deleted {entity_type}: {path}")
                
        # Debug message if changes were detected (more concise)
        if detected_changes:
            self.console.print(f"[bold yellow]Permission changes detected at {datetime.now().strftime('%H:%M:%S')}[/bold yellow]")

    def _queue_change(self, path: str, change_type: str, old_value: str, new_value: str):
        try:
            # Convert any dictionary values to JSON strings before queueing
            if isinstance(old_value, dict):
                old_value = json.dumps(old_value)
            if isinstance(new_value, dict):
                new_value = json.dumps(new_value)
            
            change = {
                'path': path,
                'timestamp': time.time(),
                'change_type': change_type,
                'old_value': old_value,
                'new_value': new_value,
                'metadata': json.dumps({
                    'detected_at': datetime.now().isoformat()
                })
            }
            self.changes_queue.put(change)
        except Exception as e:
            self.console.print(f"[red]Error queueing change: {str(e)}[/red]")

    def _log_change(self, change: Dict):
        try:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Property")
            table.add_column("Value")
            
            # Simplify the table output
            time_str = datetime.fromtimestamp(change['timestamp']).strftime('%H:%M:%S')
            table.add_row("Time", time_str)
            
            # Special handling for directories vs files
            is_dir = False
            if change['change_type'] == 'new_directory' or change['change_type'] == 'deleted_directory':
                is_dir = True
            
            entity_type = "Directory" if is_dir else "File"
            table.add_row("Type", entity_type)
            table.add_row("Path", change['path'])
            
            # Format the old/new values more clearly based on change type
            if change['change_type'] == 'chmod':
                if change['old_value'] and change['new_value']:
                    table.add_row("Mode Change", f"{change['old_value']} → {change['new_value']}")
                    table.add_row("Action", "Permission modified")
            elif change['change_type'] == 'chown':
                if change['old_value'] and change['new_value']:
                    table.add_row("Owner Change", f"{change['old_value']} → {change['new_value']}")
                    table.add_row("Action", "Ownership changed")
            elif change['change_type'] == 'new_file' or change['change_type'] == 'new_directory':
                table.add_row("Action", f"Created new {entity_type.lower()}")
            elif change['change_type'] == 'deleted_file' or change['change_type'] == 'deleted_directory':
                table.add_row("Action", f"{entity_type} deleted")
            
            # Generate a concise message for the logger
            change_msg = f"Permission: {change['change_type']} on {change['path']}"
            self.logger.info(change_msg)
            
            self.console.print(f"\n[cyan]Permission Change: {change['change_type']}[/cyan]")
            self.console.print(table)
        except Exception as e:
            self.logger.error(f"Error logging change: {str(e)}")
            self.console.print(f"[red]Error logging change: {str(e)}[/red]")

    def _save_change(self, change: Dict):
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO permission_changes 
                    (path, timestamp, change_type, old_value, new_value, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    change['path'],
                    change['timestamp'],
                    change['change_type'],
                    str(change['old_value']) if change['old_value'] is not None else None,
                    str(change['new_value']) if change['new_value'] is not None else None,
                    change['metadata']
                ))
                self.conn.commit()
        except Exception as e:
            self.console.print(f"[red]Error saving change to database: {str(e)}[/red]")
            self.console.print(f"[yellow]Problematic change data: {json.dumps(change, default=str)}[/yellow]")

    def start(self):
        """Start the permission monitoring process"""
        self.console.print("[green]Starting permission monitoring...[/green]")
        
        # Get initial state
        old_state = self._get_permission_state()
        self.console.print(f"[cyan]Initial state captured: {len(old_state)} items[/cyan]")
        
        # Start the database writer thread
        db_thread = threading.Thread(target=self._database_writer, daemon=True)
        db_thread.start()
        
        try:
            while not self.stop_event.is_set():
                time.sleep(self.config.interval)
                
                # Get current state
                new_state = self._get_permission_state()
                
                # Detect changes
                self._detect_permission_changes(old_state, new_state)
                
                # Update state
                old_state = new_state
                
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Stopping monitoring...[/yellow]")
        finally:
            self.stop()

    def _database_writer(self):
       while not self.stop_event.is_set():
            try:
                change = self.changes_queue.get(timeout=1)
                self._log_change(change)
                self._save_change(change)
            
                # ✅ اضافه کردن ارسال به Redis
                if hasattr(self, 'redis') and self.redis:
                    self.redis.add_to_queue("perm_changes", change)

            except queue.Empty:
                continue
            except Exception as e:
                self.console.print(f"[red]Database writer error: {str(e)}[/red]")
           
            except queue.Empty:
                continue
            except Exception as e:
                self.console.print(f"[red]Database writer error: {str(e)}[/red]")

    def stop(self):
        self.stop_event.set()
        if hasattr(self, 'sftp_client'):
            self.sftp_client.close()
        if hasattr(self, 'ssh_client'):
            self.ssh_client.close()
        if hasattr(self, 'conn'):
            self.conn.close()
        self.console.print("[green][+] Monitoring stopped[/green]")
        self.console.print("[green][+] Connections closed[/green]")

def get_user_input() -> Tuple[SSHConfig, MonitorConfig]:
    console = Console()
    console.print("\n[bold cyan]SSH Connection Configuration[/bold cyan]")
    
    host = Prompt.ask("Enter SSH host (e.g., server.example.com)")
    port = int(Prompt.ask("Enter SSH port", default="22"))
    username = Prompt.ask("Enter SSH username")
    
    auth_method = Prompt.ask(
        "Choose authentication method",
        choices=["password", "key"],
        default="key"
    )
    
    password = None
    key_path = None
    
    if auth_method == "password":
        password = getpass.getpass("Enter SSH password: ")
    else:
        default_key_path = os.path.expanduser("~/.ssh/id_rsa")
        key_path = Prompt.ask(
            "Enter path to SSH private key",
            default=default_key_path
        )
    
    console.print("\n[bold cyan]Monitoring Configuration[/bold cyan]")
    
    path = Prompt.ask("Enter path to monitor")
    interval = int(Prompt.ask("Enter monitoring interval in seconds", default="1"))
    recursive = Confirm.ask("Monitor recursively?", default=True)
    
    ignore_patterns = []
    if Confirm.ask("Do you want to specify ignore patterns?", default=True):
        console.print("Enter patterns to ignore (one per line, empty line to finish):")
        while True:
            pattern = input().strip()
            if not pattern:
                break
            ignore_patterns.append(pattern)

    if not ignore_patterns:
        ignore_patterns = [".git", "__pycache__", ".env"]

    ssh_config = SSHConfig(
        host=host,
        port=port,
        username=username,
        password=password,
        key_path=key_path
    )

    monitor_config = MonitorConfig(
        path=path,
        interval=interval,
        recursive=recursive,
        ignore_patterns=ignore_patterns
    )

    return ssh_config, monitor_config

def main():
    console = Console()

    try:
        console.print("\n[bold green]File Permission Monitor[/bold green]")
        console.print("This script monitors file permission changes on a remote system via SSH.")

        ssh_config, monitor_config = get_user_input()

        console.print("\n[bold cyan]Configuration Summary:[/bold cyan]")

        table = Table(show_header=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("SSH Host", ssh_config.host)
        table.add_row("SSH Port", str(ssh_config.port))
        table.add_row("SSH Username", ssh_config.username)
        table.add_row("Auth Method", "Password" if ssh_config.password else "Key")
        table.add_row("Monitor Path", monitor_config.path)
        table.add_row("Interval", f"{monitor_config.interval} seconds")
        table.add_row("Recursive", str(monitor_config.recursive))
        table.add_row("Ignore Patterns", ", ".join(monitor_config.ignore_patterns))

        console.print(table)

        if not Confirm.ask("\nStart monitoring with these settings?", default=True):
            console.print("[yellow]Monitoring cancelled by user[/yellow]")
            return

        # Create a unique database name based on host and monitored path
        db_name = f"permission_changes_{ssh_config.host}-{ssh_config.port}-{monitor_config.path.replace('/', '-')}.db"

        monitor = PermissionMonitor(ssh_config, monitor_config, db_name)
        monitor.start()

    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring cancelled by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        raise

if __name__ == "__main__":
    main()
