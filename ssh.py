import paramiko
import time
import os
import json
import logging
from datetime import datetime
import threading
import queue
from dataclasses import dataclass
from typing import List, Optional
import sqlite3
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
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

class FileOperationsMonitor:
    def __init__(self, ssh_config: SSHConfig, monitor_config: MonitorConfig, db_path: str = None):
        self.ssh_config = ssh_config
        self.config = monitor_config
        
        # Generate dynamic database filename if not provided
        if db_path is None:
            # Replace non-alphanumeric characters with hyphens
            safe_host = ''.join(c if c.isalnum() else '-' for c in ssh_config.host)
            safe_path = ''.join(c if c.isalnum() or c in '.-' else '-' for c in monitor_config.path)
            db_name = f"{safe_host}-{ssh_config.port}-{safe_path}.db"
            db_path = os.path.join(os.getcwd(), db_name)
        
        self.db_path = db_path
        self.stop_event = threading.Event()
        self.changes_queue = queue.Queue()
        self.console = Console()
        self.db_lock = threading.Lock()  # Add a mutex lock for database operations
        
        # Configure logger with minimal format
        self.logger = logging.getLogger(f"FileOps-{ssh_config.host}")
        self.logger.propagate = False  # Prevent duplicate messages
        
        # Add a custom formatter to hide path information
        for handler in logging.root.handlers:
            if isinstance(handler, logging.FileHandler):
                handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
        
        self._setup_ssh()
        self._setup_database()
        
        # Additional initialization to track external file operations
        self.monitored_path = monitor_config.path
        # Keep track of previously seen paths to detect operations with external paths
        self.previous_known_paths = set()
    def _setup_ssh(self):
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.ssh_config.host,
                'port': self.ssh_config.port,
                'username': self.ssh_config.username
            }
            
            if self.ssh_config.password:
                connect_kwargs['password'] = self.ssh_config.password
            if self.ssh_config.key_path:
                connect_kwargs['key_filename'] = os.path.expanduser(self.ssh_config.key_path)

            self.ssh_client.connect(**connect_kwargs)
            self.sftp_client = self.ssh_client.open_sftp()
        except Exception as e:
            self.console.print(f"[red]SSH connection failed: {str(e)}[/red]")
            raise

    def _setup_database(self):
        try:
            # Set check_same_thread=False to allow the connection to be used across threads
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    operation TEXT,
                    src_path TEXT,
                    dst_path TEXT,
                    details TEXT
                )
            ''')
            self.conn.commit()
        except Exception as e:
            self.console.print(f"[red]Database setup failed: {str(e)}[/red]")
            raise

    def _get_file_list(self) -> dict:
        state = {}
        try:
            if not self.config.recursive:
                entries = self.sftp_client.listdir_attr(self.config.path)
                for entry in entries:
                    if not self._should_ignore(entry.filename):
                        path = os.path.join(self.config.path, entry.filename)
                        is_dir = entry.st_mode & 0o170000 == 0o040000
                        state[path] = {
                            'mtime': entry.st_mtime, 
                            'size': entry.st_size,
                            'is_dir': is_dir
                        }
            else:
                # Add the base directory itself
                try:
                    base_attr = self.sftp_client.stat(self.config.path)
                    state[self.config.path] = {
                        'mtime': base_attr.st_mtime,
                        'size': base_attr.st_size,
                        'is_dir': True
                    }
                except Exception as e:
                    self.logger.warning(f"Could not stat base path {self.config.path}: {e}")
                    
                # Then walk through all directories and files
                for root, dirs, files in self._sftp_walk(self.config.path):
                    # Add directories to the state
                    for d in dirs:
                        if not self._should_ignore(d):
                            path = os.path.join(root, d)
                            try:
                                attr = self.sftp_client.stat(path)
                                state[path] = {
                                    'mtime': attr.st_mtime, 
                                    'size': attr.st_size,
                                    'is_dir': True
                                }
                            except Exception as e:
                                self.logger.warning(f"Could not stat directory {path}: {e}")
                    
                    # Add files to the state
                    for f in files:
                        if not self._should_ignore(f):
                            path = os.path.join(root, f)
                            try:
                                attr = self.sftp_client.stat(path)
                                state[path] = {
                                    'mtime': attr.st_mtime, 
                                    'size': attr.st_size,
                                    'is_dir': False
                                }
                            except Exception as e:
                                self.logger.warning(f"Could not stat file {path}: {e}")
        except Exception as e:
            self.console.print(f"[red]Error getting file list: {str(e)}[/red]")
        return state

    def _should_ignore(self, path: str) -> bool:
        if not self.config.ignore_patterns:
            return False
        return any(pattern in path for pattern in self.config.ignore_patterns)

    def _sftp_walk(self, path):
        files = []
        folders = []
        try:
            for entry in self.sftp_client.listdir_attr(path):
                if entry.filename.startswith('.') and entry.filename != '.':
                    continue
                if self._should_ignore(entry.filename):
                    continue
                    
                if entry.st_mode & 0o170000 == 0o040000:  # Directory
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

    def _detect_changes(self, old_files: dict, new_files: dict):
        detected_changes = False
        created_files = []
        created_dirs = []  # Track created directories separately
        deleted_files = []
        deleted_dirs = []  # Track deleted directories separately
        
        # Track external paths - will attempt to find them
        self.external_paths_cache = getattr(self, 'external_paths_cache', {})
        
        # First pass: Identify created and deleted items
        for path in new_files:
            if path not in old_files:
                if new_files[path].get('is_dir', False):
                    created_dirs.append(path)
                else:
                    created_files.append(path)
            
        for path in old_files:
            if path not in new_files:
                if old_files[path].get('is_dir', False):
                    deleted_dirs.append(path)
                else:
                    deleted_files.append(path)
        
        # Track current paths for future comparison
        current_paths = set(new_files.keys())
        
        # Try to detect the external location for files that appear
        for path in created_files:
            # Look for matching files that were recently deleted from outside our view
            matching_external = None
            if hasattr(self, 'last_external_check_time'):
                # Check if the file was recently moved from outside
                try:
                    # Execute 'find' command to look for recently modified files with same size
                    file_size = new_files[path]['size']
                    cmd = f"find /home /var/www /opt -type f -size {file_size}c -mtime -1 2>/dev/null | head -5"
                    _, stdout, _ = self.ssh_client.exec_command(cmd)
                    potential_sources = stdout.read().decode().strip().split('\n')
                    
                    # Filter out empty results and paths within our monitored directory
                    potential_sources = [p for p in potential_sources if p and self.config.path not in p]
                    
                    if potential_sources:
                        matching_external = potential_sources[0]  # Take the first potential match
                        self.external_paths_cache[path] = matching_external
                except Exception as e:
                    self.logger.debug(f"Error looking for external source: {e}")
        
        # Second pass: Try to identify moves and copies
        potential_moves = {}
        potential_copies = {}
        
        # Look for potential move operations (deleted + created with same size)
        for deleted_path in deleted_files:
            deleted_size = old_files[deleted_path]['size']
            deleted_mtime = old_files[deleted_path]['mtime']
            
            for created_path in created_files:
                created_size = new_files[created_path]['size']
                
                # If sizes match, it could be a move operation
                if created_size == deleted_size:
                    # Store as potential move
                    if deleted_path not in potential_moves:
                        potential_moves[deleted_path] = []
                    potential_moves[deleted_path].append(created_path)
        
        # Process directory operations first
        for created_dir in created_dirs:
            self._log_operation('CREATE_DIR', created_dir, details={
                'is_directory': True,
                'creation_time': new_files[created_dir]['mtime']
            })
            detected_changes = True
            self.logger.info(f"Directory created: {created_dir}")
        
        for deleted_dir in deleted_dirs:
            external_location = self.external_paths_cache.get(deleted_dir, "Unknown location")
            self._log_operation('DELETE_DIR', deleted_dir, dst_path=external_location, details={
                'is_directory': True,
                'deletion_time': time.time()
            })
            detected_changes = True
            self.logger.info(f"Directory deleted: {deleted_dir}")
        
        # Process move operations for files
        processed_created = set()
        processed_deleted = set()
        
        for source_path, dest_paths in potential_moves.items():
            for dest_path in dest_paths:
                self._log_operation('MOVE', source_path, dst_path=dest_path, details={
                    'source_size': old_files[source_path]['size'],
                    'source_mtime': old_files[source_path]['mtime']
                })
                detected_changes = True
                processed_created.add(dest_path)
                processed_deleted.add(source_path)
                # Use more concise logging
                self.logger.info(f"Move: {source_path} → {dest_path}")
        
        # Process copy operations
        for source_path, dest_paths in potential_copies.items():
            for dest_path in dest_paths:
                if dest_path not in processed_created:  # Only process if not already identified as a move
                    self._log_operation('COPY', source_path, dst_path=dest_path, details={
                        'source_size': old_files[source_path]['size'],
                        'source_mtime': old_files[source_path]['mtime']
                    })
                    detected_changes = True
                    processed_created.add(dest_path)
                    # Use more concise logging
                    self.logger.info(f"Copy: {source_path} → {dest_path}")
        
        # Process potentially external moves (files that appeared but have no source)
        for path in created_files:
            if path not in processed_created:
                # Check if we found a potential external source
                external_source = self.external_paths_cache.get(path, "Unknown location")
                
                self._log_operation('EXTERNAL_MOVE', external_source, dst_path=path, details={
                    'destination_size': new_files[path]['size'],
                    'destination_mtime': new_files[path]['mtime'],
                    'note': 'File appears to have been moved from outside the monitored path'
                })
                detected_changes = True
                processed_created.add(path)
                self.logger.info(f"External move: {external_source} → {path}")
        
        # Process remaining created files that weren't identified as moves or copies
        for path in created_files:
            if path not in processed_created:
                self._log_operation('CREATE', path)
                detected_changes = True
                self.logger.info(f"Created: {path}")

        # Check for files that may have been moved outside the monitored path
        for path in deleted_files:
            if path not in processed_deleted:
                # Try to find where it might have gone
                external_dest = "Unknown location"
                
                try:
                    # Use the find command to see if we can locate the file elsewhere
                    filename = os.path.basename(path)
                    cmd = f"find /home /var/www /opt -name '{filename}' -type f -mtime -1 2>/dev/null | grep -v '{self.config.path}' | head -1"
                    _, stdout, _ = self.ssh_client.exec_command(cmd)
                    potential_dest = stdout.read().decode().strip()
                    
                    if potential_dest:
                        # Verify the file exists and has similar size
                        try:
                            remote_stat = self.ssh_client.exec_command(f"stat -c '%s' '{potential_dest}' 2>/dev/null")[1].read().decode().strip()
                            if remote_stat and int(remote_stat) == old_files[path]['size']:
                                external_dest = potential_dest
                                self.external_paths_cache[path] = external_dest
                        except Exception:
                            pass
                except Exception as e:
                    self.logger.debug(f"Error finding external destination: {e}")
                
                self._log_operation('EXTERNAL_DELETE', path, dst_path=external_dest, details={
                    'old_size': old_files[path]['size'],
                    'old_mtime': old_files[path]['mtime'],
                    'note': 'File may have been moved outside the monitored path'
                })
                self.logger.info(f"External move/delete: {path} → {external_dest}")
                detected_changes = True

        # Detect modified files
        for path in new_files:
            if path in old_files and path not in processed_created and not old_files[path].get('is_dir', False):
                old_info = old_files[path]
                new_info = new_files[path]
                
                if new_info['mtime'] != old_info['mtime']:
                    # If size changed, it's a modification
                    if new_info['size'] != old_info['size']:
                        self._log_operation('MODIFY', path, details={
                            'old_size': old_info['size'],
                            'new_size': new_info['size'],
                            'old_mtime': old_info['mtime'],
                            'new_mtime': new_info['mtime']
                        })
                        detected_changes = True
                        self.logger.info(f"Modified: {path} (Size: {old_info['size']} → {new_info['size']})")
        
        # Update known paths for next comparison
        self.previous_known_paths = current_paths
        self.last_external_check_time = time.time()
        
        # Debug message if changes were detected (make it more concise)
        if detected_changes:
            self.console.print(f"[bold yellow]Changes detected at {datetime.now().strftime('%H:%M:%S')}[/bold yellow]")

    def _log_operation(self, operation: str, src_path: str, dst_path: str = None, details: dict = None):
        try:
            record = {
                'timestamp': time.time(),
                'operation': operation,
                'src_path': src_path,
                'dst_path': dst_path,
                'details': json.dumps(details) if details else None
            }
            
            # Save to database with thread lock
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO file_operations 
                    (timestamp, operation, src_path, dst_path, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    record['timestamp'],
                    record['operation'],
                    record['src_path'],
                    record['dst_path'],
                    record['details']
                ))
                self.conn.commit()

            # Generate a descriptive message based on operation type
            message_parts = []
            if operation == 'COPY':
                message_parts.append(f"File copied from {src_path} to {dst_path}")
                if details:
                    message_parts.append(f"Size: {details.get('source_size', 'unknown')}")
            elif operation == 'MOVE':
                message_parts.append(f"File moved from {src_path} to {dst_path}")
                if details:
                    message_parts.append(f"Size: {details.get('source_size', 'unknown')}")
            elif operation == 'EXTERNAL_MOVE':
                message_parts.append(f"File moved from {src_path} to {dst_path}")
            elif operation == 'EXTERNAL_DELETE':
                message_parts.append(f"File moved/deleted from {src_path} to {dst_path}")
            elif operation == 'CREATE':
                message_parts.append(f"New file created: {src_path}")
            elif operation == 'CREATE_DIR':
                message_parts.append(f"New directory created: {src_path}")
            elif operation == 'DELETE':
                message_parts.append(f"File deleted: {src_path}")
                if details:
                    message_parts.append(f"Previous size: {details.get('old_size', 'unknown')}")
            elif operation == 'DELETE_DIR':
                message_parts.append(f"Directory deleted: {src_path}")
            elif operation == 'MODIFY':
                message_parts.append(f"File modified: {src_path}")
                if details:
                    old_size = details.get('old_size', 'unknown')
                    new_size = details.get('new_size', 'unknown')
                    message_parts.append(f"Size changed: {old_size} → {new_size}")
            
            # Print to console
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Property")
            table.add_column("Value")
            
            time_str = datetime.fromtimestamp(record['timestamp']).strftime('%H:%M:%S')
            table.add_row("Time", time_str)
            table.add_row("Operation", operation)
            
            if operation in ['COPY', 'MOVE']:
                table.add_row("Source Path", src_path)
                table.add_row("Destination Path", dst_path)
            elif operation == 'EXTERNAL_MOVE':
                table.add_row("Source Path", src_path)
                table.add_row("Destination Path", dst_path)
            elif operation == 'EXTERNAL_DELETE':
                table.add_row("Source Path", src_path)
                table.add_row("Destination Path", dst_path)
            elif operation in ['CREATE_DIR', 'DELETE_DIR']:
                table.add_row("Directory", src_path)
            else:
                table.add_row("Path", src_path)
                
            if dst_path and operation not in ['COPY', 'MOVE', 'EXTERNAL_MOVE', 'EXTERNAL_DELETE']:
                table.add_row("Destination Path", dst_path)
                
            if details:
                # Add formatted details based on operation type
                if details.get('is_directory'):
                    table.add_row("Type", "Directory")
                
                if operation == 'MODIFY':
                    if 'old_size' in details and 'new_size' in details:
                        table.add_row("Size Change", f"{details['old_size']} → {details['new_size']}")
                elif operation == 'DELETE' and 'old_size' in details:
                    table.add_row("Previous Size", str(details['old_size']))
                elif operation in ['COPY', 'MOVE'] and 'source_size' in details:
                    table.add_row("Size", str(details['source_size']))
                elif 'note' in details:
                    table.add_row("Note", details['note'])
                else:
                    # Only include details if they exist and are meaningful
                    if any(k for k in details.keys() if k not in ['source_mtime', 'old_mtime', 'new_mtime', 'is_directory']):
                        simple_details = {k: v for k, v in details.items() 
                                         if k not in ['source_mtime', 'old_mtime', 'new_mtime', 'is_directory']}
                        table.add_row("Details", json.dumps(simple_details))

            self.console.print(f"\n[cyan]File Operation: {operation}[/cyan]")
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error logging operation: {str(e)}[/red]")

    def start(self):
        self.console.print(f"[green][+] Started monitoring file operations on {self.config.path}[/green]")
        self.console.print(f"[green][+] Connected to {self.ssh_config.host}[/green]")
        
        last_files = {}
        
        try:
            while not self.stop_event.is_set():
                try:
                    current_files = self._get_file_list()
                    self._detect_changes(last_files, current_files)
                    last_files = current_files
                    time.sleep(self.config.interval)
                except Exception as e:
                    self.console.print(f"[red]Error in monitoring loop: {e}[/red]")
                    time.sleep(5)
        except KeyboardInterrupt:
            self.console.print("\n[yellow][+] Received keyboard interrupt[/yellow]")
        finally:
            self.stop()

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

def main():
    console = Console()
    try:
        console.print("\n[bold green]File Operations Monitor[/bold green]")
        console.print("This script monitors file operations (create, delete, modify, copy/move) on a remote system via SSH.")

        # Get SSH configuration
        console.print("\n[bold cyan]SSH Configuration[/bold cyan]")
        host = Prompt.ask("Enter SSH host")
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
            key_path = Prompt.ask(
                "Enter path to SSH private key",
                default=os.path.expanduser("~/.ssh/id_rsa")
            )

        # Get monitoring configuration
        console.print("\n[bold cyan]Monitoring Configuration[/bold cyan]")
        path = Prompt.ask("Enter path to monitor")
        interval = int(Prompt.ask("Enter monitoring interval in seconds", default="1"))
        recursive = Confirm.ask("Monitor recursively?", default=True)

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
            ignore_patterns=[".git", "__pycache__", ".env"]
        )

        # Create monitor and start
        monitor = FileOperationsMonitor(ssh_config, monitor_config)
        monitor.start()

    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring cancelled by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        raise

if __name__ == "__main__":
    main()
