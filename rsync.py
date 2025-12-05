# rsync.py
import subprocess
import time
import os
from rich.console import Console

console = Console()

class RsyncBackup:
    def __init__(self, ssh_config, source, backup_path):
        self.ssh_config = ssh_config
        self.source = source
        self.backup_path = backup_path
        self.console = console
        
    def create_backup(self):
        """Create initial backup using rsync"""
        try:
            # Create backup directory if it doesn't exist
            os.makedirs(self.backup_path, exist_ok=True)
            
            # Build rsync command
            cmd = [
                'rsync',
                '-avz',
                '--delete',
                f"{self.ssh_config['username']}@{self.ssh_config['host']}:{self.source}/",
                f"{self.backup_path}/"
            ]
            
            # Add SSH options if key is provided
            if self.ssh_config.get('key_path'):
                cmd.insert(1, f"-e ssh -i {self.ssh_config['key_path']} -p {self.ssh_config['port']}")
            else:
                cmd.insert(1, f"-e ssh -p {self.ssh_config['port']}")
            
            self.console.print(f"[cyan]Creating backup: {' '.join(cmd)}[/cyan]")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.console.print("[green]✓ Backup created successfully[/green]")
                return True
            else:
                self.console.print(f"[red]✗ Backup failed: {result.stderr}[/red]")
                return False
                
        except Exception as e:
            self.console.print(f"[red]✗ Backup error: {str(e)}[/red]")
            return False
    
    def restore_from_backup(self):
        """Restore files from backup to remote server"""
        try:
            # Build rsync command for restore
            cmd = [
                'rsync',
                '-avz',
                '--delete',
                f"{self.backup_path}/",
                f"{self.ssh_config['username']}@{self.ssh_config['host']}:{self.source}/"
            ]
            
            # Add SSH options if key is provided
            if self.ssh_config.get('key_path'):
                cmd.insert(1, f"-e ssh -i {self.ssh_config['key_path']} -p {self.ssh_config['port']}")
            else:
                cmd.insert(1, f"-e ssh -p {self.ssh_config['port']}")
            
            self.console.print(f"[yellow]Restoring from backup...[/yellow]")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.console.print("[green]✓ Restore completed successfully[/green]")
                return True
            else:
                self.console.print(f"[red]✗ Restore failed: {result.stderr}[/red]")
                return False
                
        except Exception as e:
            self.console.print(f"[red]✗ Restore error: {str(e)}[/red]")
            return False
    
    def run_restore_loop(self, stop_event, interval=5):
        """Run continuous restore loop"""
        self.console.print("[cyan]Starting restore loop...[/cyan]")
        
        # Create initial backup
        if not self.create_backup():
            self.console.print("[red]✗ Failed to create initial backup[/red]")
            return
        
        while not stop_event.is_set():
            try:
                time.sleep(interval)
                if not stop_event.is_set():
                    self.restore_from_backup()
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.console.print(f"[red]✗ Restore loop error: {str(e)}[/red]")
                time.sleep(interval)


class RsyncBackupProtect(RsyncBackup):
    """Extended version with protection features"""
    
    def initial_backup(self):
        """Create initial backup"""
        return self.create_backup()
    
    def protect_loop(self, interval=5):
        """Protection loop that continuously restores"""
        self.console.print("[cyan]Starting protection loop...[/cyan]")
        
        while True:
            try:
                time.sleep(interval)
                self.restore_from_backup()
            except KeyboardInterrupt:
                self.console.print("[yellow]Protection loop stopped[/yellow]")
                break
            except Exception as e:
                self.console.print(f"[red]✗ Protection loop error: {str(e)}[/red]")
                time.sleep(interval)
