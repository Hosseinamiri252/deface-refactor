#!/usr/bin/env python3
"""
FastAPI Backend for Anti-Defacement Dashboard
استفاده: uvicorn api:app --reload --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import sqlite3
import json
import os
from pathlib import Path

# Import modules from your existing project
try:
    from permission_monitoring import PermissionMonitor, SSHConfig as PermSSHConfig, MonitorConfig as PermMonitorConfig
    from ssh import FileOperationsMonitor, SSHConfig as FileSSHConfig, MonitorConfig as FileMonitorConfig
    from red import RedisConfig
except ImportError as e:
    print(f"Warning: Could not import some modules: {e}")

app = FastAPI(title="Anti-Defacement API", version="1.0.0")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # در پروداکشن، دامنه‌های مشخص را اضافه کنید
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== Models ====================

class ServerCreate(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None
    path: str
    mode: str = "passive"  # passive or active
    backup_path: Optional[str] = None
    interval: int = 1

class ServerResponse(BaseModel):
    id: int
    name: str
    host: str
    port: int
    path: str
    mode: str
    status: str
    changes: int
    alerts: int

class AlertConfigUpdate(BaseModel):
    telegram_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    smtp_server: Optional[str] = None
    smtp_port: Optional[int] = None
    email_from: Optional[str] = None
    email_to: Optional[str] = None
    critical_threshold: str = "immediate"
    warning_threshold: str = "after_3"

class GeneralSettingsUpdate(BaseModel):
    monitoring_interval: int = 1
    default_mode: str = "active"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: Optional[str] = None
    redis_enabled: bool = False
    log_retention_days: int = 30
    log_level: str = "INFO"

# ==================== Database Helper ====================

class DatabaseManager:
    def __init__(self, db_path: str = "antidefacement.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Servers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                username TEXT NOT NULL,
                password TEXT,
                key_path TEXT,
                path TEXT NOT NULL,
                mode TEXT DEFAULT 'passive',
                backup_path TEXT,
                interval INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Statistics cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stats_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stat_key TEXT UNIQUE NOT NULL,
                stat_value INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def execute_query(self, query: str, params: tuple = (), fetch: bool = False):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        
        if fetch:
            result = cursor.fetchall()
            conn.close()
            return result
        else:
            conn.commit()
            last_id = cursor.lastrowid
            conn.close()
            return last_id

db_manager = DatabaseManager()

# ==================== Helper Functions ====================

def get_server_databases(server_id: int):
    """Get database paths for a specific server"""
    conn = db_manager.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT host, port, path FROM servers WHERE id = ?", (server_id,))
    server = cursor.fetchone()
    conn.close()
    
    if not server:
        return None, None
    
    host, port, path = server
    safe_host = ''.join(c if c.isalnum() else '-' for c in host)
    safe_path = ''.join(c if c.isalnum() or c in '.-' else '-' for c in path)
    
    perm_db = f"logs_{host}_{port}_{path.replace('/', '_')}/permission_changes.db"
    file_db = f"logs_{host}_{port}_{path.replace('/', '_')}/file_operations.db"
    
    return perm_db, file_db

def count_records_in_db(db_path: str, table_name: str, time_filter: str = None) -> int:
    """Count records in a database table"""
    if not os.path.exists(db_path):
        return 0
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        if time_filter:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE timestamp > ?", (time_filter,))
        else:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        print(f"Error counting records: {e}")
        return 0

# ==================== API Endpoints ====================

@app.get("/")
async def root():
    return {
        "message": "Anti-Defacement API",
        "version": "1.0.0",
        "docs": "/docs"
    }

# ========== Dashboard Endpoints ==========

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Get total servers
        total_servers = db_manager.execute_query(
            "SELECT COUNT(*) FROM servers WHERE status = 'active'", 
            fetch=True
        )[0][0]
        
        # Active monitors = total servers * 3 (perm + file + restore)
        active_monitors = total_servers * 3 if total_servers > 0 else 0
        
        # Calculate alerts today
        today_start = datetime.now().replace(hour=0, minute=0, second=0).timestamp()
        alerts_today = 0
        
        # Get all servers and count their alerts
        servers = db_manager.execute_query("SELECT id FROM servers WHERE status = 'active'", fetch=True)
        for (server_id,) in servers:
            perm_db, file_db = get_server_databases(server_id)
            if perm_db:
                alerts_today += count_records_in_db(perm_db, "permission_changes", today_start)
            if file_db:
                alerts_today += count_records_in_db(file_db, "file_operations", today_start)
        
        # Calculate restored files (mock for now)
        restored_files = alerts_today // 2 if alerts_today > 0 else 0
        
        return {
            "totalServers": total_servers,
            "activeMonitors": active_monitors,
            "alertsToday": alerts_today,
            "restoredFiles": restored_files
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== Servers Endpoints ==========

@app.get("/api/servers")
async def get_servers():
    """Get all servers"""
    try:
        servers = db_manager.execute_query(
            "SELECT id, name, host, port, path, mode, status FROM servers",
            fetch=True
        )
        
        result = []
        for server in servers:
            server_id, name, host, port, path, mode, status = server
            
            # Count changes and alerts
            perm_db, file_db = get_server_databases(server_id)
            changes = 0
            alerts = 0
            
            if perm_db:
                changes += count_records_in_db(perm_db, "permission_changes")
                alerts += count_records_in_db(perm_db, "permission_changes")
            if file_db:
                changes += count_records_in_db(file_db, "file_operations")
                alerts += count_records_in_db(file_db, "file_operations")
            
            result.append({
                "id": server_id,
                "name": name,
                "host": host,
                "ip": f"{host}:{port}",
                "port": port,
                "path": path,
                "mode": mode,
                "status": status,
                "changes": changes,
                "alerts": alerts
            })
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/servers")
async def add_server(server: ServerCreate, background_tasks: BackgroundTasks):
    """Add a new server"""
    try:
        server_id = db_manager.execute_query(
            """
            INSERT INTO servers (name, host, port, username, password, key_path, path, mode, backup_path, interval)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (server.name, server.host, server.port, server.username, server.password, 
             server.key_path, server.path, server.mode, server.backup_path, server.interval)
        )
        
        # Start monitoring in background
        # background_tasks.add_task(start_monitoring_for_server, server_id)
        
        return {
            "id": server_id,
            "message": "Server added successfully",
            "server": server.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/servers/{server_id}")
async def delete_server(server_id: int):
    """Delete a server"""
    try:
        db_manager.execute_query("DELETE FROM servers WHERE id = ?", (server_id,))
        return {"message": f"Server {server_id} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/servers/{server_id}")
async def get_server(server_id: int):
    """Get server details"""
    try:
        server = db_manager.execute_query(
            "SELECT * FROM servers WHERE id = ?",
            (server_id,),
            fetch=True
        )
        
        if not server:
            raise HTTPException(status_code=404, detail="Server not found")
        
        return {
            "id": server[0][0],
            "name": server[0][1],
            "host": server[0][2],
            "port": server[0][3],
            "path": server[0][6]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== Activity Endpoints ==========

@app.get("/api/activity")
async def get_activity(limit: int = 50):
    """Get recent activity from all servers"""
    try:
        activities = []
        
        # Get all servers
        servers = db_manager.execute_query(
            "SELECT id, name, host FROM servers WHERE status = 'active'",
            fetch=True
        )
        
        for server_id, server_name, host in servers:
            perm_db, file_db = get_server_databases(server_id)
            
            # Get permission changes
            if perm_db and os.path.exists(perm_db):
                conn = sqlite3.connect(perm_db)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT timestamp, change_type, path, old_value, new_value FROM permission_changes ORDER BY timestamp DESC LIMIT ?",
                    (limit // 2,)
                )
                for row in cursor.fetchall():
                    activities.append({
                        "timestamp": row[0],
                        "server": server_name,
                        "type": "permission",
                        "change_type": row[1],
                        "path": row[2],
                        "details": f"{row[3]} → {row[4]}"
                    })
                conn.close()
            
            # Get file operations
            if file_db and os.path.exists(file_db):
                conn = sqlite3.connect(file_db)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT timestamp, operation, src_path, dst_path FROM file_operations ORDER BY timestamp DESC LIMIT ?",
                    (limit // 2,)
                )
                for row in cursor.fetchall():
                    activities.append({
                        "timestamp": row[0],
                        "server": server_name,
                        "type": "file",
                        "operation": row[1],
                        "src_path": row[2],
                        "dst_path": row[3]
                    })
                conn.close()
        
        # Sort by timestamp and limit
        activities.sort(key=lambda x: x["timestamp"], reverse=True)
        return activities[:limit]
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== Alerts Endpoints ==========

@app.get("/api/alerts")
async def get_alerts(filter: str = "all"):
    """Get alerts with optional filtering"""
    try:
        activities = await get_activity(limit=100)
        
        # Mock alert data from activities
        alerts = []
        for activity in activities[:20]:
            severity = "critical" if activity.get("type") == "permission" else "warning"
            
            alerts.append({
                "time": datetime.fromtimestamp(activity["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
                "server": activity["server"],
                "type": activity.get("change_type") or activity.get("operation"),
                "severity": severity,
                "path": activity.get("path") or activity.get("src_path")
            })
        
        if filter != "all":
            alerts = [a for a in alerts if a["severity"] == filter]
        
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== File Changes Endpoints ==========

@app.get("/api/files")
async def get_file_changes(server_id: Optional[int] = None):
    """Get file changes"""
    try:
        file_changes = []
        
        if server_id:
            servers = [(server_id,)]
        else:
            servers = db_manager.execute_query("SELECT id FROM servers WHERE status = 'active'", fetch=True)
        
        for (sid,) in servers:
            _, file_db = get_server_databases(sid)
            
            if file_db and os.path.exists(file_db):
                conn = sqlite3.connect(file_db)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT timestamp, operation, src_path, dst_path, details FROM file_operations ORDER BY timestamp DESC LIMIT 50"
                )
                
                server_info = db_manager.execute_query("SELECT name FROM servers WHERE id = ?", (sid,), fetch=True)
                server_name = server_info[0][0] if server_info else f"Server-{sid}"
                
                for row in cursor.fetchall():
                    file_changes.append({
                        "timestamp": datetime.fromtimestamp(row[0]).strftime("%H:%M:%S"),
                        "server": server_name,
                        "operation": row[1],
                        "src_path": row[2],
                        "dst_path": row[3],
                        "details": row[4]
                    })
                conn.close()
        
        return file_changes
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== Permission Changes Endpoints ==========

@app.get("/api/permissions")
async def get_permission_changes(server_id: Optional[int] = None):
    """Get permission changes"""
    try:
        perm_changes = []
        
        if server_id:
            servers = [(server_id,)]
        else:
            servers = db_manager.execute_query("SELECT id FROM servers WHERE status = 'active'", fetch=True)
        
        for (sid,) in servers:
            perm_db, _ = get_server_databases(sid)
            
            if perm_db and os.path.exists(perm_db):
                conn = sqlite3.connect(perm_db)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT timestamp, change_type, path, old_value, new_value FROM permission_changes ORDER BY timestamp DESC LIMIT 50"
                )
                
                server_info = db_manager.execute_query("SELECT name FROM servers WHERE id = ?", (sid,), fetch=True)
                server_name = server_info[0][0] if server_info else f"Server-{sid}"
                
                for row in cursor.fetchall():
                    perm_changes.append({
                        "timestamp": datetime.fromtimestamp(row[0]).strftime("%H:%M:%S"),
                        "server": server_name,
                        "change_type": row[1],
                        "path": row[2],
                        "old_value": row[3],
                        "new_value": row[4]
                    })
                conn.close()
        
        return perm_changes
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== Backups Endpoints ==========

@app.get("/api/backups")
async def get_backups():
    """Get backup information for all servers"""
    try:
        servers = db_manager.execute_query(
            "SELECT id, name, backup_path FROM servers WHERE status = 'active'",
            fetch=True
        )
        
        backups = []
        for server_id, name, backup_path in servers:
            if backup_path and os.path.exists(backup_path):
                # Calculate backup size
                total_size = sum(
                    os.path.getsize(os.path.join(dirpath, filename))
                    for dirpath, dirnames, filenames in os.walk(backup_path)
                    for filename in filenames
                )
                
                # Count files
                file_count = sum(
                    len(filenames)
                    for _, _, filenames in os.walk(backup_path)
                )
                
                backups.append({
                    "id": server_id,
                    "server": name,
                    "backup_path": backup_path,
                    "last_backup": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "size": f"{total_size / (1024 * 1024):.1f} MB",
                    "files": file_count
                })
        
        return backups
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/backups")
async def create_backup(server_id: int):
    """Create a new backup for a server"""
    try:
        # Implement backup creation logic
        return {"message": f"Backup created for server {server_id}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/backups/{backup_id}/restore")
async def restore_backup(backup_id: int):
    """Restore from backup"""
    try:
        # Implement restore logic
        return {"message": f"Restore initiated for backup {backup_id}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== Settings Endpoints ==========

@app.get("/api/settings/alerts")
async def get_alert_config():
    """Get alert configuration"""
    try:
        settings = {}
        results = db_manager.execute_query(
            "SELECT key, value FROM settings WHERE key LIKE 'alert_%'",
            fetch=True
        )
        for key, value in results:
            settings[key] = value
        return settings
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/settings/alerts")
async def update_alert_config(config: AlertConfigUpdate):
    """Update alert configuration"""
    try:
        for key, value in config.dict(exclude_none=True).items():
            db_manager.execute_query(
                "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (f"alert_{key}", str(value))
            )
        return {"message": "Alert configuration updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/settings/general")
async def get_general_settings():
    """Get general settings"""
    try:
        settings = {}
        results = db_manager.execute_query(
            "SELECT key, value FROM settings WHERE key LIKE 'general_%'",
            fetch=True
        )
        for key, value in results:
            settings[key] = value
        return settings
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/settings/general")
async def update_general_settings(settings: GeneralSettingsUpdate):
    """Update general settings"""
    try:
        for key, value in settings.dict().items():
            db_manager.execute_query(
                "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (f"general_{key}", str(value))
            )
        return {"message": "General settings updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==================== Main ====================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)