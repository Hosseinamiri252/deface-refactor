# core/redis_client.py

import redis
import json
from rich.console import Console

console = Console()

class RedisConfig:
    def __init__(self, host='localhost', port=6379, db=0, password=None):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.connection = None
        self.queue = None

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
            self.connection.ping()
            console.print(f"[green]✓ Connected to Redis at {self.host}:{self.port}[/green]")
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
