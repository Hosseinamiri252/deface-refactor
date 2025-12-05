# main.py
from cli import parse_args
from core.manager import AntiDefacementManager

def main():
    args = parse_args()

    config = {
        "host": args.host,
        "ssh": {
            "host": args.host,
            "port": args.port,
            "username": args.user,
            "password": args.password,
            "key_path": args.key
        },
        "path": args.path,
        "mode": args.mode,
        "use_redis": args.use_redis,
        "redis_host": args.redis_host,
        "redis_port": args.redis_port,
        "redis_password": args.redis_password,
        "backup_path": args.backup_path or f"/tmp/anti_defacement_{args.host}",
        "perm_config": { "path": args.path, "interval": 1 },
        "file_config": { "path": args.path, "interval": 1 },
    }

    manager = AntiDefacementManager(config)
    manager.start()

if __name__ == "__main__":
    main()
