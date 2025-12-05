# cli.py
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Anti-Defacement CLI")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--port", default="22")
    parser.add_argument("--path", required=True)
    parser.add_argument("--key")
    parser.add_argument("--password")
    parser.add_argument("--mode", choices=["passive", "active"], default="passive")
    parser.add_argument("--use-redis", action="store_true")
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--redis-password")
    parser.add_argument("--backup-path")

    return parser.parse_args()
