# === main.py ===
# Socket 客戶端主程式 / Main program for socket client
import argparse
from socket_client import main_loop

def parse_args():
    parser = argparse.ArgumentParser(description="Socket client for banknote module")
    parser.add_argument("--ip", type=str, default="192.168.88.204", help="Target IP address") 
    parser.add_argument("--port", type=int, default=5888, help="Target port")   
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    main_loop(args.ip, args.port)
