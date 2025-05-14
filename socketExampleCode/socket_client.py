
# === socket_client.py ===
# 與遠端設備溝通的主模組 / Main socket communication module
import socket
import struct
import os
import threading
import select
import time
from datetime import datetime
from packet_builder import build_packet, build_action,build_setup,build_multi, ACK, SEGMENT_SIZE, SocketCommand, SocketCommandType
from packet_parser import parse_command
from data.config_data import ConfigData


ack_event = threading.Event()  # 用於等待 ACK 回應
send_lock = threading.Lock()   # 防止同時送出封包

def socket_listener(sock):
    # 監聽遠端資料回應 / Listen and handle socket input
    buffer = bytearray()
    while True:
        try:
            readable, _, _ = select.select([sock], [], [], 1)
            if sock in readable:
                data = sock.recv(1024*1024*1)
                if not data:
                    print("Client disconnected normally")
                    break

                print(f"[INFO] Received {len(data)} bytes")
                buffer.extend(data)

                offset = 0
                while offset < len(buffer):
                    remaining = len(buffer) - offset
                    expected_len = get_full_packet_length(buffer, offset, remaining)
                    if expected_len == -1 or remaining < expected_len:
                        break

                    packet = buffer[offset:offset + expected_len]

                    if len(packet) == 1 and packet[0] == ACK:
                        ack_event.set()
                        print("[PARSE] ACK received")
                    else:
                        parse_command(packet, sock)

                    offset += expected_len

                if offset < len(buffer):
                    buffer = buffer[offset:]  # 保留未處理的
                else:
                    buffer = bytearray()

        except Exception as e:
            print(f"[SOCKET IN] Error: {e}")
            break


def get_full_packet_length(data: bytes, offset: int, available: int) -> int:
    if available == 1 and data[offset] == ACK:
        return 1

    if available < 5:
        return -1
    if data[offset] != 0x02:
        return -1

    md = data[offset + 3]

    if md == SocketCommandType.ACTION_CMD_FORMAT:
        return 6

    elif md == SocketCommandType.SETUP_CMD_FORMAT:
        if available >= 6:
            length = data[offset + 4]
            return 7 + length

    elif md == SocketCommandType.MULTI_PURPOSE_CMD_FORMAT:
        if available >= 8:
            length = (
                data[offset + 4]
                | (data[offset + 5] << 8)
                | (data[offset + 6] << 16)
                | (data[offset + 7] << 24)
            )
            return 8 + length + 3

    elif md == SocketCommandType.RESPONSE_CMD_FORMAT:
        if available >= 8:
            length = (
                data[offset + 4]
                | (data[offset + 5] << 8)
                | (data[offset + 6] << 16)
                | (data[offset + 7] << 24)
            )
            return 8 + length + 3

    return -1


def heartbeat_sender(sock):
    # 定時送出心跳封包 / Send heartbeat every 60 seconds
    while True:
        try:
            packet = build_action(SocketCommand.SOCKET_ACTION_CMD_HEARTBEAT)
            ack_event.clear()
            with send_lock:
                sock.sendall(packet)
                print(f"[HEARTBEAT] Sent 0x{SocketCommand.SOCKET_ACTION_CMD_HEARTBEAT:02X} (heartbeat)")
            if not ack_event.wait(timeout=30):
                print("[HEARTBEAT] Timeout waiting for ACK.")
                break
            else:
                print("[HEARTBEAT] Got ACK")
        except Exception as e:
            print(f"[HEARTBEAT] Error: {e}")
            break
        time.sleep(10)

def upgrade_apk(filepath, sock):
    # 上傳 APK 檔案 / Upload APK file
    filesize = os.path.getsize(filepath)
    total_segments = (filesize + SEGMENT_SIZE - 1) // SEGMENT_SIZE
    with open(filepath, "rb") as f:
        for segment_id in range(total_segments):
            chunk = f.read(SEGMENT_SIZE)
            packet = build_packet(segment_id, SocketCommand.SOCKET_MULTI_CMD_UPGRADE_APK, total_segments, chunk)
            ack_event.clear()
            with send_lock:
                sock.sendall(packet)
                print(f"[upgrade_apk] Sent segment {segment_id + 1}/{total_segments}")
            if not ack_event.wait(timeout=30):
                print("[upgrade_apk] Timeout waiting for ACK. Aborting.")
                return
            else:
                print("[upgrade_apk] Got ACK")
    print("[upgrade_apk] Upload complete.")

def upgrade_sdc(filepath, sock):
    # 上傳 SDC 檔案 / Upload SDC file
    filesize = os.path.getsize(filepath)
    total_segments = (filesize + SEGMENT_SIZE - 1) // SEGMENT_SIZE
    with open(filepath, "rb") as f:
        for segment_id in range(total_segments):
            chunk = f.read(SEGMENT_SIZE)
            packet = build_packet(segment_id, SocketCommand.SOCKET_MULTI_CMD_UPGRADE_SDC, total_segments, chunk)
            ack_event.clear()
            with send_lock:
                sock.sendall(packet)
                print(f"[upgrade_sdc] Sent segment {segment_id + 1}/{total_segments}")
            if not ack_event.wait(timeout=30):
                print("[upgrade_sdc] Timeout waiting for ACK. Aborting.")
                return
            else:
                print("[upgrade_sdc] Got ACK")
    print("[upgrade_sdc] Upload complete.")



def send_socket_data(sock, packet):
    try:
        ack_event.clear()
        with send_lock:
            sock.sendall(packet)
            print(f"[STATUS] Sent 0x{SocketCommand.SOCKET_ACTION_CMD_ASK_STATUS:02X} (status)")
        if not ack_event.wait(timeout=30):
            print("[STATUS] Timeout waiting for ACK.")
        else:
            print("[STATUS] Got ACK")
    except Exception as e:
        print(f"[STATUS] Error: {e}")

def main_loop(host, port):
    # 主連線流程 / Main client loop
    with socket.create_connection((host, port)) as s:
        s.settimeout(30)
        print(f"Connected to {host}:{port}")
        threading.Thread(target=socket_listener, args=(s,), daemon=True).start()
        threading.Thread(target=heartbeat_sender, args=(s,), daemon=True).start()

        while True:
            try:
                print("\nEnter 1 for Upgrade APK, 2 for Upgrade SDC, 3 for Ask status, 4 for config write, 5 for config read, 6 for start audit mode, 7 for stop audit mode, 8 for ask date time, 9 for set date time, q to quit:")
                print("a1 for START_KEY, a2 for CLEAR_KEY, a3 for GET_DETECTION_MODE, a4 for GET_DETECTION_MODE")
                print("s10 for SELECT_CURRENCY, s11 for SET_CURRENCY_MODE, s12 for SET_DETECTION_MODE, s13 for SET_VARUIOS_MARAMETERS, s14 for SET_ADD_MODE, s15 for SET_CURRENCY_MODE")
                user_input = input("> ").strip()

                if user_input == "a1":
                    packet = build_action(SocketCommand.SOCKET_ACTION_CMD_START_KEY)
                    send_socket_data(s, packet)
                elif user_input == "a2":
                    packet = build_action(SocketCommand.SOCKET_ACTION_CMD_CLEAR_KEY)
                    send_socket_data(s, packet)
                elif user_input == "a3":
                    packet = build_action(SocketCommand.SOCKET_ACTION_CMD_GET_DETECTION_MODE)
                    send_socket_data(s, packet)
                elif user_input == "a4":
                    packet = build_action(SocketCommand.SOCKET_ACTION_GET_VARUIOS_MARAMETERS)
                    send_socket_data(s, packet)
                elif user_input == "s10":
                    packet = build_setup(SocketCommand.SOCKET_SETUP_CMD_SELECT_CURRENCY, [0x00])
                    send_socket_data(s, packet)
                elif user_input == "s11":
                    packet = build_setup(SocketCommand.SOCKET_SETUP_CMD_SET_CURRENCY_MODE, [0x01])
                    send_socket_data(s, packet)
                elif user_input == "s12":
                    params = [
                            0x01,  # SortOn: enable sorting
                            0x00,  # FaceOn: disable face detection
                            0x00,  # OrntOn: disable orientation check
                            0x01,  # EmissionOn: enable UV/IR emission
                            0x00,  # FitMode: COMPASS_FIT_OFF (0) 0 FIT Disable, 1 ATM, 2 FIT, 3 UNFIT, 4 TAPE
                            0x01  # SerialMode: COMPASS_SN_OFF (0)  0 Serial Disable, 1 Serial Enable, 2 Serial Compare, 3 TITO Enable, 4 CHECK Enable
                        ]
                    packet = build_setup(SocketCommand.SOCKET_SETUP_CMD_SET_DETECTION_MODE,params)
                    send_socket_data(s, packet)
                elif user_input == "s13":
                    params = [   
                            0x01,  # MotorSpeed: (0 = LOW, 1 = MEDIUM, 2 = HIGH, 3 = ULTRA)
                            0x01,  # SoundOn: ON
                            0x00   # AutoPrintOn: OFF
                        ]
                    packet = build_setup(SocketCommand.SOCKET_SETUP_SET_VARUIOS_MARAMETERS, params)
                    send_socket_data(s, packet)
                elif user_input == "s14":
                    packet = build_setup(SocketCommand.SOCKET_SETUP_SET_ADD_MODE, [0x01])
                    send_socket_data(s, packet)
                elif user_input == "s15":
                    packet = build_setup(SocketCommand.SOCKET_SETUP_SET_AT_MT_MODE, [0x01])
                    send_socket_data(s, packet)
                elif user_input == "1":
                    upgrade_apk("app-release.apk", s)
                elif user_input == "2":
                    upgrade_sdc("NC7500.sd6", s)
                elif user_input == "3":
                    packet = build_action(SocketCommand.SOCKET_ACTION_CMD_ASK_STATUS)
                    send_socket_data(s, packet)
                elif user_input == "4":
                    ConfigData.MaxNotes = 100
                    ConfigData.ftpusername = "user"
                    ConfigData.ftppassword = "P@ss-W0rd"
                    ConfigData.ftpserver = "192.168.1.253:21"
                    ConfigData.enableftp = True
                    ConfigData.extaddress = "192.168.1.101"
                    ConfigData.extnetmask = "255.255.255.128"
                    ConfigData.folder = "/ExchangeFolder/Counts"
                    ConfigData.folder2 = "/ExchangeFolder/Counts"
                    ConfigData.updfolder = "/firmware"
                    ConfigData.TID = 60301516
                    ConfigData.CCMStatusCheckPeriod = 300000
                    ConfigData.extmac = "3a:3a:3a:3a:3a:3a"

                    config_data = ConfigData.to_bytes();
                    packet = build_multi(SocketCommand.SOCKET_MULTI_CMD_CONFIG_WRITE, config_data)
                    send_socket_data(s, packet)

                    
                elif user_input == "5":
                    packet = build_action(SocketCommand.SOCKET_ACTION_CMD_CONFIG_READ)
                    send_socket_data(s, packet)
                    
                elif user_input == "6":
                    data=[1]
                    packet = build_setup(SocketCommand.SOCKET_SETUP_CMD_AUDIT_MODE, data)
                    send_socket_data(s, packet)
                    
                elif user_input == "7":
                    data=[0]
                    packet = build_setup(SocketCommand.SOCKET_SETUP_CMD_AUDIT_MODE, data)
                    send_socket_data(s, packet)
                    
                elif user_input == "8":
                    packet = build_action(SocketCommand.SOCKET_ACTION_CMD_ASK_DATE_TIME)
                    send_socket_data(s, packet)

                elif user_input == "9":
                    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    datetime_bytes = now.encode('utf-8')
                    packet = build_multi(SocketCommand.SOCKET_MULTI_CMD_SET_DATE_TIME, datetime_bytes)
                    send_socket_data(s, packet)
                    
                elif user_input.lower() == "q":
                    print("Exiting...")
                    break
                else:
                    print("Unknown command.")
            except KeyboardInterrupt:
                print("Interrupted by user.")
                break
