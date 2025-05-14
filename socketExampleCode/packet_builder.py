
# === packet_builder.py ===
# 負責封包的建立 / Packet builder for socket communication
import struct

# 協定常數 / Protocol Constants
STX = 0x02
STN = 0x31
ETX = 0x03
ACK = 0x06
SEGMENT_SIZE = 1 * 1024 * 1024

# 命令代碼 / Command Codes

class SocketCommand:
    SOCKET_ACTION_CMD_START_KEY = 0x04
    SOCKET_ACTION_CMD_CLEAR_KEY = 0x05
    SOCKET_SETUP_CMD_SELECT_CURRENCY = 0x0A
    SOCKET_SETUP_CMD_SET_CURRENCY_MODE = 0x0E
    SOCKET_SETUP_CMD_SET_DETECTION_MODE = 0x0F
    SOCKET_SETUP_SET_VARUIOS_MARAMETERS = 0x13
    SOCKET_ACTION_GET_VARUIOS_MARAMETERS = 0x14
    SOCKET_ACTION_CMD_GET_DETECTION_MODE = 0x15
    SOCKET_SETUP_SET_AT_MT_MODE = 0x16
    SOCKET_SETUP_SET_ADD_MODE = 0x17

    SOCKET_MULTI_CMD_CONFIG_WRITE = 0x97
    SOCKET_MULTI_CMD_UPGRADE_SDC = 0x98
    SOCKET_MULTI_CMD_UPGRADE_APK = 0x99
    SOCKET_MULTI_CMD_SET_DATE_TIME = 0x9F
    SOCKET_ACTION_CMD_HEARTBEAT = 0x9A
    SOCKET_ACTION_CMD_ASK_STATUS = 0x9B
    SOCKET_ACTION_CMD_CONFIG_READ = 0x9C
    SOCKET_ACTION_CMD_ASK_DATE_TIME = 0x9E
    SOCKET_SETUP_CMD_AUDIT_MODE = 0x9D
    SOCKET_RESPONSE_CMD_BANKNOTE_DATA = 0xAA
    SOCKET_RESPONSE_CMD_ASK_STATUS = 0x9B
    SOCKET_RESPONSE_CMD_CONFIG_READ = 0x9C
    SOCKET_RESPONSE_CMD_ASK_DATE_TIME = 0x9E

class SocketCommandType:
    RESPONSE_CMD_FORMAT = 0x00
    ACTION_CMD_FORMAT = 0x02
    SETUP_CMD_FORMAT = 0x03
    MULTI_PURPOSE_CMD_FORMAT = 0x04
    MACHINE_CMD_FORMAT = 0x05

def build_packet(segment_id, cmd_type, total_segments, data):
    # 建立 MULTI 封包 / Build packet for MULTI command
    segment_header = struct.pack("<II", segment_id, total_segments)
    payload = segment_header + data
    length = len(payload)
    header = struct.pack("<BBBBI", STX, STN, cmd_type, SocketCommandType.MULTI_PURPOSE_CMD_FORMAT, length)
    bcc1 = sum(header[1:]) % 0x80
    packet = header + bytes([bcc1]) + payload + bytes([ETX])
    bcc2 = sum(packet[1:]) % 0x80
    packet += bytes([bcc2])
    return packet

def build_action(cmd_type):
    # 建立簡易 ACTION 封包 / Build simple ACTION command packet
    header = struct.pack("<BBBBB", STX, STN, cmd_type, SocketCommandType.ACTION_CMD_FORMAT, ETX)
    bcc = sum(header[1:]) % 0x80
    packet = header + bytes([bcc])
    return packet

def build_setup(cmd_type, data):
    # 建立 SETUP 封包 / Build SETUP format packet
    length = len(data)
    header = struct.pack("<BBBBB", STX, STN, cmd_type, SocketCommandType.SETUP_CMD_FORMAT, length)
    packet = header + bytes(data) + bytes([ETX])
    bcc2 = sum(packet[1:]) % 0x80
    packet += bytes([bcc2])
    return packet


def build_multi(cmd_type, data):
    # 建立 MULTI 封包 / Build packet for MULTI command
    length = len(data)
    header = struct.pack("<BBBBI", STX, STN, cmd_type, SocketCommandType.MULTI_PURPOSE_CMD_FORMAT, length)
    bcc1 = sum(header[1:]) % 0x80
    packet = header + bytes([bcc1]) + data + bytes([ETX])
    bcc2 = sum(packet[1:]) % 0x80
    packet += bytes([bcc2])
    return packet

def calculate_bcc(byte_list, size):
    # 計算 BCC 校驗碼 / Calculate BCC
    return sum(byte_list[1:size]) % 0x80

