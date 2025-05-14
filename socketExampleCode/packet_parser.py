
# === packet_parser.py ===
# 封包解析器 / Parses received packets
import struct
import json
from collections import defaultdict
from packet_builder import SocketCommand, SocketCommandType, calculate_bcc, ACK
from data.config_data import ConfigData

def is_bcc_valid(data):
    # 驗證 BCC 正確性 / Validate BCC checksums
    if len(data) < 4:
        return False

    format_type = data[3]
    last_byte = data[-1]
    bcc2_valid = calculate_bcc(data, len(data) - 1) == (last_byte & 0xFF)

    if format_type in (SocketCommandType.MULTI_PURPOSE_CMD_FORMAT, SocketCommandType.RESPONSE_CMD_FORMAT):
        if len(data) < 9:
            return False
        bcc1_valid = calculate_bcc(data, 7) == (data[8] & 0xFF)
        print(f"[BCC] bcc1={calculate_bcc(data, 7)} == {data[8]}, bcc2={calculate_bcc(data, len(data)-1)} == {last_byte}")
        return bcc1_valid and bcc2_valid
    elif format_type in (
        SocketCommandType.ACTION_CMD_FORMAT,
        SocketCommandType.SETUP_CMD_FORMAT,
        SocketCommandType.MACHINE_CMD_FORMAT
    ):
        print(f"[BCC] bcc2={calculate_bcc(data, len(data)-1)} == {last_byte}")
        return bcc2_valid
    return False

# === parse_machine_status.py ===
# This module handles parsing of the machine status report based on NC7500 response
# The output JSON must follow a strict structure defined by the host system (Sberbank/CS SW)

def parse_machine_status(data):
    """
    Parses binary status data from NC7500 and returns structured JSON.

    Expected fields to extract:
    - MachineSerialNumber
    - Time (system time)
    - Versions (firmware components)
    - SettingsHash
    - Settings (e.g., AuditMode)
    - MachineState (State, Code)
    - Nation-specific firmware versions
    """
    try:
        index = 0

        # Serial number (fixed 10 bytes)
        serial = data[index:index+10].decode('utf-8').rstrip('\x00')
        index += 10

        # Time (fixed 20 bytes)
        timestamp = data[index:index+20].decode('utf-8').rstrip('\x00')
        index += 20

        # SettingsHash (8 bytes)
        settings_hash = data[index:index+8].decode('utf-8').rstrip('\x00')
        index += 8
        # tid (4 bytes)
        tid = int.from_bytes(data[index:index+4], byteorder='big')
        index += 4
        # AuditMode (1 byte)
        audit_mode_flag = data[index]
        audit_mode = audit_mode_flag == 1
        index += 1

        # MachineState (1 byte) and Status Code (4 bytes)
        state_code = data[index]
        index += 1
        state_text = {0: "OK", 1: "Warning", 2: "Error"}.get(state_code, "Unknown")
        status_code = int.from_bytes(data[index:index+4], byteorder='big')
        index += 4

        # Core firmware versions
        machine_model_type = data[index:index+20].decode('utf-8').rstrip('\x00')
        index += 20
        dsp_version = data[index:index+10].decode('utf-8').rstrip('\x00')
        index += 10
        fpga_version = data[index:index+10].decode('utf-8').rstrip('\x00')
        index += 10
        gui_version = data[index:index+10].decode('utf-8').rstrip('\x00')
        index += 10

        versions = {
            "MachineModelType": machine_model_type,
            "DspVersion": dsp_version,
            "FpgaVersion": fpga_version,
            "GUIVersion": gui_version
        }

        # Nation-specific versions
        nation_versions = {}
        nation_count = data[index]
        index += 1

        for _ in range(nation_count):
            nation_name = data[index:index+3].decode('utf-8').rstrip('\x00')  # 3 bytes
            index += 3
            nation_version = data[index:index+10].decode('utf-8').rstrip('\x00')  # 10 bytes
            index += 10
            nation_versions[nation_name] = nation_version

        versions["NationVersions"] = nation_versions

        status_json = {
            "MachineSerialNumber": serial,
            "Time": timestamp,
            "Versions": versions,
            "SettingsHash": settings_hash,
            "TID": tid,
            "Settings": {
                "AuditMode": audit_mode
            },
            "MachineState": {
                "State": state_text,
                "Code": status_code
            }
        }

        return status_json

    except Exception as e:
        print(f"[PARSE STATUS] Error parsing machine status: {e}")
        return None


def parse_custom_data(data):
    # 解析自定格式資料 / Parse banknote detail record
    try:
        index = 0
        cashier_id = data[index:index+20].decode('utf-8').rstrip('\x00'); index += 20
        count_speed = data[index:index+5].decode('utf-8').rstrip('\x00'); index += 5
        count_mode = data[index:index+16].decode('utf-8').rstrip('\x00'); index += 16
        settings_hash = data[index:index+4].decode('utf-8').rstrip('\x00'); index += 4
        number_count_file = struct.unpack(">Q", data[index:index+8])[0]; index += 8
        guid = data[index:index+38].decode('utf-8').rstrip('\x00'); index += 38
        machineSerialNumber = data[index:index+10].decode('utf-8').rstrip('\x00'); index += 10
        startTime = data[index:index+20].decode('utf-8').rstrip('\x00'); index += 20
        endTime = data[index:index+20].decode('utf-8').rstrip('\x00'); index += 20

        note_count = struct.unpack(">I", data[index:index+4])[0]; index += 4
        details = []
        for _ in range(note_count):
            currency = data[index:index+3].decode('utf-8').rstrip('\x00')
            nominal = struct.unpack(">I", data[index+3:index+7])[0]
            issue = data[index+7:index+17].decode('utf-8').rstrip('\x00')
            sn = data[index+17:index+37].decode('utf-8').rstrip('\x00')
            note_error = struct.unpack(">I", data[index+37:index+41])[0]
            rejected = data[index+41] == 1
            index += 60
            details.append({"currency": currency, "nominal": nominal, "issue": issue, "sn": sn, "noteError": note_error, "rejected": rejected})

        entity = {
            "cashierId": cashier_id, "countSpeed": count_speed, "countMode": count_mode,
            "settingsHash": settings_hash, "guid": guid, "numberCountFile": number_count_file,
            "machineSerialNumber": machineSerialNumber, "startTime": startTime, "endTime": endTime
        }
        return {"entity": entity, "details": details}
    except Exception as e:
        print(f"[PARSE] Error parsing byte[] format: {e}")
        return None

def format_to_new_json_structure(parsed):
    # 格式化輸出 JSON 結構 / Format parsed result into JSON
    if parsed is None:
        return None
    entity = parsed["entity"]
    details = parsed["details"]
    reject_count = sum(1 for d in details if d["rejected"])
    total_count = len(details)

    currency_amount = defaultdict(int)
    for d in details:
        if not d["rejected"] and d["currency"]:
            currency_amount[d["currency"]] += d["nominal"]

    return {
        "CountSettings": {
            "CashierId": entity.get("cashierId", ""), "CountSpeed": entity.get("countSpeed", ""),
            "CountMode": entity.get("countMode", ""), "SettingsHash": entity.get("settingsHash", ""),
            "NumberCountFile": entity.get("numberCountFile", "")
        },
        "CountResult": {
            "MachineSerialNumber": entity.get("machineSerialNumber", ""), "VersionTemplateNotes": "",
            "StartTime": entity.get("startTime", ""), "EndTime": entity.get("endTime", ""),
            "TotalNotes": total_count, "RejectNotes": reject_count,
            "Notes": details,
            "TotalAmount": [ {"Currency": c, "Amount": a} for c, a in currency_amount.items() ]
        }
    }

def parse_command(rawData, sock):
    try:
        if is_bcc_valid(rawData):
            print("[PARSE] Valid BCC. Responding ACK.")
            sock.sendall(bytes([ACK]))
            cmd_format = rawData[3]
            cmd = rawData[2] & 0xFF
            print(f"[CMD] Received CMD: 0x{cmd:02X}, FORMAT: 0x{cmd_format:02X}")
            if cmd_format == SocketCommandType.RESPONSE_CMD_FORMAT:
                data = rawData[9:-2]
                if cmd == SocketCommand.SOCKET_ACTION_GET_VARUIOS_MARAMETERS:
                    if len(data) < 5:
                        print("[PARSE] GET_VARUIOS_MARAMETERS data too short:", data)
                    else:
                        motor_speed = data[0]
                        at_mode = data[1] == 1
                        sound = data[2] == 1
                        add_on = data[3] == 1
                        auto_print_on = data[4] == 1

                        print("[PARSE] GET_VARUIOS_MARAMETERS response:")
                        print(f"  MotorSpeed     : {motor_speed} (0 = LOW, 1 = MEDIUM, 2 = HIGH, 3 = ULTRA)")
                        print(f"  AT Mode        : {at_mode}")
                        print(f"  Sound          : {sound}")
                        print(f"  AddMode        : {add_on}")
                        print(f"  AutoPrintOn    : {auto_print_on}")

                if cmd == SocketCommand.SOCKET_ACTION_CMD_GET_DETECTION_MODE:
                    if len(data) < 7:
                        print("[PARSE] GET_DETECTION_MODE data too short:", data)
                    else:
                        count_lv = data[0]
                        sort_on = (data[1] == 1)
                        face_on = (data[2] == 1)
                        ornt_on = (data[3] == 1)
                        emission_on = (data[4] == 1)
                        fit_mode = data[5]
                        serial_mode = data[6]

                        print("[PARSE] GET_DETECTION_MODE response:")
                        print(f"  CountModeLv   : {count_lv}")
                        print(f"  SortOn        : {sort_on}")
                        print(f"  FaceOn        : {face_on}")
                        print(f"  OrntOn        : {ornt_on}")
                        print(f"  EmissionOn    : {emission_on}")
                        print(f"  FitMode       : {fit_mode} (0=OFF,1=ATM,2=FIT,3=UNFIT,4=TAPE)")
                        print(f"  SerialMode    : {serial_mode} (0=OFF,1=ON,2=Compare,3=TITO,4=Check)")
                        
                if cmd == SocketCommand.SOCKET_SETUP_CMD_SELECT_CURRENCY:
                    print("[PARSE] SOCKET_SETUP_CMD_SELECT_CURRENCY success:",data[0]==0)

                if cmd == SocketCommand.SOCKET_SETUP_CMD_SET_CURRENCY_MODE:
                    print("[PARSE] SOCKET_SETUP_CMD_SET_CURRENCY_MODE success:",data[0]==0)

                if cmd == SocketCommand.SOCKET_SETUP_CMD_SET_DETECTION_MODE:
                    print("[PARSE] SOCKET_SETUP_CMD_SET_DETECTION_MODE success:",data[0]==0)

                if cmd == SocketCommand.SOCKET_RESPONSE_CMD_BANKNOTE_DATA:
                    parsed = parse_custom_data(data)
                    final_json = format_to_new_json_structure(parsed)
                    print("[PARSE] Parsed SOCKET_RESPONSE_CMD_BANKNOTE_DATA final_json JSON:\n", json.dumps(final_json, indent=2))
                if cmd == SocketCommand.SOCKET_RESPONSE_CMD_ASK_STATUS:
                    final_json = parse_machine_status(data)
                    print("[PARSE] Parsed SOCKET_RESPONSE_CMD_ASK_STATUS final_json JSON:\n", json.dumps(final_json, indent=2))
                if cmd == SocketCommand.SOCKET_RESPONSE_CMD_CONFIG_READ:
                    ConfigData.from_bytes(data)
                    print(ConfigData.to_dict())
                if cmd == SocketCommand.SOCKET_RESPONSE_CMD_ASK_DATE_TIME:
                    datetime_str = data.decode('utf-8')
                    print(datetime_str)
                if cmd == SocketCommand.SOCKET_ACTION_CMD_HEARTBEAT:
                    print("[CMD]Get heart beat")
            else:
                print("[CMD] Other FORMAT handler")
        else:
            print("[PARSE] Invalid packet or BCC failed")
    except Exception as e:
        print(f"[PARSE] Exception: {e}")
