import struct

class ConfigData:
    MaxNotes = 0
    ftpusername = ""
    ftppassword = ""
    ftpserver = ""
    enableftp = False
    extaddress = ""
    extnetmask = ""
    folder = ""
    folder2 = ""
    updfolder = ""
    TID = 0
    CCMStatusCheckPeriod = 0
    extmac = ""

    @classmethod
    def from_bytes(cls, data: bytes):
        def read_string(buf, idx):
            length = struct.unpack_from(">H", buf, idx)[0]
            idx += 2
            val = buf[idx:idx+length].decode("utf-8")
            return val, idx + length

        idx = 0
        cls.MaxNotes = struct.unpack_from(">I", data, idx)[0]; idx += 4
        cls.ftpusername, idx = read_string(data, idx)
        cls.ftppassword, idx = read_string(data, idx)
        cls.ftpserver, idx = read_string(data, idx)
        cls.enableftp = data[idx] == 1; idx += 1
        cls.extaddress, idx = read_string(data, idx)
        cls.extnetmask, idx = read_string(data, idx)
        cls.folder, idx = read_string(data, idx)
        cls.folder2, idx = read_string(data, idx)
        cls.updfolder, idx = read_string(data, idx)
        cls.TID = struct.unpack_from(">I", data, idx)[0]; idx += 4
        cls.CCMStatusCheckPeriod = struct.unpack_from(">I", data, idx)[0]; idx += 4
        cls.extmac, idx = read_string(data, idx)

    @classmethod
    def to_bytes(cls) -> bytes:
        def encode_string(s: str) -> bytes:
            b = s.encode('utf-8')
            return struct.pack(">H", len(b)) + b

        buf = bytearray()
        buf += struct.pack(">I", cls.MaxNotes)
        buf += encode_string(cls.ftpusername)
        buf += encode_string(cls.ftppassword)
        buf += encode_string(cls.ftpserver)
        buf += struct.pack("B", 1 if cls.enableftp else 0)
        buf += encode_string(cls.extaddress)
        buf += encode_string(cls.extnetmask)
        buf += encode_string(cls.folder)
        buf += encode_string(cls.folder2)
        buf += encode_string(cls.updfolder)
        buf += struct.pack(">I", cls.TID)
        buf += struct.pack(">I", cls.CCMStatusCheckPeriod)
        buf += encode_string(cls.extmac)
        return bytes(buf)

    @classmethod
    def to_dict(cls):
        return {
            "MaxNotes": cls.MaxNotes,
            "ftpusername": cls.ftpusername,
            "ftppassword": cls.ftppassword,
            "ftpserver": cls.ftpserver,
            "enableftp": cls.enableftp,
            "extaddress": cls.extaddress,
            "extnetmask": cls.extnetmask,
            "folder": cls.folder,
            "folder2": cls.folder2,
            "updfolder": cls.updfolder,
            "TID": cls.TID,
            "CCMStatusCheckPeriod": cls.CCMStatusCheckPeriod,
            "extmac": cls.extmac
        }
