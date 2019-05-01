import zlib

class Hash40:
    def __init__(self, hash40, tag = None):
        self.hash40 = hash40
        self.length = int(hash40, 16) >> 32
        self.hash = hex(int(hash40, 16) & 0xffffffff)
        self.tag = tag

        if(len(self.hash40.replace('0x', '')) < 10):
            self.hash40 = '0x' + ('0' * (10 - len(self.hash40.replace('0x', '')))) + self.hash40.replace('0x', '')

    @staticmethod
    def Create(hash, length):
        return Hash40(hex(length) + hash[2:])

    @staticmethod
    def CreateFromString(string):
        return Hash40(hex(len(string)) + Hash40.doCRC(string).replace('0x',''))

    @staticmethod
    def doCRC(string):
        h = hex(zlib.crc32(bytearray(string, 'utf-8')))
        if len(h.replace("0x","")) < 8:
            h = "0x" + ('0' * (8 - len(h.replace("0x","")))) + h.replace("0x","")
        return h