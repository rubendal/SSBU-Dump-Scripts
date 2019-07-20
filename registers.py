class Registers:
    registers = {}

    def __init__(self, registers = {}):
        self.registers = registers

    def Get(self, r):
        type, id = self.CheckRegister(r)
        if id == 'sp':
            return None
        if id in self.registers:
            if type == 'int':
                return int(self.registers[id])
            elif type == 'float':
                return float(self.registers[id])
            else:
                return self.registers[id]
        return None

    def CheckRegister(self, r):
        type = 'none'
        id = -1
        if 'sp' in r:
            return 'sp', r
        if 's' in r:
            type = 'float'
        if 'x' in r:
            type = 'int'
        if 'w' in r:
            type = 'int'
        if '.' in r:
            id = int(r[1:].split('.')[0].replace('[','').replace(']',''))
        else:
            id = int(r[1:].replace('[','').replace(']',''))
        return type, id
    
    def Set(self, r, value):
        type, id = self.CheckRegister(r)
        if type == 'float':
            value = float(value)
        self.registers[id] = value
        return self.registers[id]

    def SetAdd(self, r, value):
        type, id = self.CheckRegister(r)
        if id in self.registers:
            self.registers[id] += value
            return self.registers[id]
        else:
            self.registers[id] = value
            return self.registers[id]
        

    def Clone(self):
        return Registers(self.registers.copy())