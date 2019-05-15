import re
from hash40 import Hash40

class Constant:
    def __init__(self, index, name):
        self.index = index
        self.name = name

Constants = []
ci = 1
cfile = open('const_value_table.csv', 'r')
for s in cfile:
    Constants.append(Constant(ci, s.split(',')[1].strip()))
    ci += 1

class FunctionParams:
    def __init__(self, function, length, params):
        self.function = function
        self.length = int(length)
        self.params = params.split('|')

FunctionParam = []
fpfile = open('function_params.csv','r')
for s in fpfile:
    r = s.split(',')
    FunctionParam.append(FunctionParams(r[0],r[1],r[2].strip()))
    
class Register:
    def __init__(self, register, value):
        self.register = register
        self.value = value

class Block:
    def __init__(self, condition, branch, address = 0):
        self.condition = condition
        self.Functions = []
        self.branch = branch
        self.address = address

    def print(self,depth):
        s = ('\t' * depth) + 'if(' + self.condition.printCondition() +'){\n'
        for function in self.Functions:
            s += '{0}'.format(function.print(depth+1))
        s+= ('\t' * depth) + '}\n'
        return s

class Loop:
    def __init__(self, iterator, functions, branch, address = 0):
        self.iterator = iterator
        self.Functions = functions
        self.branch = branch

    def print(self,depth):
        s = ('\t' * depth) + 'for(' + self.iterator.iteratorPrint() + ' Iterations){\n'
        for function in self.Functions:
            s += '{0}'.format(function.print(depth + 1))
        s+= ('\t' * depth) + '}\n'
        return s

class Function:
    def __init__(self, function, params, address = 0):
        self.function = function
        self.params = params
        self.address = address

    def print(self,depth):
        s = ('\t' * depth) + '{0}( '.format(self.function)
        fp = next((x for x in FunctionParam if x.function == self.function and x.length == len(self.params)), None)
        index = 0
        for param in self.params:
            if fp:
                s += '{0}={1}, '.format(fp.params[index], param.print(0))
            else:
                s += '{0}, '.format(param.print(0))
            index += 1
        s = s.strip(', ') + ' )\n'
        return s

    def printCondition(self):
        s = '{0}( '.format(self.function)
        for param in self.params:
            s += '{0}, '.format(param.print(0))
        s = s.strip(', ') + ' )'
        return s

class Value:
    def __init__(self, value, vtype):
        self.value = value
        self.type = vtype

    def print(self,depth):
        if self.type == 'intC':
            return self.value.replace('"','')
        elif self.type == 'bool':
            if self.value == 1:
                return 'True'
            else:
                return 'False'
        elif self.type == 'function':
            return '{0}()'.format(self.value)
        elif self.type == 'hash40':
            return self.value.hash40
        elif self.type == 'int':
            return int(self.value)
        else:
            return self.value

    def iteratorPrint(self):
        return str(self.value - 1)

class SubScript:
    def __init__(self, r2, script, sectionList = []):
        self.r2 = r2 #Radare r2pipe
        self.script = script
        self.blocks = []

        ignoreLine = True
        self.Sections = sectionList
        self.lines = []
        self.address = []

        self.Registers = []
        self.Blocks = []
        self.CurrentBlock = None
        self.Functions = []
        self.Values = []
        self.SubScript = None
        self.prevOperation = None
        self.isConstant = False
        self.CurrentValue = 0

        self.CurrentAddress = 0

        for l in self.script.split('\r'):
            if len(l) > 0:
                if l[0] == '|' or l[0] == '\\':
                    if ignoreLine:
                        ignoreLine = False
                    else:
                        a = l.split(';')[0].strip().split("  ")
                        line = a[len(a)-1][1:]
                        self.lines.append(line)
                        address = re.search("0x[0-9a-f]{8}", l)
                        if address:
                            address = address.group()
                        self.address.append(address)

    def parse_movz(self, movz):
        p = movz.split(',')[0]
        h = movz.split(',')[1]
        if h == 'wzr':
            h = '0x0'
        v = int(h, 16)
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = v
        else:
            self.Registers.append(Register(p, v))
        self.CurrentValue = v

    def parse_movk(self, movk):
        p = movk.split(',')[0]
        h = movk.split(',')[1].strip()
        if h == 'wzr':
            h = '0x0'
        v = int(h, 16)
        if h != 0:
            bs = int(movk.split(',')[2].strip().replace('lsl', ''))
            v = v << bs
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value += v
            self.CurrentValue = register.value
        else:
            self.Registers.append(Register(p, v))
            self.CurrentValue = v

    def parse_mov(self, mov):
        p = mov.split(',')[0].strip()
        h = mov.split(',')[1].strip()
        if h == 'w0' or h == 'wzr':
            h = '0x0'
        if p == 'v0.16b':
            #Float
            h = 's' + h.split('.')[0].replace('v','')
            register = next((x for x in self.Registers if x.register == h), None)
            if register:
                self.CurrentValue = register.value
        else:
            try:
                v = int(h, 16)
                register = next((x for x in self.Registers if x.register == p), None)
                if register:
                    register.value = v
                else:
                    self.Registers.append(Register(p, v))
                self.CurrentValue = v
            except:
                #Register
                r = next((x for x in self.Registers if x.register == h), None)
                register = next((x for x in self.Registers if x.register == p), None)
                if r:
                    if register:
                        register.value = r.value
                    else:
                        self.Registers.append(Register(p, r.value))
                    self.CurrentValue = r.value
                else:
                    None
                
        

    def parse_cmp(self, cmp):
        self.CurrentValue = int(cmp.split(',')[1].strip(),16)

    def parse_b_lo(self, b_lo):
        address = int(b_lo,16)
        index = 0
        for function in self.Functions:
            if int(function.address,16) > address:
                break
            index += 1
        l = self.Functions[index:]
        if index > 0:
            self.Functions = self.Functions[0:index-1]
        else:
            self.Functions = []
        self.Functions.append(Loop(Value(self.CurrentValue, 'int'), l, address, self.CurrentAddress))


    def parse_adrp(self, adrp):
        p = adrp.split(',')[0].strip()
        v = int(adrp.split(',')[1], 16)
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = v
        else:
            self.Registers.append(Register(p, v))

    def parse_add(self, add):
        p = add.split(',')[0].strip()
        p2 = add.split(',')[1].strip()
        try:
            v = int(add.split(',')[2], 16)
            register = next((x for x in self.Registers if x.register == p), None)
            if register:
                register.value += v
            else:
                self.Registers.append(Register(p, v))
        except:
            try:
                f = add.split(':')[2].replace('_phx','').replace('_lib','').replace('_void','')
                find = next((x for x in self.Sections if '::' in x.function and x.function.split(':')[2].split('(')[0] == f), None)
                if find:
                    v = find.num
                    register = next((x for x in self.Registers if x.register == p), None)
                    if register:
                        register.value += v
                    else:
                        self.Registers.append(Register(p, v))
            except:
                None #sp
        
    def parse_b(self, b):
        if b == 'method.app::sv_animcmd.ATTACK_lua_State':
            if self.CurrentBlock:
                self.CurrentBlock.Functions.append(Function(b, self.Values, self.CurrentAddress))
            else:
                self.Functions.append(Function(b, self.Values, self.CurrentAddress))
            self.Values = []
        else:
            None
                
    def parse_b_ne(self, b_ne):
        None

    def parse_b_eq(self, b_eq):
        None

    def parse_bl(self, bl):
        if '0x' in bl or 'fcn.' in bl:
            #Add subscript
            if 'fcn.' in bl:
                bl = bl.replace('fcn.', '0x')
            if self.r2:
                script = self.r2.cmd('s {0};aF;pdf'.format(hex(int(bl,16))))
                self.SubScript = SubScript(self.r2, script, self.Sections)
        elif bl == 'method.lib::L2CValue.L2CValue_int':
            if self.isConstant:
                self.Values.append(Value(self.CurrentValue, 'intC'))
                self.CurrentValue = 0
                self.isConstant = False
            else:
                self.Values.append(Value(self.CurrentValue, 'int'))
                self.CurrentValue = 0
        elif bl == 'method.lib::L2CValue.L2CValue_float':
            self.Values.append(Value(self.CurrentValue, 'float'))
            self.CurrentValue = 0
        elif bl == 'method.lib::L2CValue.L2CValue_bool':
            self.Values.append(Value(self.CurrentValue, 'bool'))
            self.CurrentValue = 0
        elif bl == 'method.lib::L2CValue.L2CValue_phx::Hash40':
            register = next((x for x in self.Registers if x.register == "x1"), None)
            self.Values.append(Value(Hash40(hex(register.value)), 'hash40'))
        elif bl == 'method.app::sv_animcmd.is_excute_lua_State':
            self.Values.append(Value('method.app::sv_animcmd.is_excute_lua_State', 'function'))
        elif bl == 'method.lib::L2CValue.operatorbool__const':
            #self.Values.append(Value(self.CurrentValue, 'bool'))
            if self.CurrentBlock:
                self.CurrentBlock.Functions.append(Function('method.lib::L2CValue.operatorbool__const', self.Values, self.CurrentAddress))
            else:
                self.Functions.append(Function('method.lib::L2CValue.operatorbool__const', self.Values, self.CurrentAddress))
            self.Values = []
            self.CurrentValue = 0
        elif bl == 'method.lib::L2CAgent.pop_lua_stack_int':
            self.Values.append(Value(self.CurrentValue, 'int'))
            self.CurrentValue = 0
        elif bl == 'method.lib::L2CValue._L2CValue' or bl == 'method.lib::L2CValue.as_integer__const' or bl == 'method.lib::L2CValue.L2CValue_int' or bl == 'method.lib::L2CAgent.push_lua_stack_lib::L2CValueconst' or bl == 'method.lib::L2CValue.as_integer__const' or bl == 'method.lib::L2CValue.as_number__const' or bl == 'method.lib::L2CValue.as_bool__const' or bl == 'method.lib::L2CAgent.clear_lua_stack':
            #Ignore
            None
        else:
            if self.CurrentBlock:
                self.CurrentBlock.Functions.append(Function(bl, self.Values, self.CurrentAddress))
            else:
                self.Functions.append(Function(bl, self.Values, self.CurrentAddress))
            self.Values = []
        
    def parse_b_le(self, b_le):
        None
    
    def parse_b_gt(self, b_gt):
        None

    def parse_tbz(self, tbz):
        op = self.Functions.pop()
        block = Block(op, int(tbz.split(',')[2].strip(), 16), self.CurrentAddress)

        if self.CurrentBlock:
            self.Blocks.append(self.CurrentBlock)
        self.CurrentBlock = block

    def parse_fmov(self, fmov):
        p = fmov.split(',')[0]
        f = fmov.split(',')[1]
        if f == 'wzr':
            f = '0'
        v = float(f)
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = v
        else:
            self.Registers.append(Register(p, v))
        self.CurrentValue = v

    def parse_ldr(self, ldr):
        p = ldr.split(',')[0].strip()
        r = ldr.split(',')[1].replace('[','').strip()
        if 'arg_' in r or 'local_' in r:
            return None
        if 'w' in p:
            #Constant enum
            v = ldr.split(',')[2].replace(']','')
            if v[0] == 'x':
                register = next((x for x in self.Registers if x.register == v.replace('x','w')), None)
                v = register.value
            else:
                v = int(v, 16)
            constant = next((x for x in Constants if x.index == int(v / 4) + 1), None)
            if constant:
                if constant.name != '':
                    self.CurrentValue = constant.name
                else:
                    self.CurrentValue = v
            else:
                self.CurrentValue = v
            self.isConstant = True
        else:
            #Float value
            v = 0
            if len(ldr.split(',')) < 3:
                return None
            if ldr.split(',')[2].replace(']','').strip()[0] == 'x':
                rn = next((x for x in self.Registers if x.register == ldr.split(',')[2].replace(']','').strip()), None)
                if rn:
                    v = rn.value
            else:
                v = int(ldr.split(',')[2].replace(']','').replace('!','').strip(), 16)
            register = next((x for x in self.Registers if x.register == r.replace('x', 'w') or x.register == r), None)
            if register:
                register.value += v
                if self.r2:
                    v = self.r2.cmd('s {0};pf f'.format(register.value))
                    v = float(v.split('=')[1].strip())
                    register2 = next((x for x in self.Registers if x.register == p.replace('x', 'w') or x.register == p), None)
                    if register2:
                        register2.value = v
                    else:
                        self.Registers.append(Register(p, v))
                    self.CurrentValue = v
            else:
                self.Registers.append(Register(p, v))
                if self.r2:
                    self.CurrentValue = self.r2.cmd('s {0};pf f'.format(v))

    def parse_orr(self, orr):
        p = orr.split(',')[0]
        v = orr.split(',')[1].strip()
        o = int(orr.split(',')[2].strip(), 16)
        if v == 'wzr':
            v = 0
        else:
            r = next((x for x in self.Registers if x.register == v),None)
            if r:
                v = r.value
        v = v | o
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = v
        else:
            self.Registers.append(Register(p, v))
        self.CurrentValue = v

    def parse_and(self, andd):
        p = andd.split(',')[0]
        v = andd.split(',')[1].strip()
        o = int(andd.split(',')[2].strip(), 16)
        if v == 'wzr':
            v = 0
        else:
            r = next((x for x in self.Registers if x.register == v),None)
            if r:
                v = r.value
            else:
                v = 0
        v = v & o
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = v
        else:
            self.Registers.append(Register(p, v))
        self.CurrentValue = v

    def Parse(self):
        for line, address in zip(self.lines, self.address):
            #print(line)
            t = line.split(' ')
            op = t[0]
            val = ''.join(t[1:])
            self.CurrentAddress = address

            if self.SubScript:
                self.SubScript.Values = self.Values
                self.SubScript.Parse()
                self.Values = self.SubScript.Values

                if self.CurrentBlock:
                    self.CurrentBlock.Functions.extend(self.SubScript.Functions)
                else:
                    self.Functions.extend(self.SubScript.Functions)

                self.SubScript = None

            if self.CurrentBlock:
                if int(address,16) == self.CurrentBlock.branch:
                    self.Functions.append(self.CurrentBlock)
                    if len(self.Blocks) == 0:
                        self.CurrentBlock = None
                    else:
                        self.CurrentBlock = self.Blocks.pop()

            if op == 'movz':
                self.parse_movz(val)
            elif op == 'movk':
                self.parse_movk(val)
            elif op == 'mov':
                self.parse_mov(val)
            elif op == 'cmp':
                self.parse_cmp(val)
            elif op == 'adrp':
                self.parse_adrp(val)
            elif op == 'ldr':
                self.parse_ldr(val)
            elif op == 'add':
                self.parse_add(val)
            elif op == 'bl':
                self.parse_bl(val)
            elif op == 'b.le':
                self.parse_b_le(val)
            elif op == 'b.gt':
                self.parse_b_gt(val)
            elif op == 'b.eq':
                self.parse_b_eq(val)
            elif op == 'b.ne':
                self.parse_b_ne(val)
            elif op == 'b':
                self.parse_b(val)
            elif op == 'tbz':
                self.parse_tbz(val)
            elif op == 'fmov':
                self.parse_fmov(val)
            elif op == 'orr':
                self.parse_orr(val)
            elif op == 'and':
                self.parse_and(val)
            elif op == 'b.lo':
                self.parse_b_lo(val)
    
    def print(self,depth):
        s = ''
        for fun_blk in self.Functions:
            s += fun_blk.print(0) 
        return s


class Parser:
    def __init__(self, r2, script, scriptName, sectionList = []):
        self.scriptName = scriptName
        print(self.scriptName)
        self.main = SubScript(r2, script, sectionList)
        self.main.Parse()
        

        #print(self.main.print())
    
    def Output(self):
        return self.main.print(0)