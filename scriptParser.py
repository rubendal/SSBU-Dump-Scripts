import re, ctypes
from hash40 import Hash40
from util import adjustr2Output, UseOpcode
import math
from hitboxes import Hitbox, Grab, Throw 

#Hitboxes
currentFrame = 0.0
fsm = 1.0
animcmdFrame = 0.0

def processToFrame(frame):
    global currentFrame, fsm, animcmdFrame
    frames = frame - animcmdFrame
    currentFrame += (fsm * frames)
    animcmdFrame = frame

def processFrames(frames):
    global currentFrame, fsm, animcmdFrame
    currentFrame += (fsm * frames)
    animcmdFrame += frames

class Constant:
    def __init__(self, index, name):
        self.index = index
        self.name = name

Constants = []
ci = 1
cfile = open('const_value_table_13.0.0.csv', 'r')
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
        self.ElseBlock = None

    def print(self,depth):
        if isinstance(self.condition, Function):
            s = ('\t' * depth) + 'if(' + self.condition.printCondition() +'){\n'
            for function in self.Functions:
                s += '{0}'.format(function.print(depth+1))
            s+= ('\t' * depth) + '}\n'
            if self.ElseBlock:
                s += self.ElseBlock.print(depth)
        else:
            
            s = self.condition.print(depth)
            for function in self.Functions:
                s += '{0}'.format(function.print(depth+1))
            s+= ('\t' * depth) + '}\n'
        return s

    def printAttacks(self,depth,hitboxes,grabs,throws):
        if isinstance(self.condition, Function):
            for function in self.Functions:
                function.printAttacks(depth+1,hitboxes,grabs,throws)
            if self.ElseBlock:
                self.ElseBlock.printAttacks(depth, hitboxes,grabs,throws)
        else:
            for function in self.Functions:
                function.printAttacks(depth+1, hitboxes,grabs,throws)

class ElseBlock:
    def __init__(self, branch, address = 0):
        self.Functions = []
        self.branch = branch
        self.address = address

    def print(self,depth):
        s=''
        if(len(self.Functions)>0):
            s = ('\t' * depth) + 'else{\n'
            for function in self.Functions:
                s += '{0}'.format(function.print(depth+1))
            s+= ('\t' * depth) + '}\n'
        return s

    def printAttacks(self,depth,hitboxes,grabs,throws):
        if(len(self.Functions)>0):
            for function in self.Functions:
                function.printAttacks(depth,hitboxes,grabs,throws)

class Loop:
    def __init__(self, iterator, functions, branch, address = 0):
        self.iterator = iterator
        self.Functions = functions
        self.branch = branch
        self.address = address

    def print(self,depth):
        s = ('\t' * depth) + 'for(' + self.iterator.iteratorPrint() + ' Iterations){\n'
        for function in self.Functions:
            s += '{0}'.format(function.print(depth + 1))
        s+= ('\t' * depth) + '}\n'
        return s

    def printAttacks(self,depth,hitboxes,grabs,throws):
        for i in range(int(self.iterator.getIterator())):
            for function in self.Functions:
                function.printAttacks(depth+1, hitboxes,grabs,throws)

class Function:
    def __init__(self, function, params, address = 0):
        self.function = function
        self.params = params
        self.address = address

    def print(self,depth):
        functionName = self.function.replace('Module__', 'Module::').replace('ModuleImpl__', 'ModuleImpl::').replace('Manager__', 'Manager::').split('_lua')[0].split('_impl')[0].split('_void')[0]
        #if 'method.' in functionName:
        #    functionName = functionName.split('.')[2]
        if functionName.startswith('methodapp'):
            functionName = ':'.join(functionName.split(':')[4:]).split('(')[0]
        s = ('\t' * depth) + '{0}('.format(functionName)
        fp = next((x for x in FunctionParam if x.function == functionName and x.length == len(self.params)), None)
        index = 0
        if functionName == 'ATTACK' and len(self.params) == 33:
            self.params.insert(12,Value('LUA_VOID', 'intC'))
            self.params.insert(12,Value('LUA_VOID', 'intC'))
            self.params.insert(12,Value('LUA_VOID', 'intC'))
            fp = next((x for x in FunctionParam if x.function == functionName and x.length == len(self.params)), None)
        for param in self.params:
            if fp:
                s += '{0}={1}, '.format(fp.params[index], param.print(0))
            else:
                s += '{0}, '.format(param.print(0))
            index += 1
        s = s.strip(', ') + ')\n'
        return s

    def printAttacks(self,depth,hitboxes,grabs,throws):
        global currentFrame, fsm, animcmdFrame
        functionName = self.function.replace('Module__', 'Module::').replace('ModuleImpl__', 'ModuleImpl::').replace('Manager__', 'Manager::').split('_lua')[0].split('_impl')[0].split('_void')[0]
        #if 'method.' in functionName:
        #    functionName = functionName.split('.')[2]
        if functionName.startswith('methodapp'):
            functionName = ':'.join(functionName.split(':')[4:]).split('(')[0]
        if(functionName == 'ATTACK' or functionName == 'ATTACK_IGNORE_THROW'):
            fp = next((x for x in FunctionParam if x.function == functionName and x.length == len(self.params)), None)
            paramList = []
            index = 0
            for param in self.params:
                if fp:
                    p = fp.params[index]
                    paramList.append(param.print(0))
                    if(p == 'ID'):
                        if functionName == 'ATTACK':
                            paramList.append('')
                        else:
                            paramList.append(True)
                    if p == 'Z' and fp.length == 33:
                        paramList.append(0)
                        paramList.append(0)
                        paramList.append(0)
                index += 1
            if len(paramList) > 0:
                for attack in hitboxes:
                    if attack.params[0] == self.params[0].value and attack.endFrame == 0:
                        attack.endFrame = math.ceil(currentFrame)
                hitboxes.append(Hitbox(paramList, currentFrame))
        elif(functionName == 'frame'):
            processToFrame(float(self.params[-1].value))
        elif(functionName == 'wait'):
            processFrames(float(self.params[-1].value))
        elif(functionName == 'FT_MOTION_RATE'):
            fsm = float(self.params[0].value)
            if currentFrame == 0:
                currentFrame = 1
                animcmdFrame = 1
        elif(functionName == 'MotionModule::set_rate'):
            fsm = 1 / float(self.params[0].value)
            if currentFrame == 0:
                currentFrame = 1
                animcmdFrame = 1
        elif(functionName == 'AttackModule::clear_all'):
            for attack in hitboxes:
                if attack.endFrame == 0:
                    attack.endFrame = math.ceil(currentFrame)
        elif(functionName == 'AttackModule::clear'):
            for attack in hitboxes:
                if attack.params[0] == self.params[0].value and attack.endFrame == 0:
                    attack.endFrame = math.ceil(currentFrame)
        elif(functionName == 'ATK_SET_SHIELD_SETOFF_MUL'):
            for attack in hitboxes:
                if attack.params[0] == self.params[0].value and attack.endFrame == 0:
                    attack.shieldStunMult = float(self.params[1].value)
        elif(functionName == 'AttackModule::set_add_reaction_frame'):
            for attack in hitboxes:
                if attack.params[0] == self.params[0].value and attack.endFrame == 0:
                    attack.addHitstun = int(self.params[1].value)
        elif(functionName == 'ATK_SET_SHIELD_SETOFF_MUL_arg3'):
            for attack in hitboxes:
                if (attack.params[0] == self.params[0].value or attack.params[0] == self.params[1].value) and attack.endFrame == 0:
                    attack.shieldStunMult = float(self.params[-1].value)
        elif(functionName == 'ATK_SET_SHIELD_SETOFF_MUL_arg4'):
            for attack in hitboxes:
                if (attack.params[0] == self.params[0].value or attack.params[0] == self.params[1].value or attack.params[0] == self.params[2].value) and attack.endFrame == 0:
                    attack.shieldStunMult = float(self.params[-1].value)
        elif(functionName == 'ATK_SET_SHIELD_SETOFF_MUL_arg5'):
            for attack in hitboxes:
                if (attack.params[0] == self.params[0].value or attack.params[0] == self.params[1].value or attack.params[0] == self.params[2].value or attack.params[0] == self.params[3].value) and attack.endFrame == 0:
                    attack.shieldStunMult = float(self.params[-1].value)
        #Grabs
        elif(functionName == 'CATCH'):
            fp = next((x for x in FunctionParam if x.function == functionName and x.length == len(self.params)), None)
            paramList = []
            index = 0
            for param in self.params:
                if fp:
                    p = fp.params[index]
                    paramList.append(param.print(0))
                    if p == 'Z' and fp.length == 8:
                        paramList.append(0)
                        paramList.append(0)
                        paramList.append(0)
                index += 1
            if len(paramList) > 0:
                for grab in grabs:
                    if grab.params[0] == self.params[0].value and grab.endFrame == 0:
                        grab.endFrame = math.ceil(currentFrame)
                grabs.append(Grab(paramList, currentFrame))
        elif(functionName == 'grab'):
            if(self.params[0].value == 'MA_MSC_CMD_GRAB_CLEAR_ALL'): #Clear all
                for grab in grabs:
                    if grab.endFrame == 0:
                        grab.endFrame = math.ceil(currentFrame)
            else:
                for grab in grabs:
                    if grab.params[0] == self.params[1].value and grab.endFrame == 0: #Clear specific id
                        grab.endFrame = math.ceil(currentFrame)
        #Throws
        elif(functionName == 'ATTACK_ABS'):
            fp = next((x for x in FunctionParam if x.function == functionName and x.length == len(self.params)), None)
            paramList = []
            index = 0
            for param in self.params:
                if fp:
                    p = fp.params[index]
                    paramList.append(param.print(0))
                index += 1
            if len(paramList) > 0:
                for throw in throws:
                    if throw.params[0] == self.params[0].value and throw.params[1] == self.params[1].value and throw.endFrame == 0:
                        throw.endFrame = math.ceil(currentFrame)
                throws.append(Throw(paramList, currentFrame))
        elif(functionName == 'ATK_HIT_ABS'):
            for throw in throws:
                if throw.params[0] == self.params[0].value and throw.endFrame == 0:
                    throw.endFrame = math.ceil(currentFrame)
        elif(functionName == 'FT_CATCH_STOP'):
            processFrames(float(self.params[0].value))

    def printCondition(self):
        if self.function in ['method.lib::L2CValue.operatorbool__const', 'method lib::L2CValue::operatorbool() const', 'methodlib::L2CValue::operatorbool()const']:
            s = ''
            for param in self.params:
                s += '{0}, '.format(param.print(0))
            s = s.strip(', ')
            return s
        else:
            s = '{0}('.format(self.function)
            for param in self.params:
                s += '{0}, '.format(param.print(0))
            s = s.strip(', ') + ')'
            return s

class Value:
    def __init__(self, value, vtype):
        self.value = value
        self.type = vtype

    def print(self,depth):
        if self.type == 'intC':
            if isinstance(self.value, int):
                self.value = str(self.value)
            return self.value.replace('"','')
        elif self.type == 'bool':
            if self.value == 1:
                return 'true'
            else:
                return 'false'
        elif self.type == 'function':
            if isinstance(self.value, Function):
                return self.value.print(0).strip()
            else:
                functionName = self.value.split('_lua')[0].split('_impl')[0].split('_void')[0]
                #if 'method.' in functionName:
                #    functionName = functionName.split('.')[2]
                if functionName.startswith('methodapp'):
                    functionName = ':'.join(functionName.split(':')[4:]).split('(')[0]
                return '{0}'.format(functionName)
        elif self.type == 'hash40':
            return self.value.getLabel()
        elif self.type == 'int':
            return int(self.value)
        else:
            return self.value

    def iteratorPrint(self):
        return str(self.value - 1)
    
    def getIterator(self):
        return self.value - 1

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
        self.PrevStack = []
        self.SubScript = None
        self.prevOperation = None
        self.isConstant = False
        self.CurrentValue = 0
        self.Variables = {}

        self.CurrentAddress = 0

        for json in script["ops"]:
            line = json["disasm"]
            address = hex(json["offset"])
            opCode = json["opcode"]
            testStr = re.search("str\.([a-z]|[A-Z]|[0-9]|_)+", line) #Replace string for hex value
            if testStr:
                line = opCode
            else:
                t = line.split(' ')
                op = t[0]
                val = ''.join(t[1:])

                if op != 'bl' and UseOpcode(val):
                    line = opCode

            self.lines.append(line)
            self.address.append(address)
    
    def parse_str(self, _str):
        p = _str.split(',')[0].strip()
        r = _str.split(',')[1].replace('[','').strip()
        v = "0"
        if len(_str.split(',')) > 2:
            v = _str.split(',')[2].replace('!','').replace(']','').strip()
        if r == 'sp':
            register = next((x for x in self.Registers if x.register == p), None)
            if register:
                self.Variables[v] = register.value

    def parse_movz(self, movz):
        p = movz.split(',')[0]
        h = movz.split(',')[1]
        if h == 'wzr':
            h = '0x0'
        if '::' in h:
            #Look in section table
            try:
                f = h.split(':')[2].replace('_phx','').replace('_lib','').replace('_void','')
                find = next((x for x in self.Sections if '::' in x.function and x.function.split(':')[2].split('(')[0] == f), None)
                if find:
                    v = find.num
            except:
                v = 0
        else:
            v = ctypes.c_int32(int(h, 16)).value
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = v
        else:
            self.Registers.append(Register(p, v))
        self.CurrentValue = v

    def parse_movn(self, movn):
        p = movn.split(',')[0]
        h = movn.split(',')[1]
        if h == 'wzr':
            h = '0x0'
        v = ctypes.c_int32(int(h, 16)).value
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = (v * -1) - 1
        else:
            self.Registers.append(Register(p, v))
        self.CurrentValue = (v * -1) - 1

    def parse_movk(self, movk):
        p = movk.split(',')[0]
        h = movk.split(',')[1].strip()
        if h == 'wzr':
            h = '0x0'
        v = ctypes.c_int32(int(h, 16)).value
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
                v = ctypes.c_int32(int(h, 16)).value
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
            if int(function.address,16) >= address:
                break
            index += 1
        #index = index-1
        l = self.Functions[index:]
        
        if index > 0:
            self.Functions = self.Functions[0:index]
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
        self.CurrentValue = v

    def parse_add(self, add):
        p = add.split(',')[0].strip()
        p2 = add.split(',')[1].strip()
        try:
            v = ctypes.c_int32(int(add.split(',')[2], 16)).value
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
        if '0x' in b:
            if self.CurrentBlock:
                self.CurrentBlock.ElseBlock = ElseBlock(int(b, 16), self.CurrentAddress)
        else:
            if self.CurrentBlock:
                if self.CurrentBlock.ElseBlock:
                    self.CurrentBlock.ElseBlock.Functions.append(Function(b, self.PrevStack, self.CurrentAddress))
                else:
                    self.CurrentBlock.Functions.append(Function(b, self.PrevStack, self.CurrentAddress))
            else:
                self.Functions.append(Function(b, self.PrevStack, self.CurrentAddress))
            self.PrevStack = []

    def parse_br(self, br):
        register = next((x for x in self.Registers if x.register == br), None)
        if register:
            if self.CurrentBlock:
                if self.CurrentBlock.ElseBlock:
                    self.CurrentBlock.ElseBlock.Functions.append(Function(hex(register.value), self.Values, self.CurrentAddress))
                else:
                    self.CurrentBlock.Functions.append(Function(hex(register.value), self.Values, self.CurrentAddress))
            else:
                self.Functions.append(Function(hex(register.value), self.Values, self.CurrentAddress))
        self.Values = []
                
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
                script = self.r2.cmdj('s {0};aF;pdfj'.format(hex(int(bl,16))))
                self.SubScript = SubScript(self.r2, script, self.Sections)
        elif bl in ['method.lib::L2CValue.L2CValue_int', 'method lib::L2CValue::L2CValue(int)','methodlib::L2CValue::L2CValue(int)']:
            if isinstance(self.CurrentValue,Value):
                self.CurrentValue = self.CurrentValue.value
            if self.isConstant:
                self.Values.append(Value(self.CurrentValue, 'intC'))
                self.CurrentValue = 0
                self.isConstant = False
            else:
                self.Values.append(Value(self.CurrentValue, 'int'))
                self.CurrentValue = 0
        elif bl in ['method.lib::L2CValue.L2CValue_float', 'method lib::L2CValue::L2CValue(float)', 'methodlib::L2CValue::L2CValue(float)']:
            if isinstance(self.CurrentValue,Value):
                self.CurrentValue = self.CurrentValue.value
            self.Values.append(Value(self.CurrentValue, 'float'))
            self.CurrentValue = 0
        elif bl in ['method.lib::L2CValue.L2CValue_bool', 'method lib::L2CValue::L2CValue(bool)', 'methodlib::L2CValue::L2CValue(bool)']:
            if isinstance(self.CurrentValue,Value):
                self.CurrentValue = self.CurrentValue.value
            self.Values.append(Value(self.CurrentValue, 'bool'))
            self.CurrentValue = 0
        elif bl in ['method.lib::L2CValue.L2CValue_phx::Hash40', 'method lib::L2CValue::L2CValue(phx::Hash40)', 'methodlib::L2CValue::L2CValue(phx::Hash40)']:
            register = next((x for x in self.Registers if x.register == "x1"), None)
            self.Values.append(Value(Hash40(hex(register.value)), 'hash40'))
        elif bl in ['method.app::sv_animcmd.is_excute_lua_State', 'method app::sv_animcmd::is_excute(lua_State*)', 'methodapp::sv_animcmd::is_excute(lua_State*)']:
            self.Values.append(Value(bl, 'function'))
        elif bl in ['method.lib::L2CValue.operatorbool__const','method lib::L2CValue::operator bool() const', 'methodlib::L2CValue::operator bool()const']:
            if self.CurrentBlock:
                if self.CurrentBlock.ElseBlock:
                    self.CurrentBlock.ElseBlock.Functions.append(Function(bl, self.Values, self.CurrentAddress))
                else:
                    self.CurrentBlock.Functions.append(Function(bl, self.Values, self.CurrentAddress))
            else:
                self.Functions.append(Function(bl, self.Values, self.CurrentAddress))
            self.Values = []
            self.CurrentValue = 0
        elif bl in ['method.app::lua_bind.WorkModule__is_flag_impl_app::BattleObjectModuleAccessor__int', 'method app::lua_bind.WorkModule__is_flag_impl_app::BattleObjectModuleAccessor(int)', 'methodapp::lua_bind.WorkModule__is_flag_impl_app::BattleObjectModuleAccessor(int)']:
            l = self.Values
            self.Values = []
            self.Values.append(Value(Function(bl, l, self.CurrentAddress), 'function'))
        elif bl in ['method.lib::L2CValue.L2CValue_long', 'method lib::L2CValue::L2CValue(long)', 'methodlib::L2CValue::L2CValue(long)']:
            self.CurrentValue = 0
        elif bl in ['method.app::lua_bind.WorkModule__get_int64_impl_app::BattleObjectModuleAccessor__int', 'method app::lua_bind.WorkModule__get_int64_impl_app::BattleObjectModuleAccessor(int)','methodapp::lua_bind.WorkModule__get_int64_impl_app::BattleObjectModuleAccessor(int)','methodapp::lua_bind::WorkModule__get_int64_impl(app::BattleObjectModuleAccessor*,int)']:
            self.CurrentValue = 0
        elif bl in ['method.lib::L2CAgent.pop_lua_stack_int', 'method lib::L2CAgent::pop_lua_stack(int)', 'methodlib::L2CAgent::pop_lua_stack(int)']:
            #self.Values.append(Value(self.CurrentValue, 'int'))
            #self.CurrentValue = 0
            None
        elif bl in ['method.lib::L2CAgent.clear_lua_stack', 'method lib::L2CAgent::clear_lua_stack()', 'methodlib::L2CAgent::clear_lua_stack()']:
            self.PrevStack = self.Values
            self.Values = []
        elif bl in ['method.lib::L2CValue.as_integer__const', 'method lib::L2CValue::as_integer()', 'methodlib::L2CValue::as_integer()const']:
            self.CurrentValue = Value(self.CurrentValue, 'int')
        elif bl in ['method.lib::L2CValue.as_number__const', 'method lib::L2CValue::as_number()', 'methodlib::L2CValue::as_number()const']:
            self.CurrentValue = Value(self.CurrentValue, 'float')
        elif bl in ['method.lib::L2CValue.as_bool__const', 'method lib::L2CValue::as_bool()', 'methodlib::L2CValue::as_bool()const']:
            self.CurrentValue = Value(self.CurrentValue, 'bool')
        elif bl in ['method.lib::L2CValue.L2CValue_long', 'method lib::L2CValue.L2CValue(long)', 'methodlib::L2CValue.L2CValue(long)']:
            #self.CurrentValue = Value(self.CurrentValue, 'long')
            None
        elif bl in ['method.lib::L2CValue._L2CValue', 'method lib::L2CValue::~L2CValue()', 'methodlib::L2CValue::~L2CValue()'] or bl in ['method.lib::L2CAgent.push_lua_stack_lib::L2CValueconst','method lib::L2CAgent.push_lua_stack_lib::L2CValue const','methodlib::L2CAgent::push_lua_stack(lib::L2CValueconst&)']:
            #Ignore
            None
        #elif bl == 'method.app::sv_animcmd.frame_lua_State__float' or bl == 'method.app::sv_animcmd.wait_lua_State__float':
        #    if self.CurrentBlock:
        #        self.CurrentBlock.Functions.append(Function(bl, self.PrevStack, self.CurrentAddress))
        #    else:
        #        self.Functions.append(Function(bl, self.PrevStack, self.CurrentAddress))
        #    self.PrevStack = []
        else:
            if len(self.Values) > 0:
                if self.CurrentBlock:
                    if self.CurrentBlock.ElseBlock:
                        self.CurrentBlock.ElseBlock.Functions.append(Function(bl, self.Values, self.CurrentAddress))
                    else:
                        self.CurrentBlock.Functions.append(Function(bl, self.Values, self.CurrentAddress))
                else:
                    self.Functions.append(Function(bl, self.Values, self.CurrentAddress))
                self.Values = []
            else:
                if self.CurrentBlock:
                    if self.CurrentBlock.ElseBlock:
                        self.CurrentBlock.ElseBlock.Functions.append(Function(bl, self.PrevStack, self.CurrentAddress))
                    else:
                        self.CurrentBlock.Functions.append(Function(bl, self.PrevStack, self.CurrentAddress))
                else:
                    self.Functions.append(Function(bl, self.PrevStack, self.CurrentAddress))
                self.PrevStack = []
        
    def parse_b_le(self, b_le):
        None
    
    def parse_b_gt(self, b_gt):
        None

    def parse_tbz(self, tbz):
        op = None
        if self.CurrentBlock:
            if self.CurrentBlock.ElseBlock:
                op = self.CurrentBlock.ElseBlock.Functions.pop()
            else:
                op = self.CurrentBlock.Functions.pop()
        else:
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
        v = round(float(f),3)
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
        if 'sp' in r:
            #Variable
            v = "0"
            if len(ldr.split(',')) > 2:
                v = ldr.split(',')[2].replace('!','').replace(']','').strip()
            register = next((x for x in self.Registers if x.register == p), None)
            varValue = 0
            if v in self.Variables:
                varValue = self.Variables[v]
            if register:
                register.value = varValue
            else:
                self.Registers.append(Register(p, varValue))
            self.CurrentValue = varValue
        elif 'w' in p:
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
            #Float/Integer value
            format = 'f'
            if 'x' in p:
                format = 'i'
            v = 0
            pr = ''

            if len(ldr.split(',')) < 3:
                pr = r.replace(']','')
            else:
                pr = ldr.split(',')[2].replace(']','').strip()

            if pr == 'sp' or 'sp' in pr:
                return None

            if '::' in pr: #Symbol
                #Look in section table
                try:
                    f = pr.split(':')[2].replace('_phx','').replace('_lib','').replace('_void','')
                    find = next((x for x in self.Sections if '::' in x.function and x.function.split(':')[2].split('(')[0] == f), None)
                    nr = next((x for x in self.Registers if x.register == 'x8'), None)
                    if find:
                        #v = find.num + self.CurrentValue
                        if nr:
                            v = find.num + nr.value
                        else:
                            v = find.num + self.CurrentValue
                        v = adjustr2Output(self.r2.cmd('s {0};pf {1}'.format(hex(v), format)))
                        if format == 'f':
                            v = round(float(v.split('=')[1].strip()),3)
                        else:
                            v = ctypes.c_int32(int(v.split('=')[1].strip())).value
                        register2 = next((x for x in self.Registers if x.register == p or x.register == p.replace('x', 'w')), None)
                        if register2:
                            register2.value = v
                        else:
                            self.Registers.append(Register(p, v))
                        self.CurrentValue = v
                        return None
                except:
                    return None
            else:
                if pr[0] == 'x':
                    rn = next((x for x in self.Registers if x.register == pr), None)
                    if rn:
                        v = rn.value
                else:
                    v = ctypes.c_int32(int(pr.replace('!','').strip(), 16)).value
            register = next((x for x in self.Registers if x.register == r), None)
            if register:
                register.value += v
                if self.r2:
                    v = adjustr2Output(self.r2.cmd('s {0};pf {1}'.format(register.value, format)))
                    if format == 'f':
                        v = round(float(v.split('=')[1].strip()),3)
                    else:
                        v = ctypes.c_int32(int(v.split('=')[1].strip())).value
                    register2 = next((x for x in self.Registers if x.register == p or x.register == p.replace('x', 'w')), None)
                    if register2:
                        register2.value = v
                    else:
                        self.Registers.append(Register(p, v))
                    self.CurrentValue = v
            else:
                register = next((x for x in self.Registers if x.register == r.replace('x','w').replace(']','')), None)
                if register:
                    register.value = v
                    if self.r2:
                        v = adjustr2Output(self.r2.cmd('s {0};pf {1}'.format(register.value, format)))
                        if format == 'f':
                            v = round(float(v.split('=')[1].strip()),3)
                        else:
                            v = ctypes.c_int32(int(v.split('=')[1].strip())).value
                        register2 = next((x for x in self.Registers if x.register == p or x.register == p.replace('x', 'w')), None)
                        if register2:
                            register2.value = v
                        else:
                            self.Registers.append(Register(p, v))
                        self.CurrentValue = v
                else:
                    if self.r2:
                        v = adjustr2Output(self.r2.cmd('s {0};pf {1}'.format(v, format)))
                        if format == 'f':
                            self.CurrentValue = round(float(v.split('=')[1].strip()),3)
                            self.Registers.append(Register(p, self.CurrentValue))
                        else:
                            self.CurrentValue = ctypes.c_int32(int(v.split('=')[1].strip())).value
                            self.Registers.append(Register(p, self.CurrentValue))

    def parse_orr(self, orr):
        p = orr.split(',')[0]
        v = orr.split(',')[1].strip()
        o = ctypes.c_int32(int(orr.split(',')[2].strip(), 16)).value
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
        o = ctypes.c_int32(int(andd.split(',')[2].strip(), 16)).value
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
            t = line.replace('sym ', 'method ').split(' ')
            op = t[0]
            val = ''.join(t[1:])
            self.CurrentAddress = address

            if self.SubScript:
                self.SubScript.Values = self.Values
                self.SubScript.Parse()
                self.Values = self.SubScript.Values

                if self.CurrentBlock:
                    if self.CurrentBlock.ElseBlock:
                        self.CurrentBlock.ElseBlock.Functions.extend(self.SubScript.Functions)
                    else:
                        self.CurrentBlock.Functions.extend(self.SubScript.Functions)
                else:
                    self.Functions.extend(self.SubScript.Functions)

                self.SubScript = None

            if self.CurrentBlock:
                branch = self.CurrentBlock.branch
                if self.CurrentBlock.ElseBlock:
                    branch = self.CurrentBlock.ElseBlock.branch
                if int(address,16) == branch:
                    if len(self.Blocks) == 0:
                        self.Functions.append(self.CurrentBlock)
                        self.CurrentBlock = None
                    else:
                        while len(self.Blocks) > 0:
                            block = self.CurrentBlock
                            self.CurrentBlock = self.Blocks.pop()
                            if self.CurrentBlock.ElseBlock:
                                self.CurrentBlock.ElseBlock.Functions.append(block)
                            else:
                                self.CurrentBlock.Functions.append(block)
                            branch = self.CurrentBlock.branch
                            if self.CurrentBlock.ElseBlock:
                                branch = self.CurrentBlock.ElseBlock.branch
                            if int(address,16) < branch:
                                break
                        if len(self.Blocks) == 0:
                            self.Functions.append(self.CurrentBlock)
                            self.CurrentBlock = None
                        

            if op == 'movz':
                self.parse_movz(val)
            elif op == 'movk':
                self.parse_movk(val)
            elif op == 'mov':
                self.parse_mov(val)
            elif op == 'movn':
                self.parse_movn(val)
            elif op == 'cmp':
                self.parse_cmp(val)
            elif op == 'adrp':
                self.parse_adrp(val)
            elif op == 'str':
                self.parse_str(val)
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
            elif op == 'br':
                self.parse_br(val)
    
    def print(self,depth):
        s = ''
        for fun_blk in self.Functions:
            s += fun_blk.print(0)
        if self.CurrentBlock:
            for fun_blk in self.CurrentBlock.Functions:
                s += fun_blk.print(0)
        return s

    def printAttacks(self,depth,hitboxes,grabs,throws):
        s = ''
        for fun_blk in self.Functions:
            fun_blk.printAttacks(0, hitboxes,grabs,throws) 
        return s


class Parser:
    def __init__(self, r2, script, address, scriptName, sectionList = []):
        self.scriptName = scriptName
        #print(self.scriptName + ' - ' + address)

        self.hitboxes = []
        self.grabs = []
        self.throws = []

        self.main = SubScript(r2, script, sectionList)
        self.main.Parse()

    
    def Output(self):
        return self.main.print(0)

    def GetHitboxes(self):
        global currentFrame, fsm, animcmdFrame

        currentFrame = 0.0
        fsm = 1.0
        animcmdFrame = 0.0

        self.main.printAttacks(0, self.hitboxes, self.grabs, self.throws)

        return {
            'hitboxes': self.hitboxes,
            'grabs': self.grabs,
            'throws': self.throws
        }