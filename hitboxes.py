import math
import re

class Hitbox:
    def __init__(self, params, startFrame):
        self.params = params
        self.startFrame = math.ceil(startFrame)
        self.endFrame = 0
        self.shieldStunMult = 1
        self.addHitstun = 0

        if self.startFrame == 0:
            self.startFrame = 1

    def print(self, article, scriptName):
        l = self.params.copy()
        l.insert(0,article)
        l.insert(1,scriptName)
        l.insert(3,self.startFrame)
        l.insert(4,self.endFrame)
        l.append(self.shieldStunMult)
        l.append(self.addHitstun)
        return re.sub(r'hash40\("([a-zA-Z0-9_]+)"\)', r'\1',','.join(map(str, l)))

class Grab:
    def __init__(self, params, startFrame):
        self.params = params
        self.startFrame = math.ceil(startFrame)
        self.endFrame = 0

        if self.startFrame == 0:
            self.startFrame = 1

    def print(self, article, scriptName):
        l = self.params.copy()
        l.insert(0,article)
        l.insert(1,scriptName)
        l.insert(3,self.startFrame)
        l.insert(4,self.endFrame)
        return re.sub(r'hash40\("([a-zA-Z0-9_]+)"\)', r'\1',','.join(map(str, l)))

class Throw:
    def __init__(self, params, startFrame):
        self.params = params
        self.startFrame = math.ceil(startFrame)
        self.endFrame = 0

        if self.startFrame == 0:
            self.startFrame = 1

    def print(self, article, scriptName):
        l = self.params.copy()
        l.insert(0,article)
        l.insert(1,scriptName)
        l.insert(4,self.endFrame)
        return re.sub(r'hash40\("([a-zA-Z0-9_]+)"\)', r'\1',','.join(map(str, l)))