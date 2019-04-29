from article import Article, ScriptHash
from hash40 import Hash40

class ParseAnimcmdStart:
    def __init__(self, text):
        self.lines = []
        for l in text.split('\r'):
            if len(l) > 0 and l != '\n':
                a = l.split(';')[0].strip().split("  ")
                line = a[len(a)-1][1:]
                self.lines.append(line)
        
        #Process
        self.address = None
        for line in self.lines:
            #print(line)
            t = line.split(' ')
            op = t[0]
            val = ''.join(t[1:])
            if op == 'bl':
                if "0x" in val or "fcn." in val:
                    self.address = int(val.replace("fcn.", "0x"), 16)
                    break
