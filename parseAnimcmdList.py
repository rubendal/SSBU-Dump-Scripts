from article import Article, ScriptHash
from hash40 import Hash40
import re
from util import UseOpcode

class Register:
    def __init__(self, register, value):
        self.register = register
        self.value = value

class ArticleBranch:
    def __init__(self, article, branch = 0):
        self.article = article
        self.branch = branch

class Issue:
    def __init__(self, hash, issue):
        self.hash = hash
        self.issue = issue


class ParseAnimcmdList:
    def AddArticle(self, article, branch):
        branch = int(branch, 16)
        self.Articles = [x for x in self.Articles if x.branch != branch]
        self.Articles.append(ArticleBranch(article, branch))

    def RemoveArticle(self, article):
        self.Articles = [x for x in self.Articles if x.article != article]

    def parse_movz(self, movz):
        p = movz.split(',')[0]
        v = int(movz.split(',')[1], 16)
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = v
        else:
            self.Registers.append(Register(p, v))

    def parse_movk(self, movk):
        p = movk.split(',')[0]
        v = int(movk.split(',')[1].strip(), 16)
        bs = int(movk.split(',')[2].strip().replace('lsl', ''))
        v = v << bs
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value += v
        else:
            self.Registers.append(Register(p, v))

    def parse_cmp(self, cmp):
        None

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
                else:
                    px2 = next((x for x in self.Registers if x.register == "x2"), None)
                    if px2:
                        self.Issues.append(Issue(Hash40(hex(px2.value)), add.split(',')[2]))
                    self.hasIssue = True
            except:
                px2 = next((x for x in self.Registers if x.register == "x2"), None)
                if px2:
                    self.Issues.append(Issue(Hash40(hex(px2.value)), add.split(',')[2]))
                self.hasIssue = True
        
    def parse_b(self, b):
        #Set article scripts
        if len(self.Hashes) > 0:
            self.ArticleScripts.append(Article(Hash40(hex(self.CurrentArticle)), self.Hashes))
        self.RemoveArticle(self.CurrentArticle)
        self.Hashes = []
                
    def parse_b_ne(self, b_ne):
        p = "x9"
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            self.AddArticle(register.value, b_ne)
            self.CurrentArticle = register.value

    def parse_b_eq(self, b_eq):
        p = "x9"
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            self.AddArticle(register.value, b_eq)

    def parse_bl(self, bl):
        if "::Hash40" in bl:
            if not self.hasIssue:
                px1 = next((x for x in self.Registers if x.register == "x1"), None)
                px2 = next((x for x in self.Registers if x.register == "x2"), None)
                if px1 and px2:
                    self.Hashes.append(ScriptHash(Hash40(hex(px2.value)), px1.value))
            else:
                self.hasIssue = False
        elif "0x" in bl:
            text = self.r2.cmd("s {0};af;pdf".format(bl))
            self.Subscript = ParseAnimcmdList(self.r2, text, self.Sections)

    def parse_b_le(self, b_le):
        p = "x9"
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            self.AddArticle(register.value, b_le)
    

    def parse_b_gt(self, b_gt):
        p = "x9"
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            self.AddArticle(register.value, b_gt)

    def __init__(self, r2, text, sectionList = []):
        self.r2 = r2
        self.Registers = []
        self.Articles = []
        self.Hashes = []
        self.CurrentArticle = None
        self.ArticleScripts = []
        self.hasIssue = False
        self.Issues = []
        self.Sections = []
        self.Subscript = None
        ignoreLine = True
        self.Sections = sectionList
        self.lines = []
        self.address = []
        for l in text.split('\r'):
            if len(l) > 0:
                if l[0] == '|':
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

        
        for line, address in zip(self.lines, self.address):
            #print(line)

            if self.Subscript:
                self.Hashes.extend(self.Subscript.Hashes)
                self.Subscript = None

            find = next((x for x in self.Articles if address is not None and x.branch == int(address, 16)), None)
            if find:
                self.CurrentArticle = find.article
            t = line.split(' ')
            op = t[0]
            val = ''.join(t[1:])
            if op == 'movz':
                self.parse_movz(val)
            elif op == 'movk':
                self.parse_movk(val)
            elif op == 'cmp':
                self.parse_cmp(val)
            elif op == 'adrp':
                self.parse_adrp(val)
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
            

        #Check if list has hashes and CurrentArticle has a value, this happens when there is a Code XREF on Radare output
        #Since branch doesn't close data needs to be set here if not it won't be dumped
        if len(self.Hashes) > 0 and self.CurrentArticle is not None:
            self.ArticleScripts.append(Article(Hash40(hex(self.CurrentArticle)), self.Hashes))

class ParseAnimcmdListJ:
    def AddArticle(self, article, branch):
        branch = int(branch, 16)
        self.Articles = [x for x in self.Articles if x.branch != branch]
        self.Articles.append(ArticleBranch(article, branch))

    def RemoveArticle(self, article):
        self.Articles = [x for x in self.Articles if x.article != article]

    def parse_movz(self, movz):
        p = movz.split(',')[0]
        v = int(movz.split(',')[1], 16)
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value = v
        else:
            self.Registers.append(Register(p, v))

    def parse_movk(self, movk):
        p = movk.split(',')[0]
        v = int(movk.split(',')[1].strip(), 16)
        bs = int(movk.split(',')[2].strip().replace('lsl', ''))
        v = v << bs
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            register.value += v
        else:
            self.Registers.append(Register(p, v))

    def parse_cmp(self, cmp):
        None

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
                else:
                    px2 = next((x for x in self.Registers if x.register == "x2"), None)
                    if px2:
                        self.Issues.append(Issue(Hash40(hex(px2.value)), add.split(',')[2]))
                    self.hasIssue = True
            except:
                px2 = next((x for x in self.Registers if x.register == "x2"), None)
                if px2:
                    self.Issues.append(Issue(Hash40(hex(px2.value)), add.split(',')[2]))
                self.hasIssue = True
        
    def parse_b(self, b):
        #Set article scripts
        if len(self.Hashes) > 0:
            self.ArticleScripts.append(Article(Hash40(hex(self.CurrentArticle)), self.Hashes))
        self.RemoveArticle(self.CurrentArticle)
        self.Hashes = []
                
    def parse_b_ne(self, b_ne):
        p = "x9"
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            self.AddArticle(register.value, b_ne)
            self.CurrentArticle = register.value

    def parse_b_eq(self, b_eq):
        p = "x9"
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            self.AddArticle(register.value, b_eq)

    def parse_bl(self, bl):
        if "::Hash40" in bl:
            if not self.hasIssue:
                px1 = next((x for x in self.Registers if x.register == "x1"), None)
                px2 = next((x for x in self.Registers if x.register == "x2"), None)
                if px1 and px2:
                    self.Hashes.append(ScriptHash(Hash40(hex(px2.value)), px1.value))
            else:
                self.hasIssue = False
        elif "0x" in bl:
            text = self.r2.cmdj("s {0};af;pdfj".format(bl))
            self.Subscript = ParseAnimcmdListJ(self.r2, text, self.Sections)

    def parse_b_le(self, b_le):
        p = "x9"
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            self.AddArticle(register.value, b_le)
    

    def parse_b_gt(self, b_gt):
        p = "x9"
        register = next((x for x in self.Registers if x.register == p), None)
        if register:
            self.AddArticle(register.value, b_gt)

    def __init__(self, r2, json, sectionList = []):
        self.r2 = r2
        self.Registers = []
        self.Articles = []
        self.Hashes = []
        self.CurrentArticle = None
        self.ArticleScripts = []
        self.hasIssue = False
        self.Issues = []
        self.Sections = []
        self.Subscript = None
        self.Sections = sectionList
        self.lines = []
        self.address = []

        for op in json["ops"]:
            address = op["offset"]
            line = op["disasm"]
            opcode = op["opcode"]


            if self.Subscript:
                self.Hashes.extend(self.Subscript.Hashes)
                self.Subscript = None

            find = next((x for x in self.Articles if address is not None and x.branch == address), None)
            if find:
                self.CurrentArticle = find.article
            t = line.split(' ')
            op = t[0]
            val = ''.join(t[1:])

            if(op != 'bl' and UseOpcode(val)):
                t = opcode.split(' ')
                val = ''.join(t[1:])

            
            if op == 'movz':
                self.parse_movz(val)
            elif op == 'movk':
                self.parse_movk(val)
            elif op == 'cmp':
                self.parse_cmp(val)
            elif op == 'adrp':
                self.parse_adrp(val)
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
            

        #Check if list has hashes and CurrentArticle has a value, this happens when there is a Code XREF on Radare output
        #Since branch doesn't close data needs to be set here if not it won't be dumped
        if len(self.Hashes) > 0 and self.CurrentArticle is not None:
            self.ArticleScripts.append(Article(Hash40(hex(self.CurrentArticle)), self.Hashes))
