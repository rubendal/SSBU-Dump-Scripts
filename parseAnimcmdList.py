from article import Article, ScriptHash
from hash40 import Hash40
import re

class Pointer:
    def __init__(self, pointer, value):
        self.pointer = pointer
        self.value = value

class ArticleBranch:
    def __init__(self, article, branch = 0):
        self.article = article
        self.branch = branch

Pointers = []
Articles = []
Hashes = []
CurrentArticle = None
ArticleScripts = []
hasIssue = False
Issues = []
Sections = []

class Issue:
    def __init__(self, hash, issue):
        self.hash = hash
        self.issue = issue

def AddArticle(article, branch):
    global Articles
    branch = int(branch, 16)
    Articles = [x for x in Articles if x.branch != branch]
    Articles.append(ArticleBranch(article, branch))

def RemoveArticle(article):
    global Articles
    Articles = [x for x in Articles if x.article != article]

def parse_movz(movz):
    p = movz.split(',')[0]
    v = int(movz.split(',')[1], 16)
    pointer = next((x for x in Pointers if x.pointer == p), None)
    if pointer:
        pointer.value = v
    else:
        Pointers.append(Pointer(p, v))

def parse_movk(movk):
    p = movk.split(',')[0]
    v = int(movk.split(',')[1].strip(), 16)
    bs = int(movk.split(',')[2].strip().replace('lsl', ''))
    v = v << bs
    pointer = next((x for x in Pointers if x.pointer == p), None)
    if pointer:
        pointer.value += v
    else:
        Pointers.append(Pointer(p, v))

def parse_cmp(cmp):
    None

def parse_adrp(adrp):
    p = adrp.split(',')[0].strip()
    v = int(adrp.split(',')[1], 16)
    pointer = next((x for x in Pointers if x.pointer == p), None)
    if pointer:
        pointer.value = v
    else:
        Pointers.append(Pointer(p, v))

def parse_add(add):
    global hasIssue
    p = add.split(',')[0].strip()
    p2 = add.split(',')[1].strip()
    try:
        v = int(add.split(',')[2], 16)
        pointer = next((x for x in Pointers if x.pointer == p), None)
        if pointer:
            pointer.value += v
        else:
            Pointers.append(Pointer(p, v))
    except:
        try:
            f = add.split(':')[2].replace('_phx','').replace('_lib','').replace('_void','')
            find = next((x for x in Sections if '::' in x.function and x.function.split(':')[2].split('(')[0] == f), None)
            if find:
                v = find.num
                pointer = next((x for x in Pointers if x.pointer == p), None)
                if pointer:
                    pointer.value += v
                else:
                    Pointers.append(Pointer(p, v))
            else:
                px2 = next((x for x in Pointers if x.pointer == "x2"), None)
                if px2:
                    Issues.append(Issue(Hash40(hex(px2.value)), add.split(',')[2]))
                hasIssue = True
        except:
            px2 = next((x for x in Pointers if x.pointer == "x2"), None)
            if px2:
                Issues.append(Issue(Hash40(hex(px2.value)), add.split(',')[2]))
            hasIssue = True
    
def parse_b(b):
    global CurrentArticle, Hashes
    #Set article scripts
    if len(Hashes) > 0:
        ArticleScripts.append(Article(Hash40(hex(CurrentArticle)), Hashes))
    RemoveArticle(CurrentArticle)
    Hashes = []
            
def parse_b_ne(b_ne):
    global CurrentArticle
    p = "x9"
    pointer = next((x for x in Pointers if x.pointer == p), None)
    if pointer:
        AddArticle(pointer.value, b_ne)
        CurrentArticle = pointer.value

def parse_b_eq(b_eq):
    p = "x9"
    pointer = next((x for x in Pointers if x.pointer == p), None)
    if pointer:
        AddArticle(pointer.value, b_eq)

def parse_bl(bl):
    global hasIssue, Hashes
    if "::Hash40" in bl:
        if not hasIssue:
            px1 = next((x for x in Pointers if x.pointer == "x1"), None)
            px2 = next((x for x in Pointers if x.pointer == "x2"), None)
            if px1 and px2:
                Hashes.append(ScriptHash(Hash40(hex(px2.value)), px1.value))
        else:
            hasIssue = False

def parse_b_le(b_le):
    p = "x9"
    pointer = next((x for x in Pointers if x.pointer == p), None)
    if pointer:
        AddArticle(pointer.value, b_le)
  

def parse_b_gt(b_gt):
    p = "x9"
    pointer = next((x for x in Pointers if x.pointer == p), None)
    if pointer:
        AddArticle(pointer.value, b_gt)


class ParseAnimcmdList:
    def __init__(self, text, sectionList = []):
        global CurrentArticle, ArticleScripts, Pointers, Articles, Hashes, hasIssue, Issues, Sections
        Pointers = []
        Articles = []
        Hashes = []
        CurrentArticle = None
        ArticleScripts = []
        hasIssue = False
        Issues = []
        ignoreLine = True
        Sections = sectionList
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
            find = next((x for x in Articles if address is not None and x.branch == int(address, 16)), None)
            if find:
                CurrentArticle = find.article
            t = line.split(' ')
            op = t[0]
            val = ''.join(t[1:])
            if op == 'movz':
                parse_movz(val)
            elif op == 'movk':
                parse_movk(val)
            elif op == 'cmp':
                parse_cmp(val)
            elif op == 'adrp':
                parse_adrp(val)
            elif op == 'add':
                parse_add(val)
            elif op == 'bl':
                parse_bl(val)
            elif op == 'b.le':
                parse_b_le(val)
            elif op == 'b.gt':
                parse_b_gt(val)
            elif op == 'b.eq':
                parse_b_eq(val)
            elif op == 'b.ne':
                parse_b_ne(val)
            elif op == 'b':
                parse_b(val)
            

        #Check if list has hashes and CurrentArticle has a value, this happens when there is a Code XREF on Radare output
        #Since branch doesn't close data needs to be set here if not it won't be dumped
        if len(Hashes) > 0 and CurrentArticle is not None:
            ArticleScripts.append(Article(Hash40(hex(CurrentArticle)), Hashes))

        self.Issues = Issues
        self.ArticleScripts = ArticleScripts
