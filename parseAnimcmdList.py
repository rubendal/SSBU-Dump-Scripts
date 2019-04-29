from article import Article, ScriptHash
from hash40 import Hash40

class Pointer:
    def __init__(self, pointer, value):
        self.pointer = pointer
        self.value = value

Pointers = []
Articles = []
Hashes = []
CurrentArticle = None
ArticleScripts = []
hasIssue = False
Issues = []
lastArticle = True

class Issue:
    def __init__(self, hash, issue):
        self.hash = hash
        self.issue = issue

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
    global CurrentArticle
    p = cmp.split(',')[1].strip()
    pointer = next((x for x in Pointers if x.pointer == p), None)
    if pointer:
        Articles.append(pointer.value)

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
        px2 = next((x for x in Pointers if x.pointer == "x2"), None)
        if px2:
            Issues.append(Issue(Hash40(hex(px2.value)), add.split(',')[2]))
        hasIssue = True
    
    

def parse_bl(bl):
    global CurrentArticle, hasIssue, Hashes
    if "L2CFighterAnimcmd" in bl:
        None
        #Tried to avoid reading more stuff but it doesn't work on all characters... so putting everything on character folder lol
        #if CurrentArticle is None:
            #Set
        #    CurrentArticle = Articles[len(Articles)-1]
        #else:
        #    #Set article scripts
        #    ArticleScripts.append(Article(Hash40(hex(CurrentArticle)), Hashes))
        #    Articles.remove(CurrentArticle)
        #    Hashes = []
        #    if len(Articles) > 0:
        #        CurrentArticle = Articles[len(Articles) - 1]
    elif "::Hash40" in bl:
        if not hasIssue:
            px1 = next((x for x in Pointers if x.pointer == "x1"), None)
            px2 = next((x for x in Pointers if x.pointer == "x2"), None)
            if px1 and px2:
                Hashes.append(ScriptHash(Hash40(hex(px2.value)), px1.value))
        else:
            hasIssue = False

class ParseAnimcmdList:
    def __init__(self, text):
        global CurrentArticle, ArticleScripts, Pointers, Articles, Hashes, hasIssue, Issues
        Pointers = []
        Articles = []
        Hashes = []
        CurrentArticle = None
        ArticleScripts = []
        hasIssue = False
        Issues = []
        ignoreLine = True
        self.lines = []
        for l in text.split('\r'):
            if len(l) > 0:
                if l[0] == '|':
                    if ignoreLine:
                        ignoreLine = False
                    else:
                        a = l.split(';')[0].strip().split("  ")
                        line = a[len(a)-1][1:]
                        self.lines.append(line)
        
        for line in self.lines:
            #print(line)
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
        
        #Set last Article
        #if CurrentArticle:
            #ArticleScripts.append(Article(Hash40(hex(CurrentArticle)), Hashes))

        ArticleScripts.append(Article(Hash40(hex(min(Articles))), Hashes))

        self.Issues = Issues
        self.ArticleScripts = ArticleScripts
