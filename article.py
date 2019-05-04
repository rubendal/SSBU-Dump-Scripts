from hash40 import Hash40

class NameHash40:
    def __init__(self, name, hash40):
            self.name = name
            self.hash40 = hash40


HashList = []
ArticleList = []

namesFile = open('scriptNames.txt', 'r')
HashList.append(NameHash40("game_".strip(), Hash40.CreateFromString("game_".lower().strip()))) #Share animation
for s in namesFile:
    if(s != "\n"):
        s = "game_" + s
        HashList.append(NameHash40(s.strip(), Hash40.CreateFromString(s.lower().strip())))
        if 'Special' in s or 'Final' in s:
                HashList.append(NameHash40(s.replace('Special','SpecialAir').replace('Final','FinalAir').strip(), Hash40.CreateFromString(s.replace('Special','SpecialAir').replace('Final','FinalAir').lower().strip())))

articlesFile = open('articles.txt','r')
for s in articlesFile:
    if(s != "\n"):
        s = s.replace("WEAPON_KIND_", "")
        ArticleList.append(NameHash40(s.lower().strip(), Hash40.CreateFromString(s.lower().strip())))


class Article: # Character / Weapon
    def __init__(self, article, hashes = []):
        self.article = article
        self.scriptsHash = hashes

    def addScriptHash(self, hash, address):
        self.scriptsHash.append(ScriptHash(hash, address))
    
    def findHashValue(self):
        find = next((x for x in ArticleList if self.article.hash == x.hash40.hash and self.article.length == x.hash40.length), None)
        if find:
            return find.name
        else:
            return self.article.hash40


class ScriptHash:
    def __init__(self, hash, address):
        self.hash = hash
        self.address = address

    def getAddress(self):
        return hex(self.address)

    def findHashValue(self):
        find = next((x for x in HashList if self.hash.hash == x.hash40.hash and self.hash.length == x.hash40.length), None)
        if find:
            return find.name
        else:
            return self.hash.hash40