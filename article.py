class Article: # Character / Weapon
    def __init__(self, article, hashes = []):
        self.article = article
        self.scriptsHash = hashes

    def addScriptHash(self, hash, address):
        self.scriptsHash.append(ScriptHash(hash, address))
    
    def findHashValue(self):
        return self.article.hash40


class ScriptHash:
    def __init__(self, hash, address):
        self.hash = hash
        self.address = address

    def getAddress(self):
        return hex(self.address)

    def findHashValue(self):
        return self.hash.hash40