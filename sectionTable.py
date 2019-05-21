import re

class SectionTable:
    def __init__(self, text):
        self.sections = []
        for l in text.split('\r'):
            line = re.sub('\s+', '\t', l)
            fields = len(line.split('\t'))
            if line != '\n' and '\t' in line and 'Vaddr' not in line and fields >= 6:
                self.sections.append(Section(line))

    def getSections():
        return sections
        


class Section:
    def __init__(self, text):
        sep = text.split('\t')
        self.num = int(sep[2], 16)
        self.function = sep[6]
        self.size = int(sep[5])
        self.address = int(sep[2],16)

    def getAddress(self):
        return hex(self.address)