class Constant:
    def __init__(self, index, hash, name):
        self.index = index
        self.hash = hash
        self.name = name

Constants = []

def InitializeConstants(version = '3.1.0'):
    ci = 1
    cfile = open('const_value_table_' + version + '.csv', 'r')
    for s in cfile:
        v = s.split(',')
        Constants.append(Constant(ci, v[0].strip(), v[1].strip()))
        ci += 1