import sys, getopt, os, shutil
import zlib
import r2pipe
from hash40 import Hash40
from sectionTable import SectionTableJ, SectionJ
from parseAnimcmdList import ParseAnimcmdListJ
from parseAnimcmdStart import ParseAnimcmdStartJ
from scriptParser import Parser

parserOutput = "parser"
animcmdFile = ["game"]

def parse(file, r2, sections, filename, f):
    game = next((x for x in sections if "lua2cpp::create_agent_fighter_animcmd_" + f + "_" in x.function and "_share_" not in x.function), None)
    if game:
        print("{0} found".format(game.function))

        af = r2.cmdj('s {0};af;pdfj'.format(game.getAddress()))
        
        p = ParseAnimcmdListJ(r2, af, sections)

        print("Scripts extracted") #, {0} articles found .format(len(p.ArticleScripts))

        if not os.path.exists(parserOutput):
            os.makedirs(parserOutput)
    
        if not os.path.exists("{0}/{1}".format(parserOutput, filename)):
            os.makedirs("{0}/{1}".format(parserOutput, filename))

        if len(p.Issues) > 0:
            #Log missing scripts in file due to issues on parsing or radare2 output
            None
            #f = open("{0}/{1}/{2}.txt".format(output, filename, "missing"), "w")
            #f.write("")
            #f.close()

        for article in p.ArticleScripts:
            
            print("Dumping article {0} scripts, count: {1}".format(article.findHashValue(), len(article.scriptsHash)))

            if not os.path.exists("{0}/{1}/{2}".format(parserOutput, filename, article.findHashValue())):
                os.makedirs("{0}/{1}/{2}".format(parserOutput, filename, article.findHashValue()))
            
            for hash in article.scriptsHash:
                scriptStart = r2.cmdj('s {0};pdj 20'.format(hash.getAddress()))
                scriptAddress = ParseAnimcmdStartJ(scriptStart).address

                if scriptAddress:
                    script = r2.cmdj('s {0};aF;pdfj'.format(hex(scriptAddress)))

                    try:
                        #print(hash.findHashValue())
                        parser = Parser(r2, script, hex(scriptAddress), hash.findHashValue(), sections)
                        pf = open('{0}/{1}/{2}/{3}.txt'.format(parserOutput, filename, article.findHashValue(), hash.findHashValue()),'w')
                        pf.write(parser.Output())
                        pf.close()
                    except:
                        print("Couldn't parse {0}".format(hash.findHashValue()))


    else:
        print('animcmd_game not found on file {0}'.format(file))

def dump(file):
    global parserOutput, animcmdFile
    print("Opening file {0}".format(file))
    filename = os.path.split(os.path.splitext(file)[0])[-1]

    if 'common' in filename or 'item' in filename:
        return

    r2 = r2pipe.open(file)
    r2.cmd('e anal.vars = false')
    r2.cmd('e anal.bb.maxsize = 0x10000')
    r2.cmd('e anal.depth = 128')
    sections = SectionTableJ(r2.cmdj("isj")).sections
    
    
    for f in animcmdFile:
        parse(file, r2, sections, filename, f)
    
    r2.quit()

def Parse(file):
    script = open(file, 'r')
    t = script.read()
    t = t.replace('\n','\n\r')
    #p = Parser(None, t)

def start(path, argv):
    global parserOutput, animcmdFile

    t = []
    scriptSpecified = False

    try:
      opts, args = getopt.getopt(argv,"o:gexs",["output=","game","effect","expression","sound"])
    except getopt.GetoptError:
        print('main.py path [-g|-e|-x|-s]')
        print("file path: dump scripts from elf file")
        print("directory path: dump all scripts from elf files found on directory")
        print("-g: Dump game scripts (default when no type is specified)")
        print("-e: Dump effect scripts")
        print("-x: Dump expression scripts")
        print("-s: Dump sound scripts")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-o':
            parserOutput = arg
        if opt == '-e':
            t.append("effect")
            scriptSpecified = True
        if opt == '-x':
            t.append("expression")
            scriptSpecified = True
        if opt == '-s':
            t.append("sound")
            scriptSpecified = True
        if opt == '-g':
            t.append("game")
            scriptSpecified = True
        
    if scriptSpecified:
        animcmdFile = t

    run = False

    if os.path.isdir(path):
        for file in os.listdir(path):
            if os.path.splitext(file)[1] == ".elf": 
                run = True
                dump(os.path.join(path,file))
    elif os.path.isfile(path):
        ext = os.path.splitext(path)
        if ext[1] == ".elf":
            run = True
            dump(path)

    if not run:
        print("No elf file found")

    print("Done!")


if __name__ == "__main__":
    start(sys.argv[1], sys.argv[2:])