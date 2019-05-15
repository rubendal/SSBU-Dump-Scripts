import sys, getopt, os, shutil
import zlib
import r2pipe
from hash40 import Hash40
from sectionTable import SectionTable, Section
from parseAnimcmdList import ParseAnimcmdList
from parseAnimcmdStart import ParseAnimcmdStart
from scriptparser import Parser

output = "output"
testParser = False

def dump(file):
    global output, testParser
    print("Opening file {0}".format(file))
    filename = os.path.split(os.path.splitext(file)[0])[-1]

    if 'common' in filename or 'item' in filename:
        return

    r2 = r2pipe.open(file)
    sections = SectionTable(r2.cmd("is")).sections
    r2.cmd('e anal.bb.maxsize = 0x10000')
    game = next((x for x in sections if "lua2cpp::create_agent_fighter_animcmd_game_" in x.function and "_share_" not in x.function), None)
    if game:
        print("{0} found".format(game.function))

        af = r2.cmd('s {0};af;pdf'.format(game.getAddress()))
        
        p = ParseAnimcmdList(af, sections)

        print("Scripts extracted") #, {0} articles found .format(len(p.ArticleScripts))

        if not os.path.exists(output):
            os.makedirs(output)
        
        if not os.path.exists("{0}/{1}".format(output, filename)):
                os.makedirs("{0}/{1}".format(output, filename))

        if len(p.Issues) > 0:
            #Log missing scripts in file due to issues on parsing or radare2 output
            None
            #f = open("{0}/{1}/{2}.txt".format(output, filename, "missing"), "w")
            #f.write("")
            #f.close()

        for article in p.ArticleScripts:
            
            print("Dumping article {0} scripts, count: {1}".format(article.findHashValue(), len(article.scriptsHash)))

            if not os.path.exists("{0}/{1}/{2}".format(output, filename, article.findHashValue())):
                os.makedirs("{0}/{1}/{2}".format(output, filename, article.findHashValue()))
            else:
                #Remove previous dumped files (to prevent duplicates with code used for script filename)
                shutil.rmtree("{0}/{1}/{2}".format(output, filename, article.findHashValue()))
                os.makedirs("{0}/{1}/{2}".format(output, filename, article.findHashValue()))
            
            for hash in article.scriptsHash:
                scriptStart = r2.cmd('s {0};pd 20'.format(hash.getAddress()))
                scriptAddress = ParseAnimcmdStart(scriptStart).address

                if scriptAddress:
                    script = r2.cmd('s {0};aF;pdf'.format(hex(scriptAddress)))

                    if testParser:
                        try:
                            parser = Parser(r2, script, hash.findHashValue(), sections)
                            pf = open('parser/{0}.txt'.format(hash.findHashValue()),'w')
                            pf.write(parser.Output())
                            pf.close()
                        except:
                            print("Couldn't parse {0}".format(hash.findHashValue()))

                    script = script.replace('\r', '')
                    exists = os.path.exists("{0}/{1}/{2}/{3}.txt".format(output, filename, article.findHashValue(), hash.findHashValue()))
                    if not exists:
                        f = open("{0}/{1}/{2}/{3}.txt".format(output, filename, article.findHashValue(), hash.findHashValue()), "w")
                        f.write(script)
                        f.close()
                    else:
                        v = 2
                        while exists:
                            exists = os.path.exists("{0}/{1}/{2}/{3} ({4}).txt".format(output, filename, article.findHashValue(), hash.findHashValue(), v))
                            if not exists:
                                f = open("{0}/{1}/{2}/{3} ({4}).txt".format(output, filename, article.findHashValue(), hash.findHashValue(), v), "w")
                                f.write(script)
                                f.close()
                            v += 1

    else:
        print('animcmd_game not found on file {0}'.format(file))
    
    r2.quit()

def Parse(file):
    script = open(file, 'r')
    t = script.read()
    t = t.replace('\n','\n\r')
    p = Parser(None, t)

def start(path, argv):
    global output, testParser
    try:
      opts, args = getopt.getopt(argv,"o:p",["output="])
    except getopt.GetoptError:
        print('main.py path')
        print("file path: dump scripts from elf file")
        print("directory path: dump all scripts from elf files found on directory")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-o':
            output = arg
        if opt == '-p':
            testParser = True

    run = False

    if os.path.isdir(path):
        for file in os.listdir(path):
            if os.path.splitext(file)[1] == ".elf": 
                run = True
                dump(os.path.join(path,file))
    elif os.path.isfile(path):
        ext = os.path.splitext(path)
        if os.path.splitext(path)[1] == ".elf":
            run = True
            dump(path)

    if not run:
        print("No elf file found")

    print("Done!")


if __name__ == "__main__":
    start(sys.argv[1], sys.argv[2:])