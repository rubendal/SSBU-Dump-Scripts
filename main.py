import sys, getopt, os, shutil
import zlib
import r2pipe
from hash40 import Hash40
from sectionTable import SectionTableJ, SectionJ
from parseAnimcmdList import ParseAnimcmdListJ
from parseAnimcmdStart import ParseAnimcmdStartJ
from scriptParser import Parser

parserOutput = "parser"
hitboxOutput = "hitboxes"
animcmdFile = ["game"]
dumpHitboxes = False

def parse(file, r2, sections, filename, f, dumpHitboxes):
    if f != 'game':
        dumpHitboxes = False

    hitboxes = ''
    grabs = ''
    throws = ''

    animcmdfile = next((x for x in sections if "lua2cpp::create_agent_fighter_animcmd_" + f + "_" in x.function and "_share_" not in x.function), None)
    if animcmdfile:
        print("{0} found".format(animcmdfile.function))

        af = r2.cmdj('s {0};af;pdfj'.format(animcmdfile.getAddress()))
        
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
                        parser = Parser(r2, script, hex(scriptAddress), hash.findHashValue(), sections)
                        pf = open('{0}/{1}/{2}/{3}.txt'.format(parserOutput, filename, article.findHashValue(), hash.findHashValue()),'w')
                        pf.write(parser.Output())
                        pf.close()

                        if dumpHitboxes:
                            #Hitbox dump
                            if not os.path.exists(hitboxOutput):
                                os.makedirs(hitboxOutput)
                        
                            if not os.path.exists("{0}/{1}".format(hitboxOutput, filename)):
                                os.makedirs("{0}/{1}".format(hitboxOutput, filename))

                            data = parser.GetHitboxes()

                            if(data):

                                for hitbox in data['hitboxes']:
                                    if('Genesis' not in hash.findHashValue()):
                                        hitboxes += (hitbox.print(article.findHashValue(), hash.findHashValue())) + '\n'
                                
                                for grab in data['grabs']:
                                    grabs += (grab.print(article.findHashValue(), hash.findHashValue())) + '\n'

                                for t in data['throws']:
                                    throws += (t.print(article.findHashValue(), hash.findHashValue())) + '\n'

                    except:
                        print("Couldn't parse {0}".format(hash.findHashValue()))
        
        if dumpHitboxes:
            pf = open('{0}/{1}/{2}.csv'.format(hitboxOutput, filename, 'hitboxes'),'w')
            pf.write(hitboxes)
            pf.close()

            pf = open('{0}/{1}/{2}.csv'.format(hitboxOutput, filename, 'grabs'),'w')
            pf.write(grabs)
            pf.close()

            pf = open('{0}/{1}/{2}.csv'.format(hitboxOutput, filename, 'throws'),'w')
            pf.write(throws)
            pf.close()

    else:
        print('animcmd_game not found on file {0}'.format(file))

def dump(file):
    global parserOutput, animcmdFile, dumpHitboxes
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
        parse(file, r2, sections, filename, f, dumpHitboxes)
    
    r2.quit()

def Parse(file):
    script = open(file, 'r')
    t = script.read()
    t = t.replace('\n','\n\r')
    #p = Parser(None, t)

def start(path, argv):
    global parserOutput, animcmdFile, dumpHitboxes

    scriptSpecified = False

    try:
      opts, args = getopt.getopt(argv,"o:gexsh",["output=","game","effect","expression","sound","hitboxDump"])
    except getopt.GetoptError:
        print(getopt.GetoptError.msg)
        print('main.py path [-g|-e|-x|-s]')
        print("file path: dump scripts from elf file")
        print("directory path: dump all scripts from elf files found on directory")
        print("-g: Dump game scripts (default when no type is specified)")
        print("-e: Dump effect scripts")
        print("-x: Dump expression scripts")
        print("-s: Dump sound scripts")
        print("-h: Dump hitboxes on csv file")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-o':
            parserOutput = arg
        if opt == '-e':
            animcmdFile.append("effect")
            scriptSpecified = True
        if opt == '-x':
            animcmdFile.append("expression")
            scriptSpecified = True
        if opt == '-s':
            animcmdFile.append("sound")
            scriptSpecified = True
        if opt == '-g':
            animcmdFile.append("game")
            scriptSpecified = True
        if opt == '-h':
            dumpHitboxes = True
        
    if not scriptSpecified:
        animcmdFile = ["game"]
    else:
        animcmdFile.pop(0)

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