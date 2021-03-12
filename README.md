# SSBU-Dump-Scripts
Script to dump character game animcmd scripts programatically using r2pipe (3.0.0 and later versions only)

## Requirements
* Python 3
* Radare2 >= 3.0.0 & < 5.0.0, 4.3.1 recommended
* pip install r2pipe=1.5.3

## Usage
```
python main.py ".elf path" (-g|-e|-s|-x)
python main.py "directory with .elf files" (-g|-e|-s|-x)

-g = Game scripts
-e = Effect scripts
-s = Sound scripts
-x = Expression scripts
```

## To do
* Add missing script and article names
* Fix issues on parser [More details about issues](https://github.com/rubendal/SSBU-Dump-Scripts/projects/1)