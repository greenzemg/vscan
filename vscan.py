import argparse
import os
import re
import string
import json
import time

userFileList  = []
userDirList   = []
srcFilter     = "" 

srcDirList    = []
srcFileList   = []
srcTypeList   = []

srcTypeDict   = {"c":[".c", ".cpp", ".h"],
                "txt":[".txt"],
                "py":[".py", ".pyc"]
                }
#Api Rule Sets for C
#This is a dictionary with key for api causing the hit loaded from json file 
with open("crule.json","r") as jf:
		cApiRuleSets  = json.load(jf)

scanRecurs    = True


scanner=re.Scanner([
        (r"[a-zA-Z_]\w*", lambda scanner, token:("WORD", token)),
        (r"=|\+|-|\*|/|%|&|:|\?|!", lambda scanner, token:("OPER", token)),
        (r"\d+\.\d*", lambda scanner, token:("FLOAT", token)),
        (r"\d+", lambda scanner, token:("INT", token)),
        (r"[,;\[\].(){}\"#<>*'\\]", lambda scanner,token:("PUNC", token)),
        (r"\\n", lambda scanner,token:("ESQ", token)),
        (r"\s+", None), # None == skip token.
        #(r'.', lambda scanner, token: None),
], flags=re.DOTALL)

def get_filepaths(directory,pFilterList):
    """
    This function will generate the file names in a directory 
    tree by walking the tree either top-down or bottom-up. For each 
    directory in the tree rooted at directory top (including top itself), 
    it yields a 3-tuple (dirpath, dirnames, filenames).
    """
    file_paths = []  # List which will store all of the full filepaths.
    # Walk the tree.
    for root, directories, files in os.walk(directory):
        for filename in files:
            if filename.endswith(tuple(pFilterList)):
                # Join the two strings in order to form the full filepath.
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)  # Add it to the list.

    return file_paths  # Self-explanatory.

def displaySrcFiles(pFilePaths):

    for f in pFilePaths:
            print f

def is_valid_file(parser, arg):
    arg = os.path.abspath(arg)
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg

def parseArguments():
    global srcDirList, srcFileList,srcTypeList
    global srcTypeDict
    #fullFilePaths
    parser = argparse.ArgumentParser(description="Vscan - source code vulnerability scanner for c and c++") 
    parser.add_argument('-D','--dir', 
		help='The directory that contain source files', 
		nargs='*',
        dest="srcdirs")
    parser.add_argument("-F", "--file",
	    help="Source code files to be scan",
	    dest="srcfiles",
	    nargs='*',
	    type=lambda x: is_valid_file(parser, x),
	    metavar="FILE")
    parser.add_argument("-L", "--lang",
		help="Use this option to specif the target programming language",
                dest="language",
                nargs='*')
    parser.add_argument('--recurs', action='store_true')
    parser.add_argument('--no-recurs', action='store_false')
    #parser.parse_args()
    args = parser.parse_args()
	
    if args.no_recurs is False:
		scanRecursiv = False
    if args.recurs is True:
		scanRecursiv = True
    if args.srcfiles:
        userFileList = args.srcfiles
        srcFileList.extend(userFileList)
    if args.srcdirs:
        userDirList = args.srcdirs
        srcDirList.extend(x for x in userDirList if x not in srcDirList)
    if args.language:
        for lan in args.language:
            srcTypeList.extend(srcTypeDict[lan])
    else:
        srcTypeList = srcTypeDict["c"] 


    #Adjusting global variables
    for d in srcDirList:
        srcFileList.extend(get_filepaths(d,srcTypeList))

def showBanner():
    with open("banner.txt") as f:
        print f.read()

def printGlobalVar():
    print "------------Value of GlobalVars-------------"
    print "Type of source file to scan " + str(srcTypeList) 
    print "Directories to scan" + str(srcDirList)
    print "Source file to scan------"
    displaySrcFiles(srcFileList) 

#Lexical Analysis function input=>file output=>list of tokens or ast
def lexicalysis(pFile):
	lFileAstDict   = {} 
	lLineAstDict   = {}

	with open(pFile) as pf:
		for linenum, line in enumerate(pf, 1):
			curAstList, remainder=scanner.scan(line)
			lLineAstDict[linenum] = curAstList
			if remainder:
				print "[Debug] remainder:>" + str(remainder)
		lFileAstDict[pFile] = lLineAstDict
        return lFileAstDict

def vulnalysis(pFileAstDict):
	lHitScanList = []

	for filename, lineAstDict in pFileAstDict.iteritems():
		for linenum, lineAstList in lineAstDict.iteritems():
			for catag, tok in lineAstList:
				if catag is "WORD" and tok in [api for sub in cApiRuleSets.keys() for api in sub.split('|')]:
					lHitScanList.append((filename, linenum, tok))

	return lHitScanList	
def reportalysis(pHitScanList):
	for hit in pHitScanList:
		print("{0} LN[{1}] API[{2}]".format(hit[0], hit[1], hit[2])),
		for key, val in cApiRuleSets.iteritems():
			if hit[2] in key:
				print("\n\t[Type of Vulerabilty]: {0}\n\t[Warning]: {1}\n\t[Sugestion]: {2} ".format(val["type"], val["warn"], val["sug"]))		

def vscanengine(pFilterList):
	lFileAstDict = {}
	lHitScanList = []

	print "##################Vscan started##################"
	for srcf in srcFileList:
		if srcf.endswith(tuple(pFilterList)):
			lFileAstDict = lexicalysis(srcf)
			lHitScanList = vulnalysis(lFileAstDict) 
			reportalysis(lHitScanList)
			#print "[Debug]: in vscanengine htscanlist:>"

def vscan():

	parseArguments()
	showBanner()
	printGlobalVar()
	vscanengine(srcTypeList)

if __name__ == '__main__':
    try:
        vscan()
    except KeyboardInterrupt:
        print "*** Vscan engine interrupted"
