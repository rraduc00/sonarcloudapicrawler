#!/usr/bin/env python3

"""
@Author Razvan Raducu
Gonzalo Esteban Costales
Flavio Rodrigues Dias
Camino Fernández LLamas

CONSTRAINTS: As of 26th of July 2018 SonarCloud API is limited to the first 10000 results. 
You cannot query more than that. THIS CONSTRAINT IS APPLIED TO EVERY SINGLE QUERY. That is,
when requesting all the projects that meet the filter, only 10000 results can be seen.
When requesting the vulnerability list of the corresponeding key to each result, only
10000 vulnerabilities can be seen and so on.

Problem 1.
We found that we cannot just append every result of the queries looking for vulnerabilities
into one single file because the result is a malformatted JSON file since there cannot be
more than one JSON object per file. 
Solution 1.
The solution is to actually request the first 500 
results of the vulnerability query (page 1) and write them to a file. Immediately after,
parse that file and request the corresponding source code. When we got it, request
the next 500 (page 2) vulnerabilities, write the result to a file (not append) and, once again,
request the sourcecode. This loop goes on until we reach the 10000 results limit imposed
by Sonarcloud's API. 

Problem 2.
Turns out each vulnerable code line is a different entry from the same JSON list. That is,
we could have 13 different results, 13 different issues, but they are just different lines
of the same file. We end up having 13 copies of the same sourcode but with different name. 
Solution 2.
What we came up with is simply compiling all vulnerable lines within the same file, download
the file and append the lines as a comment. (Appending at the end of the file)

Problem 3.
Apparently SonarCloud maintains a list of issues even though the file those issues arise 
from got deleted long time ago. The results is a file whose sole content is a json list
called "errors" containing a "msg". 
Solution 3.
The solution is pretty simple, we inspect the content that's about to be written out in 
the corresponeding file. If it contains a "errors" json list, we skip it. 

It will take a while to download all sourcecode because requests are sequential. 

"""


# pip install requests
import requests 
import json
import sys
import os

def printUsage():
	print("Usage:\n"+
		"Execute it with command \"./PythonSonarBot.py\". Make sure it has execute permission.\n"+
		"The script receives the following arguments: \n"+
		"\tThe directory you want the sourcecode to be downloaded in. Example: ./PythonSonarBot.py ./DataSet\n"+
		"The script receives the following options: \n"+
		"\tNo option. When no option is specified it will execute in quiet mode.\n"+
		"\t-v option is used for verbose mode. Example: ./PythonSonarBot ./DataSet -v\n")
	sys.exit()

def checkPath(path):
	if not os.path.exists(path):
		try:
			os.makedirs(path)
		except OSError as err:
			print("Error: {0}".format(err))
			sys.exit()


############################↓↓↓ Detecting arguments and options ↓↓↓######################################
print("#### Append -h to print usage. (./PythonSonarBot.py -h) ####\n")
verbose = 0
dumpDir = ""
if len(sys.argv) == 2:
	if sys.argv[1] == '-h':
		printUsage()
	else:
		dumpDir = sys.argv[1]
		checkPath(dumpDir)
elif len(sys.argv) == 3: 
	if sys.argv[2] == '-v': verbose +=1 
	else:
		print("Wrong usage. Aborting")
		sys.exit() 
	dumpDir = sys.argv[1]
	checkPath(dumpDir)
else:
	print("Wrong usage. Aborting")
	sys.exit()

print("#### Executing verbosely") if verbose else print("#### Executing in quiet mode. ####")

verbosePrint = print if verbose else lambda k: None
############################↑↑↑ Detecting arguments and options ↑↑↑######################################

############################↓↓↓ Requesting project IDS ↓↓↓######################################
def APIProjectRequest():
	global remainingResults
	global queryJsonResponse

	url = 'https://sonarcloud.io/api/components/search_projects'
	parameters = {'filter':'security_rating>=2 and languages=c','p': p,'ps': ps }

	try:
		req = requests.get(url, params=parameters)
	except requests.exceptions.RequestException as e:
		print("Error: {0}".format(e))
		sys.exit()

	verbosePrint("#### Request made to " + req.url + " ####")

	# Writing the results of the query to a file
	queryJsonResponse = req.json()
	totalResults = queryJsonResponse['paging']['total']
	verbosePrint("#### Query generated " + str(totalResults) + " results ####")

	verbosePrint("#### Writing page " + str(p) + " to file ####")

	# The writing is done in 'a' (append) mode (optional)
	##print(json.dumps(queryJsonResponse, indent=4), file=open('sonarQueryResults.json','a'))

	remainingResults = totalResults - (ps*p)
	if remainingResults < 0:
		remainingResults = 0
	verbosePrint("#### There are " + str(remainingResults) + " left to #print ####")

p = 1
ps = 500
remainingResults = 0
queryJsonResponse = 0

APIProjectRequest()

while remainingResults > 500:
	if p == 20: # 500 results * 20 pages = 10000 limit reached
		break
	p+=1
	verbosePrint("#### Querying again. Requesting pageindex " + str(p) + " ####")
	APIProjectRequest()


#################################↑↑↑  Requesting project IDS  ↑↑↑################################


##################################↓↓↓ Obtaining function range within file ↓↓↓##################################
"""
This function is the one that actually discovers which line and offset the vulenrable function ends.
It takes the vulnerable file, the starting line of bulnerable function and the starting offset of vulnerable
function. 
It traverses the line seeking and counting matching prenthesis. If the parenthesis do not match, an empty list will
be returned. 

Returns: A list containing [endLineOfVulnerableFunction, endOffsetOfVulnerableFunction]
"""

def functionRangeCalculator(lines, startLine, startOffset, evaluate, pNumber):
	"""
	One must be subtracted from linde index since array is 0 based
	"""
	lineNumber = startLine-1
	line = lines[lineNumber]
	line = line[startOffset:]

	print("La línea vulnerable es: ", line, " que es el numero: ", startLine)

	"""
	Aux flag for recursivity
	"""
	evaluating = evaluate
	delegate = False
	parenNumber = pNumber
	solutionArray = 0
	traversedChars = 0

	for char in line:
		print("\n### ESTOY ANALIZANDO EL CHAR:[", char, "] de la línea: ",startLine)
		traversedChars += 1
		if char == '(':
			parenNumber += 1
			evaluating = True
		elif char == ')':
			parenNumber -= 1
		elif char == '\n':
			delegate = True
			solutionArray = functionRangeCalculator(lines, 
				startLine + 1 , 
				0, 
				evaluating, 
				parenNumber)
		"""
		End of recursivity. We sum 1 to convert from index-based numeration.
		"""
		print("ParenNumber is #############============> ", parenNumber)
		if(evaluating and not parenNumber and not delegate):
			endLine = lineNumber+1
			endOffset = startOffset + traversedChars + 1
			break
		elif(evaluating and delegate):
			endLine = solutionArray[0]+1
			endOffset = solutionArray[1]+1
			break

			"""
			TODO: There are errors when starting offset is inline. For example:
						"%s", buffer);
			"""
	print("El final de la llamada vulnerable es la línea: ", endLine, " con el offset: ", endOffset)

	return [endLine, endOffset]

#################################↑↑↑  Obtaining function range within file   ↑↑↑################################

##################################↓↓↓ Requesting sourcecode ↓↓↓##################################

"""
When requesting sourcecode only the key is needed, as stated by the api DOCS 
https://sonarcloud.io/web_api/api/sources/raw. The key is ['issues']['component']
value from the queryJsonResponse at this moment.
"""

def APISourceCodeRequest():
	url = 'https://sonarcloud.io/api/sources/raw'

	# For each project ID, we get its source code and name it according to the following pattern:
	# fileKey_startLine:endLine.c

	"""
	Opening the temporal file sonarQueryResults.json, we read each ['issues']['component'] value
	and request it to /sources/raw
	"""
	with open('sonarQueryResults.json') as data_file:    
		data = json.load(data_file)

	for issue in data['issues']:
		fileKey = issue['component']
		parameters = {'key':fileKey}
		try:
			req = requests.get(url, params=parameters)
		except requests.exceptions.RequestException as e:
			print(e)
			print("Aborting")
			sys.exit(1)

		# If the file contains errors because it was not found, we simply skip it.
		if req.content.find(b"{\"errors\":[{\"msg\":") != -1:
			print("#### FILE " + req.url + " SKIPPED BECAUSE IT CONTAINED ERRORS ####\n")
			print(req.content)
			print("######################\n")
			continue

		# We replace '/' with its hex value 2F
		vulnerableFile = (str(dumpDir)+"/"+(str(fileKey)).replace('/','2F'))
		verbosePrint("Looking if "+ vulnerableFile+ " exists.")

		startLine = issue['textRange']['startLine']
		# 1 is added to startOffset so we can properly use the value within clang.
		startOffset = issue['textRange']['startOffset']+1

		endLine, endOffest = 0, 0

		if not os.path.isfile(vulnerableFile):

			verbosePrint("++++> File doesn't exist. Creating <++++")
			with open(vulnerableFile, 'ab+') as file:
				file.write(req.content)

			with open(vulnerableFile, 'r') as file: 
				lines = file.readlines()

				functionEndRange = functionRangeCalculator(lines, startLine, startOffset-1, False, 0)	

				endLine = functionEndRange[0] 
				endOffset = functionEndRange[1]
	
	
			with open(vulnerableFile, 'ab+') as file: 	
				file.write(str.encode("///###BEGIN_VULNERABLE_LINES###\n\n"))
				file.write(str.encode("///" + str(startLine) + "," + str(startOffset) + ";" + str(endLine) + "," + str(endOffset) +"\n\n"))
		else:
			verbosePrint("----> File exists. Appending vulnerable lines <----")
			with open(vulnerableFile, 'r') as file: 
				lines = file.readlines()

				functionEndRange = functionRangeCalculator(lines, startLine, startOffset-1, False, 0)	

				endLine = functionEndRange[0] 
				endOffset = functionEndRange[1]
	
	
			with open(vulnerableFile, 'ab+') as file: 	
				file.write(str.encode("///###BEGIN_VULNERABLE_LINES###\n\n"))
				file.write(str.encode("///" + str(startLine) + "," + str(startOffset) + ";" + str(endLine) + "," + str(endOffset) +"\n\n"))
		

##################################↑↑↑ Requesting sourcecode ↑↑↑##################################

#################################↓↓↓ Requesting vulnerabilities ↓↓↓##############################
"""
Here are the keys of every single repo that meets the following conditions:
	1. Is public 
	2. Is written in C language
	3. Its security rating is >= 2
"""
projectIds = "" 

"""
The value of queryJsonResponse is retrieved at this point because the total number of
projects that meets our filter, as of right now, is 417. Thus, APIProjectRequest() gets
executed only once and queryJsonResponse has all the 417 projects. 
"""
for component in queryJsonResponse['components']:
	# It's appended into the list to compose the following request.
	projectIds += str(component['key']) + ","

# Deletion of trailing comma. (Right side of index specifier is exclusive)
projectIds = projectIds[:-1]

p = 1
remainingResults = 0

def APIVulnsRequest():
	global remainingResults
	url = 'https://sonarcloud.io/api/issues/search'
	parameters = {'projects':projectIds, 'types':'VULNERABILITY', 'languages':'c', 'ps':500, 'p': p }

	try:
		req = requests.get(url, params=parameters)
	except requests.exceptions.RequestException as e:
		print(e)
		print("Aborting")
		sys.exit(1)

	verbosePrint("#### Request made to " + req.url + " ####")

	# Writing the results of the query to a file
	queryJsonResponse = req.json()
	print(json.dumps(queryJsonResponse, indent=4), file=open('sonarQueryResults.json','w'))

	## REQUESTING SOURCECODE ##
	verbosePrint("#### REQUESTING SOURCECODE ####")
	APISourceCodeRequest()

	totalResults = queryJsonResponse['total']
	verbosePrint("#### Query generated " + str(totalResults) + " results ####")


	remainingResults = totalResults - (ps*p)
	if remainingResults < 0:
		remainingResults = 0
	verbosePrint("#### There are " + str(remainingResults) + " left to print ####")

APIVulnsRequest()

while remainingResults > 500:
	if p == 20: # 500 results * 20 pages = 10000 limit reached
		break
	p+=1
	verbosePrint("#### Querying again. Requesting pageindex " + str(p) + " ####")
	APIVulnsRequest()

###############################↑↑↑ Requesting vulnerabilities ↑↑↑################################

