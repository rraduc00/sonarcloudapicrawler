#!/usr/bin/env python3

"""
@Author Razvan Raducu

CONSTRAINTS: As of 26th of July 2018 SonarCloud API is limited to the first 10000 results. 
You cannot query more than that. THIS CONSTRAINT IS APPLIED TO EVERY SINGLE QUERY. That is,
when requesting all the projects that meet the filter, only 10000 results can be seen.
When requesting the vulnerability list of the corresponeding key to each result, only
10000 vulnerabilities can be seen and so on.

#TODO COMENTS

"""


# pip install requests
import requests 
import json
import sys

############################↓↓↓ Requesting project IDS ↓↓↓######################################
def APIProjectRequest():
	global remainingResults
	global queryJsonResponse

	url = 'https://sonarcloud.io/api/components/search_projects'
	parameters = {'filter':'security_rating>=2 and languages=c','p': p,'ps': ps }

	try:
		req = requests.get(url, params=parameters)
	except requests.exceptions.RequestException as e:
		print(e)
		print("Aborting")
		sys.exit(1)

	print("#### Request made to " + req.url + " ####")

	# Writing the results of the query to a file
	queryJsonResponse = req.json()
	totalResults = queryJsonResponse['paging']['total']
	print("#### Query generated " + str(totalResults) + " results ####")

	

	#print("#### Writing page " + str(p) + " to file ####")

	# The writing is done in 'a' (append) mode (optional)
	#print(json.dumps(queryJsonResponse, indent=4), file=open('sonarQueryResults.json','a'))

	remainingResults = totalResults - (ps*p)
	if remainingResults < 0:
		remainingResults = 0
	print("#### There are " + str(remainingResults) + " left to print ####")

p = 1
ps = 500
remainingResults = 0
queryJsonResponse = 0

APIProjectRequest()

while remainingResults > 500:
	if p == 20: # 500 results * 20 pages = 10000 limit reached
		break
	p+=1
	print("#### Querying again. Requesting pageindex " + str(p) + " ####")
	APIProjectRequest()


#################################↑↑↑  Requesting project IDS  ↑↑↑################################

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

		print("#### Request made to " + req.url + " ####")

		# Writing the results of the query to a file
		fileName = (str(fileKey) + '_' + str(issue['textRange']['startLine']) + ':' + str(issue['textRange']['endLine']) + '.c').replace('/','%3A')
		with open('./'+fileName,'wb+') as file:
			file.write(req.content)

##################################↑↑↑ Requesting sourcecode ↑↑↑##################################

#################################↓↓↓ Requesting vulnerabilities ↓↓↓##############################
"""
Here are the keys of every single repo that meets the following conditions:
	1. Is public 
	2. Is written in C language
	3. Its security rating is >= 2
"""
projectIds = "" 
for component in queryJsonResponse['components']:
	# It's appended into the list to compose the following request.
	projectIds += str(component['key']) + ","

# Deletion of trailing comma. (Right side of index specifier is exclusive)
projectIds = projectIds[:-1]
#print(projectIds)

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

	print("#### Request made to " + req.url + " ####")

	# Writing the results of the query to a file
	queryJsonResponse = req.json()
	print(json.dumps(queryJsonResponse, indent=4), file=open('sonarQueryResults.json','a'))

	## REQUESTING SOURCECODE ##
	print("#### REQUESTING SOURCECODE ####")
	#APISourceCodeRequest()

	totalResults = queryJsonResponse['total']
	print("#### Query generated " + str(totalResults) + " results ####")


	remainingResults = totalResults - (ps*p)
	if remainingResults < 0:
		remainingResults = 0
	print("#### There are " + str(remainingResults) + " left to print ####")

APIVulnsRequest()

while remainingResults > 500:
	if p == 20: # 500 results * 20 pages = 10000 limit reached
		break
	p+=1
	print("#### Querying again. Requesting pageindex " + str(p) + " ####")
	APIVulnsRequest()

###############################↑↑↑ Requesting vulnerabilities ↑↑↑################################

