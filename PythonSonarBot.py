#!/usr/bin/env python3

"""
@Author Razvan Raducu

CONSTRAINTS: As of 26th of July 2018 SonarCloud API is limited to the first 10000 results. 
You cannot query more than that. THIS CONSTRAINT IS APPLIED TO EVERYSINGLE QUERY. That is,
when requesting all the projects that meet the filter, only 10000 results can be seen.
When requesting the vulnerability list of the corresponeding key to each result, only
10000 vulnerabilities can be seen.
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

# Deletion of trailing comma. 
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

##################################↓↓↓ Requesting sourcecode ↓↓↓##################################




