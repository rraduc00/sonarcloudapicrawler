#!/usr/bin/env python3

"""
@Author Razvan Raducu

CONSTRAINTS: As of 26th of July 2018 SonarCloud API is limited to the first 10000 results. 
You cannot query more than that. 
"""


# pip install requests
import requests 
import json
import sys

###
def APIrequest():
	global remainingResults

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

	

	print("#### Writing page " + str(p) + " to file ####")

	# The writing is done in 'a' (append) mode
	print(json.dumps(queryJsonResponse, indent=4), file=open('sonarQueryResults.json','a'))

	remainingResults = totalResults - (ps*p)
	if remainingResults < 0:
		remainingResults = 0
	print("#### There are " + str(remainingResults) + " left to print ####")

###

p = 1
ps = 500
remainingResults = 0

APIrequest()

while remainingResults > 500:
	p+=1
	print("#### Querying again. Requesting pageindex " + str(p) + " ####")
	APIrequest()



