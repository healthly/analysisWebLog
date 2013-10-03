#!/usr/bin/env python
#coding=utf-8
import sys
import argparse
import re
import analysisM
from datetime import datetime
from pymongo import Connection
from datetime import timedelta
from pymongo.errors import ConnectionFailure

_utcnow = datetime.utcnow()

def insertR(dbC, collect, data):
	dbC[collect].insert(data, save=True)

def logfromMongo(host,port,dbname,times):
	''' host: mongodb hostname
	port: mongodb port
	dbname: mongodb database names
	times: times before now to get logs from mongodb,eg:-10
	'''
	try:
		_c1 = Connection(host, port)
	except ConnectionFailure, e:
		sys.stderr.write("Could not connect to MongoDB: %s" % e)
		sys.exit(1)
	dbC = _c1[dbname]
	assert dbC.connection == _c1
	end = _utcnow
	amin = timedelta(seconds=times)
	#amin = timedelta(minutes=-1)
	start = end + amin
	_r1 = dbC.access.find({'time': {'$gte': start, '$lt': end}})
	return _r1

def argP():
	parser = argparse.ArgumentParser(description='analy nginx log from mongodb')
	parser.add_argument('--ipurl', dest="ipurl", action='store_true', help="output out ip's ,urls in ten seconds")
	parser.add_argument('--search', dest="search", action='store_true', help="output search reslut in ten seconds")
	parser.add_argument('--codemethod', dest="codemethod", action='store_true', help="output out codes,methods Ocurrences in ten seconds")
	parser.add_argument('-H', dest="dbhost", default='localhost', help="mongodb's ip or hostname")
	parser.add_argument('-N', dest="dbname", default='nginx111', help="mongodb's dbname")
	parser.add_argument('-T', dest="times", type=int,default=-10 , help="times before now to get logs from mongodb,eg:-10 seconds")
	parser.add_argument('-C', dest="counts",type=int,default=10,help="ips,urls counts")
	parser.add_argument('-S', dest="keyword",default='-',help="search url's keyword")
	#parser.add_argument('-N', dest="dbname", type=int)
	
	return parser
	
	
def main():
	argS = argP().parse_args()
	if len(sys.argv) <= 1:
		argP().print_help()
	
	else:
		 
		if argS.ipurl:
			i = logfromMongo(argS.dbhost,27017,argS.dbname,argS.times)
			m = analysisM.getLogItems(i,u'method',u'referer',u'code',u'size',u'agent')[1]
			analysisM.countIP_URL(m,argS.counts)
		
		elif argS.codemethod:
			i = logfromMongo(argS.dbhost,27017,argS.dbname,argS.times)
			m = analysisM.getLogItems(i,u'method',u'referer',u'code',u'size',u'agent')[1]
			analysisM.c_m_Ocurrences(m)
		elif argS.search:
			i = logfromMongo(argS.dbhost,27017,argS.dbname,argS.times)
			m = analysisM.getLogItems(i,u'method',u'referer',u'code',u'size',u'agent')[1]
			analysisM.searchUrl(m,argS.keyword)
		else:
			argP().print_help()
	#c1 = u'nginx1'
	#insertR(dbC, c1, logIn)


if __name__ == "__main__":
   main()