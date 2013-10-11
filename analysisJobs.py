#!/usr/bin/env python
#coding=utf-8
import sys
#import argparse
#import re
import analysisM
from datetime import datetime
from pymongo import Connection
from datetime import timedelta
from pymongo.errors import ConnectionFailure
from apscheduler.scheduler import Scheduler
import logging 
import comiplist
#_utcnow = datetime.utcnow()

def badip2mongo(dbC,collect,iplist):
	for ip in iplist:
		if ip[0] in comiplist.comiplist():
			continue
		i = dbC[collect].find_one({"ip":ip[0]})
		if i:
			c1 = i.get("counts") + 1
			dbC[collect].update({"ip":ip[0]},{"$set":{"counts":c1}}, save=True)
		else:
			dbC[collect].insert({"ip":ip[0],"counts":1}, save=True)

			
def mongoclient(host,port,dbname):
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
	return dbC
	
	
	
def logUtimes(dbC,times):
	end = datetime.utcnow()
	amin = timedelta(seconds=times)
	#amin = timedelta(minutes=-1)
	start = end + amin
	_r1 = dbC.access.find({'time': {'$gte': start, '$lt': end}})
	return _r1
	
	
def jobs():
	flag = 'ip'
	dbc = mongoclient('localhost',27017,'nginx111')
	i = logUtimes(dbc,-10)
	m = analysisM.getLogItems(i)[1]
	ipL = analysisM.countIP_URL(m,60,-10,flag)
	dbB = mongoclient('localhost',27017,'badip')
	badip2mongo(dbB,'iplist',ipL)
	#for j in dbB.iplist.find():
	#	print j
		
		
if __name__=="__main__":
	#dbhost = 'localhost'
	#dbname = 'nginx111'
	#jobs()
	# Start the scheduler
	logging.basicConfig()
	sched = Scheduler()
	sched.daemonic = False
	sched.add_interval_job(jobs,seconds=10)
	sched.start()	
