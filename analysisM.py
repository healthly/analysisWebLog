#!/usr/bin/env python
#coding=utf-8
import sys
import re
import ipLocation

def searchUrl(logList,keyword,times,count):
	_ipp = []
	_ip = {}
	_urll = []
	_url = {}
	s = keyword
	for i in logList:
		u1 = str(i.get(u'ip')) + ':' +str(i.get(u'url'))
		if s == str(i.get(u'url')):
			print "search web log eq" + keyword +" keywords's via IP :" + i.get(u'ip')
		elif re.search(s,u1):
			print u1
			#_ipp.append(i.get(u'ip'))
			#_urll.append(i.get(u'url'))
			
#	for m in _ipp:
#		if _ipp.count(m) > 1:
#			_ip[m] = _ipp.count(m)
#	
#	for n in _urll:
#		if _urll.count(n) > 1:
#			_url[n] = _urll.count(n)
#			
#	ip = sorted(_ip.items(), key=lambda _ip:_ip[1], reverse=True)
#	url = sorted(_url.items(), key=lambda _url:_url[1], reverse=True)
#	print "------Nginx access IP NUMS in " + str(times)[1:] + " seconds and use "+ keyword +" keywords-------"
#	for k in ip:
#		if k[1] > count:
#			print k[0],':',k[1],':',ipLocation.ip_location(k[0])
#	
#	print "------Nginx access URL NUMS in " + str(times)[1:] + " seconds and use "+ keyword +" keywords-------"
#	for k in url:
#		if k[1] > count:
#			print k[0],':',k[1]


def countIP_URL(logList,count,times):
	_ip = {}
	_url = {}
	_ipp = []
	_urll = []
	_code = {}
	_codee = []
	_total = len(logList)
	for n in logList:
		_ipp.append(n.get('ip'))
		_urll.append(n.get('url'))
		_codee.append(n.get('code'))
	for m in _ipp:
		if _ipp.count(m) > 1:
			_ip[m] = _ipp.count(m)
	ip = sorted(_ip.items(), key=lambda _ip:_ip[1], reverse=True)

	for i in _urll:
		if _urll.count(i) > 1:
			_url[i] = _urll.count(i)
	url = sorted(_url.items(), key=lambda _url:_url[1], reverse=True)
	
	print "------Nginx access IP NUMS in " + str(times)[1:] + " seconds-------"
	print 'total nums :' + str(_total)
	for k in ip:
		if k[1] > count:
			print k[0],':',k[1],':',ipLocation.ip_location(k[0])
		
	print "-----Nginx access url NUMs in " +str(times)[1:] + " seconds-------"
	print 'total nums :' + str(_total)
	for j in url:
		if j[1] > count:
			print j[0],':',j[1]
			
	


def c_m_Ocurrences(logList):
	_code = {}
	_codes = []
	_meth = {}
	_meths = []
	_total = len(logList)
	for n in logList:
		_meths.append(n.get('method'))
		_codes.append(n.get('code'))
		
	for m in _meths:
		if _meths.count(m) > 0:
			_meth[m] = _meths.count(m)
	meth = sorted(_meth.items(), key=lambda _meth:_meth[1], reverse=True)
	print "------Nginx methods nums in 20 seconds---------"
	print 'total nums :' + str(_total)
	for p in meth:
		per = int(p[1]) / float(_total) * 100
		per = float('%0.3f' % per)
		print p[0],':',p[1],':',str(per) + '%'
			
	for m in _codes:
		if _codes.count(m) > 0:
			_code[m] = _codes.count(m)
	code = sorted(_code.items(), key=lambda _code:_code[1], reverse=True)
	print "------Nginx codes nums in 20 seconds---------"
	print 'total nums :' + str(_total)
	for p in code:
		per = int(p[1]) / float(_total) * 100
		per = float('%0.3f' % per)
		print p[0],':',p[1],':',str(per) + '%'



def getLogItems(weblog,*args):
   '''
      get web log items from mongodb
      '''
   _logD = {}
   logIn = []
   logOut = []
   for i in weblog:
      s = ur'192\.168\.10\.'
      if re.match(s,i.get(u'remotehost')):
         if u'path' in i.keys():
            _url1 = i.get(u'host') + i.get(u'path')
            _logD = {u'ip':i['xforwardedhost'],u'url':_url1,u'time':i['time'],u'from':u'111'}
            if len(args):
               for j in args:
                  _logD[j] = i.get(j)
            
            logIn.append(_logD)
         else:
            _url1 = i.get(u'host')
            _logD = {u'ip':i['xforwardedhost'],u'url':_url1,u'time':i['time'],u'from':u'111'}
            if len(args):
               for j in args:
                  _logD[j] = i.get(j)
            logIn.append(_logD)
      else:
         if u'path' in i.keys():
            _url1 = i.get(u'host') + i.get(u'path')
            _logD = {u'ip':i['remotehost'],u'url':_url1,u'time':i['time']}
            if len(args):
               for j in args:
                  _logD[j] = i.get(j)
            logOut.append(_logD)
         else:
            _url1 = i.get(u'host')
            _logD = {u'ip':i['remotehost'],u'url':_url1,u'time':i['time']}
            if len(args):
               for j in args:
                  _logD[j] = i.get(j)
            logOut.append(_logD)
   return (logIn,logOut)

