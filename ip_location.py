#!/usr/bin/env python
# -*- coding: utf-8 -*-
# the script is used to query the location of every ip
 
import urllib
import json
 
#taobao ip interfaces
url = "http://ip.taobao.com/service/getIpInfo.php?ip="
 
def ip_location(ip):
	data = urllib.urlopen(url + ip).read()
	datadict=json.loads(data)
 
	for oneinfo in datadict:
		if "code" == oneinfo:
			if datadict[oneinfo] == 0:
				return datadict["data"]["country"] + datadict["data"]["region"] + datadict["data"]["city"] + "\t\t" + datadict["data"]["isp"]
