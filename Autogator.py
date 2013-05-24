#!/usr/bin/python

# 99% of this code derived from Automator by TekDefense.  Thanks 1aN0rmus 

import csv, httplib2, re, sys, getopt, urllib, urllib2

def main(argv):
  inputfile = ''
	outputfile = ''
	
	try:
		opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
	except getopt.GetoptError:
		print 'h4shit.py -i <inputfile>'
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-h':
			print 'h4shit.py -i <inputfile>'
			sys.exit()
		elif opt in ("-i", "--ifile"):
			inputfile = arg
		elif opt in ("-o", "--ofile"):
			outputfile = arg

	if inputfile == "":
		print "Usage: h4shit.py -i <inputfile>"
		print "No input file specified"
		print ""
		sys.exit(2)
	
	print ""
	print "Looking up ip addresses in:  " + inputfile

	input_file = csv.reader(open(inputfile, 'r'),delimiter='\t')

	for input_row in input_file:
		ipInput = input_row[0]
		a_records = robtex(ipInput)
		category = fortiURL(ipInput)
		blacklist = str(ipvoid_blacklist(ipInput))
		isp = ipvoid_isp(ipInput)
		geo = ipvoid_geo(ipInput)
		print ipInput + "|" + a_records + "|" + category + "|" + blacklist + "|" + isp + "|" + geo

def robtex(ipInput):   
	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open("http://robtex.com/" + ipInput)
	content = response.read()
	contentString = str(content)
	rpd = re.compile('host\.robtex\.com.+\s\>(.+)\<\/a\>', re.IGNORECASE)
	rpdFind = re.findall(rpd,contentString)
	rpdSorted=sorted(rpdFind)
	i=''
	if len(rpdSorted) == 0:
		return "None"
	elif len(rpdSorted) == 1:
		for i in rpdSorted:
			return str(i)
	else:
		return str(len(rpdSorted)) + " domains"
		
def fortiURL(ipInput):
	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open("http://www.fortiguard.com/ip_rep/index.php?data=" + ipInput + "&lookup=Lookup")
	content = response.read()
	contentString = str(content)
	rpd = re.compile('Category:\s(.+)\<\/h3\>\s\<a', re.IGNORECASE)
	rpdFind = re.findall(rpd,contentString)
	rpdSorted=sorted(rpdFind)
	m=''
	for m in rpdSorted:
		return m
	if m =='':
		return ('No Data')

def ipvoid_blacklist(ipInput):
	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open("http://ipvoid.com/scan/" + ipInput)
	content = response.read()
	contentString = str(content)
	rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
	rpdFinderr = re.findall(rpderr,contentString)
	if "ERROR" in str(rpdFinderr):
		return "NoData"
	else:
		rpd = re.compile('Detected\<\/font\>\<\/td..td..a.rel..nofollow..href.\"(.{6,70})\"\stitle\=\"View', re.IGNORECASE)
		rpdFind = re.findall(rpd,contentString)
		rpdSorted=sorted(rpdFind)
		if rpdSorted != "":
			for i in rpdSorted:
				if i != '':
					return 'Blacklists: '+ str(i)
				else:
					return 'N/A'

def ipvoid_isp(ipInput):
	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open("http://ipvoid.com/scan/" + ipInput)
	content = response.read()
	contentString = str(content)
	rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
	rpdFinderr = re.findall(rpderr,contentString)
	if "ERROR" in str(rpdFinderr):
		return "NoData"
	else:
		rpd = re.compile('ISP\<\/td\>\<td\>(.+)\<\/td\>', re.IGNORECASE)
		rpdFind = re.findall(rpd,contentString)
		rpdSorted=sorted(rpdFind)
		if rpdSorted != "":
			for i in rpdSorted:
				if i != '':
					return str(i)
				else:
					return 'N/A'

def ipvoid_geo(ipInput):
	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open("http://ipvoid.com/scan/" + ipInput)
	content = response.read()
	contentString = str(content)
	rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
	rpdFinderr = re.findall(rpderr,contentString)
	if "ERROR" in str(rpdFinderr):
		return "NoData"
	else:
		rpd = re.compile('Country\sCode.+flag\"\s\/\>\s(.+)\<\/td\>', re.IGNORECASE)
		rpdFind = re.findall(rpd,contentString)
		rpdSorted=sorted(rpdFind)
		if rpdSorted != "":
			for i in rpdSorted:
				if i != '':
					return str(i)
				else:
					return 'N/A'

if __name__ == "__main__":
	main(sys.argv[1:])
