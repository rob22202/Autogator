#!/usr/bin/python

# 99% of this code derived from Automator by 1aN0rmus from http://www.tekdefense.com/
# This verion is made for mass ip information lookups and outputs in tabular format 
# The original (with many more bells and whitstles than Autogator) is at https://github.com/1aN0rmus/TekDefense/blob/master/Automater.py
# Usage: Autogator.py -i <inputfile>
# The input file should contain a \n delimited list of ip addresses.
# rob22202@gmail.com, rob22202 on github

# Updated 05/28/2013 - Addded Reverse DNS

import socket, csv, httplib2, re, sys, getopt, urllib, urllib2

def main(argv):
	inputfile = ''
	outputfile = ''
	
	try:
		opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
	except getopt.GetoptError:
		print 'Autogator.py -i <inputfile>'
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-h':
			print 'Autogator.py -i <inputfile>'
			sys.exit()
		elif opt in ("-i", "--ifile"):
			inputfile = arg
		elif opt in ("-o", "--ofile"):
			outputfile = arg

	if inputfile == "":
		print "Usage: Autogator.py -i <inputfile>"
		print "No input file specified"
		print ""
		sys.exit(2)
	
	print ""
	print "Looking up ip addresses in:  " + inputfile

	input_file = csv.reader(open(inputfile, 'r'),delimiter='\t')

        for input_row in input_file:
                ipInput = input_row[0]
                reverse = reverse_dns(ipInput)
                a_records = robtex(ipInput)
                category = fortiURL(ipInput)
                blacklist = str(ipvoid_blacklist(ipInput))
                isp = ipvoid_isp(ipInput)
                geo = ipvoid_geo(ipInput)
                print ipInput + "|" + reverse  + "|" + a_records + "|" + category + "|" + blacklist + "|" + isp + "|" + geo

def reverse_dns(ipInput):
        try:
                reverse_info = socket.gethostbyaddr(ipInput)
                return reverse_info[0]
        except:
                return "None Found"

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
		return "None Found"
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
		return ('None Found')

def ipvoid_blacklist(ipInput):
	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open("http://ipvoid.com/scan/" + ipInput)
	content = response.read()
	contentString = str(content)
	rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
	rpdFinderr = re.findall(rpderr,contentString)
	if "ERROR" in str(rpdFinderr):
		return "None Found"
	else:
		rpd = re.compile('Detected\<\/font\>\<\/td..td..a.rel..nofollow..href.\"(.{6,70})\"\stitle\=\"View', re.IGNORECASE)
		rpdFind = re.findall(rpd,contentString)
		rpdSorted=sorted(rpdFind)
		if rpdSorted != "":
			for i in rpdSorted:
				if i != '':
					return str(i)
				else:
					return 'None Found'

def ipvoid_isp(ipInput):
	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open("http://ipvoid.com/scan/" + ipInput)
	content = response.read()
	contentString = str(content)
	rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
	rpdFinderr = re.findall(rpderr,contentString)
	if "ERROR" in str(rpdFinderr):
		return "None Found"
	else:
		rpd = re.compile('ISP\<\/td\>\<td\>(.+)\<\/td\>', re.IGNORECASE)
		rpdFind = re.findall(rpd,contentString)
		rpdSorted=sorted(rpdFind)
		if rpdSorted != "":
			for i in rpdSorted:
				if i != '':
					return str(i)
				else:
					return 'None Found'

def ipvoid_geo(ipInput):
	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open("http://ipvoid.com/scan/" + ipInput)
	content = response.read()
	contentString = str(content)
	rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
	rpdFinderr = re.findall(rpderr,contentString)
	if "ERROR" in str(rpdFinderr):
		return "None Found"
	else:
		rpd = re.compile('Country\sCode.+flag\"\s\/\>\s(.+)\<\/td\>', re.IGNORECASE)
		rpdFind = re.findall(rpd,contentString)
		rpdSorted=sorted(rpdFind)
		if rpdSorted != "":
			for i in rpdSorted:
				if i != '':
					return str(i)
				else:
					return 'None Found'

if __name__ == "__main__":
	main(sys.argv[1:])
