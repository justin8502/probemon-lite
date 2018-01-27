#!/usr/bin/python

import time
import datetime
import argparse
import netaddr
import sys
import logging
import numpy
from scapy.all import *
from pprint import pprint
from logging.handlers import RotatingFileHandler


NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe request frames"

DEBUG = False

def build_packet_callback(time_fmt, logger, delimiter, arr, currindex):
	def packet_callback(packet):
			
		# print currindex[0]

		tempresults = numpy.empty([1, 5], dtype = 'S20')
		
		if(arr[0][0] == ''):
			print "First run" 
			arr[0][0] = 'Z'
		
		if not packet.haslayer(Dot11):
			return

		# we are looking for management frames with a probe subtype
		# if neither match we are done here
		if packet.type != 0 or packet.subtype != 0x04:
			return

		# list of output fields
		fields = []

		# determine preferred time format 
		log_time = str(int(time.time()))
		if time_fmt == 'iso':
			log_time = datetime.now().isoformat()

		fields.append(log_time)
		tempresults[0][0] = log_time

		# append the mac address itself
		fields.append(packet.addr2)
		tempresults[0][1] = packet.addr2

		# parse mac address and look up the organization from the vendor octets
		try:
			parsed_mac = netaddr.EUI(packet.addr2)
			mac = parsed_mac.oui.registration().org
			fields.append('{:20}'.format(mac))
			tempresults[0][2] = mac
		except netaddr.core.NotRegisteredError, e:
			fields.append('{:20}'.format('UNKNOWN'))
			tempresults[0][2] = 'UNKNOWN'

		# include the SSID in the probe frame
		fields.append('{:10}'.format(packet.info))
		tempresults[0][3] = packet.info
			
		rssi_val = -(256-ord(packet.notdecoded[-4:-3]))
		fields.append(str(rssi_val))
		tempresults[0][4] = str(rssi_val)

		# Did we find a unique device?
		if(not(arr[0][2] == tempresults[0][2] and arr[0][1] == tempresults[0][1])):
			for x in range(0, len(tempresults[:, 0])):
				for y in range(0, len(tempresults[0, :])):
					arr[x][y] = tempresults[x][y]

			currindex[0] = currindex[0] + 1
			#print "-------------------------TEMP"
			#for x in range(0, len(tempresults[:, 0])):
			#	for y in range(0, len(tempresults[0, :])):
			#		print tempresults[x][y]
			#print "-------------------------"
		else:
			return

		logger.info(delimiter.join(fields))

	return packet_callback

def main():
	results = numpy.empty([100, 5], dtype = 'S20')
	currindex = [0]
	# print len(results[:, 0])
	# print len(results[0, :])
	# print results

	parser = argparse.ArgumentParser(description=DESCRIPTION)
	parser.add_argument('-i', '--interface', help="capture interface")
	parser.add_argument('-t', '--time', default='iso', help="output time format (unix, iso)")
	parser.add_argument('-o', '--output', default='probemon.log', help="logging output location")
	parser.add_argument('-b', '--max-bytes', default=5000000, help="maximum log size in bytes before rotating")
	parser.add_argument('-c', '--max-backups', default=99999, help="maximum number of log files to keep")
	parser.add_argument('-d', '--delimiter', default='\t', help="output field delimiter")
	parser.add_argument('-D', '--debug', action='store_true', help="enable debug output")
	parser.add_argument('-l', '--log', action='store_true', help="enable scrolling live view of the logfile")
	args = parser.parse_args()

	# print args

	if not args.interface:
		print "error: capture interface not given, try --help"
		sys.exit(-1)
	
	DEBUG = args.debug

	# setup our rotating logger
	logger = logging.getLogger(NAME)
	logger.setLevel(logging.INFO)
	handler = RotatingFileHandler(args.output, maxBytes=args.max_bytes, backupCount=args.max_backups)
	logger.addHandler(handler)
	if args.log:
		logger.addHandler(logging.StreamHandler(sys.stdout))
	built_packet_cb = build_packet_callback(args.time, logger, 
		args.delimiter, results, currindex)
	print "Time" + '\t\t' + "MAC Addr" + '\t\t' + "Vendor" + '\t\t\t' + "Network" +'\t\t' + "RSSID"
	sniff(iface=args.interface, prn=built_packet_cb, store=0)

if __name__ == '__main__':
	main()
