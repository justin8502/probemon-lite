#!/usr/bin/python

import time
import datetime
import argparse
import netaddr
import sys
import logging
import numpy
import manuf
import os
from scapy.all import *
from pprint import pprint
from logging.handlers import RotatingFileHandler


NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe request frames"

DEBUG = False

def build_packet_callback(time_fmt, logger, delimiter, results, p):
	def packet_callback(packet):
		uniqmac = True
		#print len(results)

		tempresults = ["", "", "", "", "", len(results), "1"]
		
		#if not results:
		#	print "First run"
		
		if not packet.haslayer(Dot11):
			return

		# we are looking for management frames with a probe subtype
		# if neither match we are done here
		if packet.type != 0 or packet.subtype != 0x04:
			return

		# list of output fields
		fields = []

		# determine preferred time format 
		log_time = datetime.now().strftime("%H:%M:%S")

		fields.append(log_time)
		tempresults[0] = log_time

		# append the mac address itself
		fields.append(packet.addr2)
		tempresults[1] = packet.addr2

		# parse mac address and look up the organization from the vendor octets
		try:
			parsed_mac = netaddr.EUI(packet.addr2)
			if parsed_mac in results:
				uniqmac = False
			mac = p.get_manuf(str(parsed_mac))
			if type(mac) == type(None):
				return
			fields.append('{:20}'.format(mac[:20]))
			tempresults[2] = mac
		except netaddr.core.NotRegisteredError, e:
			fields.append('{:20}'.format('UNKNOWN'))
			tempresults[2] = 'UNKNOWN'

		# include the SSID in the probe frame if new device
		if uniqmac:
			fields.append('{:12}'.format(packet.info[:12]))
			tempresults[3] = packet.info
		else:
			if results[parsed_mac][3] == "":
				fields.append('{:12}'.format(packet.info[:12]))
				tempresults[3] = packet.info
			else:
				if packet.info != "":
					results[parsed_mac][3] = packet.info
				fields.append(results[parsed_mac][3][:12])
			
		rssi_val = -(256-ord(packet.notdecoded[-4:-3]))
		fields.append(str(rssi_val))
		tempresults[4] = str(rssi_val)
		# Did we find a unique device?
		if uniqmac:
			results[parsed_mac] = tempresults
			fields.append(tempresults[6])
		else:
			results[parsed_mac][6] = str(int(results[parsed_mac][6]) + 1)
			fields.append(results[parsed_mac][6])

			lines_modify = len(results)- results[parsed_mac][5]

			#if results[parsed_mac][3] == "":
			#	results[parsed_mac][3] = tempresults[3]

			backline(lines_modify)
			logger.info(delimiter.join(fields))
			forwardline(lines_modify -1)
			return

		logger.info(delimiter.join(fields))

	return packet_callback

def backline(times):
	for x in range(0, times):
		sys.stdout.write("\033[F")
		# sys.stdout.write("\033[K")

def forwardline(times):
	if times < 0:
		return
	for x in range(0, times):
		sys.stdout.write("\n")	

def main():

	parser = argparse.ArgumentParser(description=DESCRIPTION)
	parser.add_argument('-i', '--interface', help="capture interface")
	parser.add_argument('-t', '--time', default='iso', help="output time format (unix, iso)")
	parser.add_argument('-o', '--output', default='probemon.log', help="logging output location")
	parser.add_argument('-b', '--max-bytes', default=5000000, help="maximum log size in bytes before rotating")
	parser.add_argument('-c', '--max-backups', default=99999, help="maximum number of log files to keep")
	parser.add_argument('-d', '--delimiter', default='\t', help="output field delimiter")
	parser.add_argument('-D', '--debug', action='store_true', help="enable debug output")
	args = parser.parse_args()

	if not args.interface:
		print "error: capture interface not given, try --help"
		sys.exit(-1)
	
	DEBUG = args.debug

	clear = lambda: os.system('cls' if os.name=='nt' else 'clear')
	clear()

	# setup our rotating logger
	logger = logging.getLogger(NAME)
	logger.setLevel(logging.INFO)
	handler = RotatingFileHandler(args.output, maxBytes=args.max_bytes, backupCount=args.max_backups)
	logger.addHandler(handler)
	logger.addHandler(logging.StreamHandler(sys.stdout))
	built_packet_cb = build_packet_callback(args.time, logger, 
		args.delimiter, {}, manuf.MacParser())
	print '\n' + "Time" + '\t\t' + "MAC Addr" + '\t\t' + "Vendor" + '\t\t\t' + "Network" +'\t\t' + "RSSID" + '\t' + "#Data" + '\n'
	#print("FAILED...")
	#backline(4)

	sniff(iface=args.interface, prn=built_packet_cb, store=0)

if __name__ == '__main__':
	main()
