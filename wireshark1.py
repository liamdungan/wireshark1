#!/usr/bin/python

# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
# 1) number of the packets (use number_of_packets),
# 2) list distinct source IP addresses and number of packets for each IP address, in descending order
# 3) list distinct destination TCP ports and number of packers for each port(use tcp_ports, in descending order)
# 4) The number of distinct source IP, destination TCP port pairs, in descending order

import dpkt
import socket
import argparse


# this helper method will turn an IP address into a string
def inet_to_str(inet):
	# First try ipv4 and then ipv6
	try:
		return socket.inet_ntop(socket.AF_INET, inet)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, inet)


# main code
def main():
	number_of_packets = 0       # you can use these structures if you wish
	ips = dict()
	tcp_ports = dict()
	ip_tcp_ports = dict()

	# parse all the arguments to the client
	parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
	parser.add_argument('-f', '--filename', help='pcap file to input', required=True)

	# get the filename into a local variable
	args = vars(parser.parse_args())
	filename = args['filename']

	# open the pcap file for processing
	input_data = dpkt.pcap.Reader(open(filename, 'r'))

	# this main loop reads the packets one at a time from the pcap file
	for timestamp, packet in input_data:
		number_of_packets += 1
		eth = dpkt.ethernet.Ethernet(packet)

		# Only consider IP packet types and ignore others
		if isinstance(eth.data, dpkt.ip.IP):
			ip = eth.data
		else:
			continue

		# ips --> {"Source IP addresses": count}
		if inet_to_str(ip.src) in ips:
			ips[inet_to_str(ip.src)] += 1
		else:
			ips[inet_to_str(ip.src)] = 1

		# tcp_ports --> {"Destination TCP ports": count}
		# ip_tcp_ports --> {"Source IPs/Destination TCP ports": count}
		if ip.p == dpkt.ip.IP_PROTO_TCP:
			tcp = ip.data
			if tcp.dport not in tcp_ports:
				tcp_ports[tcp.dport] = 1
			else:
				tcp_ports[tcp.dport] += 1

			if inet_to_str(ip.src) + ":" + str(tcp.dport) not in ip_tcp_ports:
				ip_tcp_ports[inet_to_str(ip.src) + ":" + str(tcp.dport)] = 1
			else:
				ip_tcp_ports[inet_to_str(ip.src) + ":" + str(tcp.dport)] += 1

		# sort all dicts by value
		sorted_ips_name = sorted(ips, key=ips.get, reverse=True)
		sorted_tcp_ports_name = sorted(tcp_ports, key=tcp_ports.__getitem__, reverse=True)
		sorted_ip_tcp_ports_name = sorted(ip_tcp_ports, key=ip_tcp_ports.__getitem__, reverse=True)

	# print total num of packets
	print "Total number of packets, {0}".format(number_of_packets)

	# print ips in descending order
	print "Source IP addresses,count"
	for key in sorted_ips_name:
		print "{0},{1}".format(key, ips[key])

	# print tcp ports in descending order
	print "Destination TCP ports,count"
	for key in sorted_tcp_ports_name:
		print "{0},{1}".format(str(key), tcp_ports[key])

	# print ip/tcp in descending order
	print "Source IPs/Destination TCP ports,count"
	for key in sorted_ip_tcp_ports_name:
		print "{0},{1}".format(str(key), ip_tcp_ports[key])


# execute a main function in Python
if __name__ == "__main__":
	main()
