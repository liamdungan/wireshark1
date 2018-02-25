# wireshark1


## About

This program uses the Python [dkpt library](https://dpkt.readthedocs.io/en/latest/) to read files of saved network packets, and outputs a report of the number of different packet types.

Given a pcap file as input, the program will output packet counts in csv format. The output report will consist of 4 sections, where each section will be prefaced by a header string.

1. The number of all packets, which includes all types. 
2. A list of distinct source IP addresses and number of packets for each IP address, including all types of IP packets, such as TCP, UDP ICMP, etc, sorted in descending order of the number of packets from a given source IP address. The IP address should be printed in dotted-decimal notation, and the count as a decimal integer. 
3. A list distinct destination TCP ports and number of packers for each port, also sorted in descending order of the number of packets from a given destination TCP port.  The port and count should be printed as decimal integers. 
4. A list of unique source IP/Destination TCP port pairs. The list The number of distinct source IP, destination TCP port pairs, in decreasing count of each pair. The source IP, in dotted decimal, and destination port, as an integer, must be separated by a ":". 
..* E.g., 192.168.2.22:80.  

## Usage

python wireshark1.py -f small.pcap