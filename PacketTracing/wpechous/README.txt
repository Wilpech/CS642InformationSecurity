Here is how you run my code as further specified on the Piazza post (on my machine it runs just like how your example specifies but please only run one pcap file at a time even though I have error catches for that):

python scanner.py example.py


ARP Spoof:
Basically, we check for flags and then the arp addresses that are being sent in against the hardcoded MAC addresses and if the faulty ones are in the MACs sent to us but are not in the ones we have, then we detect an ARP Spoof and print the message as follows.

Port Scanning:
Basically, we check for flags and I have two methods that scan for port scans, one for TCP and one for UDP and then compiles the packets into a list and then this list is checked through and if the length is longer than 100, then we print out our error message as follows.

SYN Flooding:
Basically, we check for flags and then we create a list of potential victims and then we check each one individually as the requests are coming in and if there are more than 100 requests, we print the error message as follows.