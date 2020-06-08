import math, optparse, random, sys, time, socket, struct
from collections import deque
import dpkt

# since there is no reason to detect any MACs, we are
# just going to be hardcoding them into the program
# it also must be in hex format
class victim(object):
	macAdds = {
	'\xC0\xA8\x00\x64': '\x7C\xD1\xC3\x94\x9E\xB8',
	'\xC0\xA8\x00\x67': '\xD8\x96\x95\x01\xA5\xC9',
	'\xC0\xA8\x00\x01': '\xF8\x1A\x67\xCD\x57\x6E',
	}

# for the various attacks to defend against	
portScan = {}
synFlood = {}

def initialize(self):
	usage = '%prog <pcap>'
	self.op = optparse.OptionParser(usage=usage)
	
def addOutput(self, addr):
	return ':'.join(x.encode('hex') for x in addr)
	
def ipOutput(self,addr):
	return socket.inet_ntoa(addr)
	
def pktOutput(self, pkts):
	return '[%s]' % ','.join(str(pkt['num']) for pkt in pkts)
	
def arpSpoofDetection(self, arp, num):
	if arp.spa in self.macAdds and arp.sha != self.macAdds[arp.spa]:
		print 'ARP spoofing!'
		print 'Src MAC: %s' % (self.addOutput(self.macAdds[arp.spa],arp))
		print 'Dst MAC: %s' % (self.adOutput(self,arp))
		print 'Packet number: %d' % (num)
		
def portScanDetectionTCP(self, tcp, ip, num):
	if tcp.flags == dpkt.tcp.TH_SYN:
		self.portScanDetection(tcp.dport, ip, num)
	
def portScanDetectionUDP(self, udp, ip, num):
	self.portScanDetection(udp.dport, ip, num)
	
def portScanDetection(self, port, ip, num):
	if ip.dst in self.portScan[ip.dst]
		pkts = self.portScan[ip.dst]
		for pkt in pkts:
			if port == pkt['port']:
				return
			pkts.append({'src': ip.src, 'dst': ip.dst, 'num': num, 'port': port}]
			else:
				self.portScan[ip.dst] = [{'src': ip.src, 'dst': ip.dst, 'num': num, 'port': port}]
				
def portScanComplete(self):
	for dst in self.portScan:
		pkts = self.portScan[dst]
		if len(pkts) > 100:
			print 'Port scan!:'
			print 'Dst IP: %s' % (self.ipOutput(pkts[0]['dst']))
			print 'Packet number: %s' % (self.pktOutput(pkts))
			
def synFloodDetection(self, tcp, ip, ts, num):
	if tcp.flags == dpkt.tcp.TH_SYN:
		dst = ip.dst+':'+str(tcp.dport)
		if dst in self.synFlood:
			pkts = self.synFlood[dst]
			while len(pkts) > 0:
				pkt = pkts[0]
				if ts - pkt['ts'] >= 1:
					pkts.popleft()
				else:
					break
					
			pkts.append({'src': ip.src, 'dst': ip.dst, 'num': num, 'port': tcp.dport, 'ts': ts})
			
			if len(pkts) > 100:
				print 'SYN floods!'
				print 'Dst IP: %s' % (self.ipOutput(pkts[0]['dst']) 
				print 'Dst Port: %s' % (self.pktOutput(pkts[0]['port'])
				print 'Packet number: %s' % (self.pktOutput(pkts))
				pkts.clear()
		else:
			self.synFlood[dst] = deque([{'src': ip.src, 'dst': ip.dst, 'num': num, 'port': tcp.dport, 'ts': ts}])
			
def main(self, argv=None):
	if not argv:
		argv = sys.argv[1:]
	opts, args = self.op.parse_args(argv)
	
	if not args:
		self.op.error('PCAP file missing???')
	elif len(args) > 1:
		self.op.error('one at a time please')
		
	f = open(args[0])
	pcap = dpkt.pcap.Reader(f)
	
	
	for idx, (ts, buf) in enumerate(pcap):
		num = idx + 1
		eth = dpkt.ethernet.Ethernet(buf)
		level3 = eth.data
		if type(level3) is dpkt.arp.ARP:
			self.arpSpoofDetection(level3, num)
		elif type(level3) is dpkt.ip.IP:
			level4 = level3.data
			if type(level4) is dpkt.tcp.TCP:
				self.portScanDetectionTCP(level4, level3, num)
				self.synFloodDetection(level4, level3, ts, num)
			elif type(level4) is dpkt.udp.UDP:
				self.portScanDetectionUDP(level4, level3, num)
			
		
	self.portScanComplete()
	
	f.close()
