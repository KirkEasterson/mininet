from ptf.testutils import group
from lib.base_test import *


# The variables below are from the Mininet session
hosts = ['h1', 'h2']
macs = {'h2': 'b2:ff:48:c9:17:30', 'h1': '32:44:c7:03:cd:83'}
ips = {'h2': '10.0.0.2/8', 'h1': '10.0.0.1/8'}

class FirstTest(P4RuntimeTest):

	def runTest(self):
		pkts = []
		
		print("Sending packet - h1 -> h2")
		pkt1 = testutils.simple_tcp_packet(
		                        eth_src=macs["h1"],
		                        eth_dst=macs["h2"],
		                        ip_src=ips["h1"],
		                        ip_dst=ips["h2"])
		pkts.append(pkt1)
		
		
		print("Sending packet - h2 -> h1")
		pkt2 = testutils.simple_tcp_packet(
		                        eth_src=macs["h2"],
		                        eth_dst=macs["h1"],
		                        ip_src=ips["h2"],
		                        ip_dst=ips["h1"])
		pkts.append(pkt2)
		
		
		for pkt in pkts:
		    for outport in [self.port1, self.port2]:
		        packet_out_msg = self.helper.build_packet_out(
		            payload=str(pkt),
		            metadata={
		                "egress_port": outport,
		                "_pad": 0
		            })
		
		        self.send_packet_out(packet_out_msg)
		        testutils.verify_packet(self, pkt, outport)
		
		    testutils.verify_no_other_packets(self)
		
