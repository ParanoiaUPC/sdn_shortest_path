# author: ParanoiaUPC
# email: 757459307@qq.com
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types

import networkx as nx
import ArpHandler

class ShortestPath(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "ArpHandler": ArpHandler.ArpHandler
    }

    def __init__(self, *args, **kwargs):
        super(ShortestPath, self).__init__(*args, **kwargs)
        self.arp_handler = kwargs["ArpHandler"]
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        dpid = datapath.id
        self.datapaths[dpid] = datapath        

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        ignore_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        ignore_actions = []
        self.add_flow(datapath, 65534, ignore_match, ignore_actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            In packet_in handler, we need to learn access_table by ARP.
            Therefore, the first packet from UNKOWN host MUST be ARP.
        '''
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        eth_type = eth_pkt.ethertype
        if eth_type == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            if len(pkt.get_protocols(ethernet.ethernet)):
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        result = self.arp_handler.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
        else:
            self.flood(msg)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def flood(self, msg):
        """
            Flood ARP packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.arp_handler.access_ports:
            for port in self.arp_handler.access_ports[dpid]:
                if (dpid, port) not in self.arp_handler.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            To calculate shortest forwarding path and install them into datapaths.

        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result:
            src_sw, dst_sw, to_dst_port = result[0], result[1], result[2]
            if dst_sw:
                # Path has already calculated, just get it.
                to_dst_match = parser.OFPMatch(
                    eth_type = eth_type, ipv4_dst = ip_dst)
                port_no = self.arp_handler.set_shortest_path(ip_src, ip_dst, src_sw, dst_sw, to_dst_port, to_dst_match)
                self.send_packet_out(datapath, msg.buffer_id, in_port, port_no, msg.data)
        return

    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None
        dst_port = None

        src_location = self.arp_handler.get_host_location(src)
        if in_port in self.arp_handler.access_ports[dpid]:
            if (dpid,  in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None

        dst_location = self.arp_handler.get_host_location(dst)
        if dst_location:
            dst_sw = dst_location[0]
            dst_port = dst_location[1]
        return src_sw, dst_sw, dst_port

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)