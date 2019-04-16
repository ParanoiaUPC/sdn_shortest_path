# author: ParanoiaUPC
# email: 757459307@qq.com
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import api as topo_api
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_link, get_switch
from ryu.lib.ofp_pktinfilter import packet_in_filter, RequiredTypeFilter

import networkx as nx
import random

class ArpHandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ArpHandler, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.link_to_port = {}       # (src_dpid,dst_dpid)->(src_port,dst_port)
        self.link_delay = {}
        self.access_table = {}       # {(sw,port) :[host1_ip]}
        self.switch_port_table = {}  # dpip->port_num
        self.access_ports = {}       # dpid->port_num
        self.interior_ports = {}     # dpid->port_num
        self.graph = nx.DiGraph()
        self.dps = {}
        self.switches = None
        self.discover_thread = hub.spawn(self._discover)

    def _discover(self):
        i = 0
        while True:
            self.get_topology(None)
            hub.sleep(1)

    def get_topology(self, ev):
        """
            Get topology info
        """
        # print "get topo"
        switch_list = get_all_switch(self)
        # print switch_list
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()
        links = get_link(self.topology_api_app, None)
        self.create_interior_links(links)
        self.create_access_ports()
        self.get_graph()

    def create_port_map(self, switch_list):
        for sw in switch_list:
            dpid = sw.dp.id
            self.graph.add_node(dpid)
            self.dps[dpid] = sw.dp
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def create_interior_links(self, link_list):
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # Find the access ports and interiorior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    def create_access_ports(self):
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port

    def get_graph(self):
        link_list = topo_api.get_all_link(self)
        for link in link_list:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            if (src_dpid, dst_dpid) not in self.link_delay.keys():
                x = random.randint(1, 501)
                self.link_delay[(src_dpid, dst_dpid)] = x
                self.link_delay[(dst_dpid, src_dpid)] = x
            self.graph.add_edge(src_dpid, dst_dpid,
                                src_port=src_port,
                                dst_port=dst_port,
                                delay=self.link_delay[(src_dpid, dst_dpid)])
        return self.graph

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth_type == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if ip_pkt:
            src_ipv4 = ip_pkt.src
            src_mac = eth_pkt.src
            if src_ipv4 != '0.0.0.0' and src_ipv4 != '255.255.255.255':
                self.register_access_info(datapath.id, in_port, src_ipv4, src_mac)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac

            # Record the access info
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)

    def register_access_info(self, dpid, in_port, ip, mac):
        """
            Register access host info into access table.
        """
        # print "register " + ip
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return

    def get_host_location(self, host_ip):
        """
            Get host location info:(datapath, port) according to host ip.
        """
        for key in self.access_table.keys():
            if self.access_table[key][0] == host_ip:
                return key
        self.logger.debug("%s location is not found." % host_ip)
        return None

    def get_switches(self):
        return self.switches

    def get_links(self):
        return self.link_to_port

    def get_datapath(self, dpid):
        if dpid not in self.dps:
            switch = topo_api.get_switch(self, dpid)[0]
            self.dps[dpid] = switch.dp
            return switch.dp
        return self.dps[dpid]

    def set_shortest_path(self,
                          ip_src,
                          ip_dst,
                          src_dpid, 
                          dst_dpid, 
                          to_port_no,
                          to_dst_match,
                          pre_actions=[]
                          ):
        if nx.has_path(self.graph, src_dpid, dst_dpid):
            path = nx.shortest_path(self.graph, src_dpid, dst_dpid, weight="delay")
        else:
            path = None
        if path is None:
            self.logger.info("Get path failed.")
            return 0
        if self.get_host_location(ip_src)[0] == src_dpid:
            paths = nx.all_shortest_paths(self.graph, src_dpid, dst_dpid)
            print "All the shortest from " + ip_src + " to " + ip_dst + " are:"
            for spath in paths:
                tmp_delay = 0
                for i in range(len(spath)-1):
                    tmp_delay = tmp_delay + self.graph[spath[i]][spath[i+1]]['delay']
                    # print path[i], path[i+1], self.graph[path[i]][path[i+1]]['delay']
                print ip_src + ' ->',
                print spath,
                print "-> " + ip_dst,
                print "     delay: " + str(tmp_delay)
            print "Shortest path from " + ip_src + " to " + ip_dst +'is:'
            print ip_src + ' ->',
            for sw in path:
                print str(sw) + ' ->',
            print ip_dst
        if len(path) == 1:
            dp = self.get_datapath(src_dpid)
            actions = [dp.ofproto_parser.OFPActionOutput(to_port_no)]
            self.add_flow(dp, 10, to_dst_match, pre_actions+actions)
            port_no = to_port_no
        else:
            self.install_path(to_dst_match, path, pre_actions)
            dst_dp = self.get_datapath(dst_dpid)
            actions = [dst_dp.ofproto_parser.OFPActionOutput(to_port_no)]
            self.add_flow(dst_dp, 10, to_dst_match, pre_actions+actions)
            port_no = self.graph[path[0]][path[1]]['src_port']

        return port_no

    def install_path(self, match, path, pre_actions=[]):
        for index, dpid in enumerate(path[:-1]):
            port_no = self.graph[path[index]][path[index + 1]]['src_port']
            dp = self.get_datapath(dpid)
            actions = [dp.ofproto_parser.OFPActionOutput(port_no)]
            self.add_flow(dp, 10, match, pre_actions+actions)

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

