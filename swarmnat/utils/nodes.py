import socket
from enum import Enum
  
#定义NatNodesRelays类，用于存储nat节点和relay节点的关系
class NatNodesRelays:
    
    #静态方法，用于生成连接列表及连接号（relay port）
    @staticmethod
    def _generate_connection_lists(nats, ingress_port:int=4789):
        single_relay_list = {}
        double_relay_list = {}
        connection_id = ingress_port-1 

        # 第一个列表：包含第一列和第三列，第二列为 None
        for i in range(len(nats)):
            node = nats[i]
            hostname = node['nat']
            single_relay_list[hostname] = [None, connection_id]
            connection_id -= 1

        # 第二个列表：同原来的要求，不同网关下的节点需要互相连接，连接标识递减
        for i in range(len(nats)):
            node1 = nats[i]
            gateway1 = node1['relay']
            hostname1 = node1['nat']
            for j in range(i + 1, len(nats)):
                node2 = nats[j]
                gateway2 = node2['relay']
                hostname2 = node2['nat']
                if gateway1 != gateway2:
                    double_relay_list[connection_id] = [(hostname1, hostname2), (gateway1, gateway2)]
                    connection_id -= 1

        return single_relay_list, double_relay_list
   
    def get_relay_port_by_nat(self, host1, host2=None):
        # 在 single_relay_list 中查询连接号
        if host1 in self.single_relay_list and (host2 is None or host2 not in self.single_relay_list):
            return self.single_relay_list[host1][1]
        elif host2 in self.single_relay_list and (host1 is None or host1 not in self.single_relay_list):
            return self.single_relay_list[host2][1]
        # 在 double_relay_list 中查询连接号
        for connection_id, (hosts, _) in self.double_relay_list.items():
            if host1 in hosts and host2 in hosts:
                return connection_id
        return None

    def get_connection_host_by_relay_port(self, connection_id):
        if connection_id in self.double_relay_list:
            return self.double_relay_list[connection_id]
        return None

    def get_other_host_by_relay_port(self, connection_id, host):
        if connection_id in self.double_relay_list:
            hosts, gateways = self.double_relay_list[connection_id]
            if (host == hosts[0]) or (host == gateways[0]):
                return {
                    'host': hosts[1],
                    'relay': gateways[1]
                }
            elif host == hosts[1] or host == gateways[1]:
                return {
                    'host': hosts[0],
                    'relay': gateways[0]
                }
        return None
    
    def get_relay_hostname_by_nat(self, nat_hostname):
        # self.nats是一个列表，列表中的每个元素是一个字典，字典中有两个key，一个是relay，一个是nat
        # 从self.nats中找到nat_hostname对应的字典，然后取出字典中的relay值
        for nat in self.nats:
            if nat["nat"] == nat_hostname:
                return nat["relay"] 
    
        
    def __init__(self,nat_nodes_relays_list=None, ingress_port:int=4789) -> None:
        
        self.nat_nodes_relays_list = [] if nat_nodes_relays_list is None else nat_nodes_relays_list

        # 根据nat_nodes_relays_list获取到一个relays去重列表，一个nats去重列表[{"relay":"","nat":""}] 
        self.relays = list()
        self.nats = list()

        for nat_nodes_relay in self.nat_nodes_relays_list:
            self.relays.append(nat_nodes_relay["relay"])
            nats_tmp =[{"relay":nat_nodes_relay["relay"],"nat":nat} for nat in nat_nodes_relay["nat"]]
            self.nats.extend(nats_tmp)

        # 对relays列表去重
        self.relays = list(set(self.relays))

        # 对nats列表去重
        self.nats = list(set([frozenset(nat.items()) for nat in self.nats]))
        self.nats = [dict(nat) for nat in self.nats]
        self.single_relay_list, self.double_relay_list = self._generate_connection_lists(self.nats, ingress_port)
      
class NetworkType(Enum):
    TYPE_1 = "节点有独立公网IP，且公网IP就在接口上"
    TYPE_2 = "节点有独立公网IP，但是通过内网IP ip映射 nat 到公网IP上,内网中无其余待参与组网的节点"
    TYPE_3 = "节点有独立公网IP，但是通过内网IP ip映射 nat 到公网IP上，内网中有其余待参与组网的节点，网络情况同3"
    TYPE_4 = "节点有独立公网IP，但是通过内网IP ip映射 nat 到公网IP上，内网中有其余待参与组网的节点，网络情况同5"
    TYPE_5 = "节点有无独立公网IP，但与d类型节点在同一内网中，可互通"

class Node:
    def __init__(self, network_type=None, hostname=None, local_ip=None, external_ip=None, subnet_node_hostname=set([])):

        self.network_type = network_type if network_type is not None else None
        self.hostname = hostname if hostname is not None else None
        self.external_ip = external_ip if external_ip is not None else None
        if self.network_type == NetworkType.TYPE_1:
             self.local_ip = self.external_ip
        else:
            self.local_ip = local_ip if local_ip is not None else None
        self.relay_node:Node = None
        self.relay_hostname = None
        self.subnet_node:set(Node) = set([])
        self.subnet_node_ip = set([])
        self.subnet_node_hostname = subnet_node_hostname if subnet_node_hostname is not set([]) else set([])   
    
    def __eq__(self, other):
        if isinstance(other, Node):
            return self.hostname == other.hostname
        return False
    
    def __hash__(self):
        return hash(self.hostname)
    
    def get_relay_port(self):
        pass
    
    def get_be_relayed_node(self,func):
        return func()
    
class Nodes:

    def get_local_ip_by_hostname(self, hostname=None):
        if hostname is None:
            return None
        else:
            for node in self.nodes:
                return node.local_ip if node.hostname == hostname else None

    def get_external_ip_by_hostname(self, hostname=None):
        if hostname is None:
            return None
        else:
            for node in self.nodes:
                return node.external_ip if node.hostname == hostname else None

    def get_local_ip_by_external_ip(self, external_ip=None):
        if external_ip is None:
            return None
        else:
            for node in self.nodes:
                return node.local_ip if node.external_ip == external_ip else None
                

    def get_external_ip_by_local_ip(self, local_ip=None):
        if local_ip is None:
            return None
        else:
            for node in self.nodes:
                return node.external_ip if node.local_ip == local_ip else None
            
    def _init_nodes_relay_info (self, nat_nodes_relays:NatNodesRelays):
        # 根据nat_nodes_relays信息 （NatNodesRelays类），将本node的relay和subnet相关进行信息初始化      
        for node in self.nodes:
            node.relay_hostname = nat_nodes_relays.get_relay_hostname_by_nat(node.hostname)
            # for debug 
            # if node.hostname == "DESKTOP-SKPL5RD":
            #     print("DESKTOP-SKPL5RD")
            node.relay_node = next((n for n in self.nodes if n.hostname == node.relay_hostname), None)
            node_relay_host = node.hostname if node.hostname in nat_nodes_relays.relays else node.relay_hostname
            if node_relay_host is not None:
                def make_get_relay_port(node):
                    def get_relay_port(node2: Node):
                        return nat_nodes_relays.get_relay_port_by_nat(node.hostname, node2.hostname)
                    return get_relay_port
                node.get_relay_port = make_get_relay_port(node)
                #node.relay_port = nat_nodes_relays.get_relay_port_by_nat(node.hostname)
                node.subnet_node_hostname.update([n["nat"] for n in nat_nodes_relays.nats if n["relay"] == node_relay_host]+[node_relay_host])
                node.subnet_node.update([n for n in self.nodes if n.hostname in node.subnet_node_hostname and n != node])
                node.subnet_node_ip.update([node.local_ip for node in node.subnet_node])

    def get_local_node(self) -> Node:
        # 获取本机节点
        localnode = [node for node in self.nodes if node.hostname == socket.gethostname()]
        if len(localnode) > 0:
            return localnode[0]
        else:
            raise Exception("Local node not found. It is recommended to check your config.yml file, whether the current node information exists in the configuration file.")
        


    def __init__(self, nodes:list[Node], nat_nodes_relays:NatNodesRelays) -> None:
        self.nodes = nodes
        self._init_nodes_relay_info(nat_nodes_relays)

    def __iter__(self):
        for node in self.nodes:
            yield node

    def __len__(self):
        return len(self.nodes)
        
    def __getitem__(self, index):
        return self.nodes[index]
