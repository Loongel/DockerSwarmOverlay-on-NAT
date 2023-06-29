from swarmnat.utils.nodes import Nodes, Node, NetworkType, NatNodesRelays
import chardet
import yaml

class Config:
    def __init__(self, nodes, nat_nodes_relays, ingress_port):
        self.nodes = nodes
        self.nat_nodes_relays = nat_nodes_relays
        self.ingress_port = ingress_port

def _check_config(config_data):
    # Check if all nodes are valid
    for node in config_data['nodes']:
        if node['type'] not in NetworkType.__members__:
            print(f"Invalid node type: {node['type']}")
            return False
        elif getattr(NetworkType, node['type'])  == NetworkType.TYPE_5:
            # Check if all TYPE_5 nodes are in the relay table
            node_in_relay_table = False
            for  relay_data in config_data['nat_nodes_relays']:
                if node['hostname'] in relay_data['nat']:
                    node_in_relay_table = True
                    break
            if not node_in_relay_table:
                print(f"TYPE_5 node {node['hostname']} not found in relay table")
                return False
    try:
        ingress_port = int(config_data['ingress_port'][0])
        if not 0< ingress_port <= 65535:
            print(f"The config of ingress_port is invaid")
            return False
    except (ValueError, TypeError):
        print(f"The config of ingress_port is invaid")
        return False
    return True 
        
def read_config_file(file_path):    
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        encoding = chardet.detect(raw_data)['encoding']
    with open(file_path, 'r', encoding=encoding) as f:
        config_data = yaml.load(f, Loader=yaml.FullLoader)
    
    if _check_config(config_data):
        nodes = []
        ingress_port = int(config_data['ingress_port'][0])
        for node_data in config_data['nodes']:
            node_type = getattr(NetworkType, node_data['type'])
            node = Node(node_type, node_data['hostname'], node_data['internal_ip'], node_data['external_ip'])
            nodes.append(node)
            
        nat_nodes_relays_list =[]
        for relay_data in config_data['nat_nodes_relays']:
            relay = relay_data['relay']
            nat = relay_data['nat']
            nat_nodes_relays_list.append({"relay": relay, "nat": nat})
        nat_nodes_relays = NatNodesRelays(nat_nodes_relays_list, ingress_port)
        
        return Config(Nodes(nodes, nat_nodes_relays), nat_nodes_relays, ingress_port)
    else:
        return None


