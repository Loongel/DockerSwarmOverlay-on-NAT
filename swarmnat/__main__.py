"""Swarm Nat Tools: help docker swarm overlay nodes work on nat networks"""

from swarmnat.utils.nodes import Node, Nodes, NetworkType, NatNodesRelays
from swarmnat.utils.network_manager import NetworkManager
from swarmnat.config import read_config_file

def main():
    # Initialize nodes and nat_nodes_relays
    
    conf = read_config_file('config.yml')
    if conf is None:
        print("Invalid config file")
        return
    
    nodes = Nodes(
        # 注意：各节点的主机名不能重复
        nodes = conf.nodes,
        nat_nodes_relays = conf.nat_nodes_relays
    )
    network_manager = NetworkManager(nodes)

    # 根据通讯链路查找本机节点的nat任务，并执行
    network_manager.handle_on_chains()

if __name__ == "__main__":
    main()

