import ipaddress
import subprocess
from pandas import DataFrame as df
import pandas as pd
from enum import Enum
import os

from swarmnat.utils.nodes import Nodes, Node, NetworkType

class NetworkManager:
    def __init__(self, nodes:Nodes , ingress_port:int=4789):
        self.ingress_port = ingress_port
        self.nodes = nodes
        self.local_node = nodes.get_local_node()
        # 定义chain处理的任务列表dataframe的数据结构
        # chain_tasks = df([{chain:node1:port -> node2:port,chain_type:..., tasks:[ {node:node1,task:{nat_mode:,src_ip:,src_port:,dst_ip:,dst_port:,to_ip:,to_port:,chain_type:},
        #                                                                           {node:node2,task:{nat_mode:,src_ip:,src_port:,dst_ip:,dst_port:,to_ip:,to_port:,chain_type:}}] 
        #}])
        # 初始化一个空的 chain_tasks
        self.chain_tasks = df()

    @staticmethod
    def _add_nat_rule(deduplicate=True, insert_mode="I", task_type="nat", mark=None, nat_mode="dnat", chain="OUTPUT", protocol="all", \
        match_src_ip=None, match_src_port=None, match_dst_ip=None, match_dst_port=None, to_ip=None, to_port=None):
        
        def command_executor(cmd, for_check=False):
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                if for_check:                   
                    print(f"Checked None Rule Before: {cmd} stdout: {stderr}")
                    return True
                else:
                    print(f"CMD exec FAIL ! !!! : {cmd} error: {stderr}")
                    return False               
            else:
                if for_check:
                    #check if rule exists 返回0 代表该规则已经存在 check not pass
                    print(f"Rule Duplicated ! : {cmd}  error: {stdout}")
                    return False
                else:
                    print(f"CMD EXE SUCCES: {cmd} stdout: {stdout}")
                    return True
        
        #当 nat_mode="snat", chain="PREROUTING"时，因iptables限制，需新增自定义链，如 PRE_NAT_DOCKER_RELAY  
        if nat_mode == "snat" and chain == "PREROUTING":
            cmd1=f"iptables -t nat -N PRE_NAT_DOCKER_RELAY"
            cmd2=f"iptables -t nat -{insert_mode} PREROUTING -j PRE_NAT_DOCKER_RELAY"
            cmdend=f"iptables -t nat -A PRE_NAT_DOCKER_RELAY -j RETURN"
            chain = "PRE_NAT_DOCKER_RELAY"
            cmd1_check = f"iptables -t nat -S PRE_NAT_DOCKER_RELAY"
            cmdend_check=f"iptables -t nat -C PRE_NAT_DOCKER_RELAY -j RETURN"
            cmdend_del=f"iptables -t nat -D PRE_NAT_DOCKER_RELAY -j RETURN"
            if command_executor(cmd1_check, for_check=True):
                command_executor(cmd1)
                command_executor(cmd2)
                command_executor(cmdend)
               
        # 构造命令头
        if task_type == "nat":
            cmd_header = f"iptables -t nat "
        elif task_type == "mark":
            cmd_header = f"iptables -t mangle "
        # 构造命令体
        cmd_body = f"{chain.upper()} "
        if protocol != "all" and protocol in ["tcp", "udp"]:
            cmd_body += f"-p {protocol} "
        if mark and task_type == "nat":
            cmd_body += f"-m mark --mark {mark} "
        if match_src_ip:
            cmd_body += f"-s {match_src_ip} "
        if match_src_port:
            cmd_body += f"--sport {match_src_port} "
        if match_dst_ip:
            cmd_body += f"-d {match_dst_ip} "
        if match_dst_port:
            cmd_body += f"--dport {match_dst_port} "
        if task_type == "nat" and nat_mode is not None:
            cmd_body += f"-j {nat_mode.upper()} --to "
            if to_ip:
                cmd_body += f"{to_ip}"  
            if to_port:
                cmd_body += f":{to_port}"
        elif task_type == "mark" and mark is not None:
            cmd_body += f"-j MARK --set-mark {mark}"
            
        # 构造完整命令
        cmd = f"{cmd_header} -{insert_mode.upper()} {cmd_body}"
        
        # 如果需要去重
        if deduplicate:
            # 构造检查命令
            cmd_check = f"{cmd_header} -C {cmd_body}"
            # 如果rule有效且不存在，则添加命令
            if command_executor(cmd_check,for_check=True):
                command_executor(cmd)
        else:
            command_executor(cmd)
        
        if nat_mode == "snat" and chain == "PREROUTING":
            # 增加自定义链的尾巴 RETURN
            command_executor(f"{cmdend_del} & {cmdend};")
            
    @staticmethod
    def command_executor(cmd):
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"CMD exec FAIL !: {cmd} error: {stderr}")
            return False               
        else:
            print(f"CMD exec SUCCES: {cmd}  stdout: {stdout}")
            return True
        
    @staticmethod
    def save_iptables_rules():
        # save iptables rules
        NetworkManager.command_executor("apt update &&\
            echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections &&\
            echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections &&\
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent &&\
            systemctl stop docker &&\
            iptables-save > /etc/iptables/rules.v4 && systemctl restart netfilter-persistent &&\
            systemctl start docker")

        # enable ip forwarding
        NetworkManager.command_executor('echo "net.ipv4.ip_forward=1" | tee /etc/sysctl.d/99-ip_forward.conf && sysctl -p')

   
    def clear_swarmnat_iptables_rules(self, mode=None):
        
        def iptables_del_rule_gen(del_rule_keywords_list):
            # Run iptables-save command and get the output
            iptables_save_output = subprocess.getoutput("iptables-save")

            # Split iptables-save output into lines
            iptables_lines = iptables_save_output.split("\n")

            # Placeholder for current table
            current_table = ""

            # Placeholder for commands to be executed
            commands = []

            # Iterate over each line in iptables-save output
            for line in iptables_lines:
                # If line starts with "*", it's a table name
                if line.startswith("*"):
                    current_table = line[1:]
                elif line.startswith(":"):  # If line starts with ":", it's a chain name
                    pass
                # If line contains any of Docker-related elements, prepare "delete" command
                elif any(element in line for element in del_rule_keywords_list):
                    # Replace "-A" with "-D" in the line
                    line = line.replace("-A", "-D", 1)
                    # Prepare command
                    command = f'sudo iptables -t {current_table} {line}'
                    commands.append(command)

            return commands


        def python_run_bash_cmd(cmd_list):
            for cmd in cmd_list:
                # Run each command
                subprocess.run("echo "+cmd, shell=True)
                subprocess.run(cmd, shell=True)
                
        if mode == 'nat' or mode is None:
            del_rule_keywords_list = [str(self.ingress_port)[:-1]]
        elif mode == 'all':
            del_rule_keywords_list = ["DOCKER", "DOCKER-USER", "DOCKER-INGRESS",
                                    "DOCKER-ISOLATION-STAGE-1", "DOCKER-ISOLATION-STAGE-2",
                                    "docker0", "docker_gwbridge", "172.17.", "172.18.", "172.19.",str(self.ingress_port)[:-1],"794"]

        commands_to_execute = iptables_del_rule_gen(del_rule_keywords_list)

        print("deleting rules: mode=", mode,"\n")
        python_run_bash_cmd(commands_to_execute)

        
                
    @staticmethod
    def backup_iptables_rules():
        # Check if backup file already exists
        backup_file = "iptables-backup.txt"
        if os.path.exists(backup_file):
            # If backup file exists, add sequence number to file name
            i = 0
            while os.path.exists(f"{backup_file}.{i}"):
                i += 1
            backup_file = f"{backup_file}.{i}"
        # Backup iptables rules
        NetworkManager.command_executor(f"iptables-save > {backup_file}")    
    
    def is_same_area_network(self, node2:Node, node1:Node) -> bool:
        """
        1.检查两个节点是否在同一个区域网，且能连通
            1.1在node.subnet_node_ip能匹配到,则在返回真
            1.2若同属于网络类型3，且内网ip在16位mask内一致，且能互相ping通，则在返回真
        """
        if node1 is None:
            node1 = self.local_node

        # 检查两个ip地址经过掩码后是否是一样的
        def check_ip_is_same_within_mask(ip1, ip2, mask) -> bool:
            ip1 = ipaddress.ip_address(ip1)
            ip2 = ipaddress.ip_address(ip2)
            return int(ip1) & (sum([2**i for i in range(32-mask,32)])) == int(ip2) & (sum([2**i for i in range(32-mask,32)]))
        
        # 检查ip能否ping通，延迟是否小于参数ms，返回bool
        def check_ping(ip, ms=5, system="linux") -> bool:
            if system == "linux":
                cmd = f"ping -c 1 -W {ms} {ip}"
            else:
                cmd = f"ping -n 1 -w {ms} {ip}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            return False if process.returncode != 0 else True

        if node1 is None or node2 is None:
            return False
        else:
            # Check if the nodes are in the same subnet
            if node1 in node2.subnet_node:
                return True
            # Check if the nodes are both of network type 3 and have the same internal IP within a 16-bit mask
            elif node1.network_type == NetworkType.TYPE_3 and NetworkType.TYPE_3:
                #判断node2和node1哪个是本机节点，决定ping哪个 
                remote_node = node2 if node1 == self.local_node else node1
                return check_ip_is_same_within_mask(node1.local_ip, node2.local_ip, 16) and check_ping(remote_node.local_ip,ms=5)
            else:
                return False
    
    def handle_on_chains(self):
        
        # 定义一个链的枚举：0.没有relay，1.有单边relay，2.有双边relay        
        class ChainType(Enum):
            NO_RELAY = 0
            SINGLE_RELAY = 1
            DOUBLE_RELAY = 2
               
        def get_connection_type(local_node:Node, remote_node:Node)->ChainType:
            if local_node.network_type == NetworkType.TYPE_5 and remote_node.network_type == NetworkType.TYPE_5:
                return ChainType.DOUBLE_RELAY
            elif local_node.network_type == NetworkType.TYPE_5 and remote_node.network_type != NetworkType.TYPE_5:
                return ChainType.SINGLE_RELAY
            elif local_node.network_type != NetworkType.TYPE_5 and remote_node.network_type == NetworkType.TYPE_5:
                return ChainType.SINGLE_RELAY
            else:
                return ChainType.NO_RELAY   
               
        
        def execute_task(task):
            # 根据task数据结构task:{task_type:,nat_mode:,src_ip:,src_port:,dst_ip:,dst_port:,to_ip:,to_port:,chain_type:}
            # 调用_add_nat_rule方法来完成任务
            NetworkManager._add_nat_rule(task_type=task['task_type'], mark=task['mark'], 
                                         nat_mode=task['nat_mode'], chain=task['chain_type'], protocol="tcp", 
                                         match_src_ip=task['src_ip'], match_src_port=task['src_port'], 
                                         match_dst_ip=task['dst_ip'], match_dst_port=task['dst_port'], 
                                         to_ip=task['to_ip'], to_port=task['to_port'])
            NetworkManager._add_nat_rule(task_type=task['task_type'], mark=task['mark'], 
                                         nat_mode=task['nat_mode'], chain=task['chain_type'], protocol="udp", 
                                         match_src_ip=task['src_ip'], match_src_port=task['src_port'], 
                                         match_dst_ip=task['dst_ip'], match_dst_port=task['dst_port'], 
                                         to_ip=task['to_ip'], to_port=task['to_port'])
            
        def backup_iptables():
            NetworkManager.backup_iptables_rules()
            
        def save_nat_tasks():
            NetworkManager.save_iptables_rules()
            
        def execute_chain_tasks(chain_tasks,debug=False):
            """
            Executes the chain tasks in the given chain_tasks dataframe.

            Args:
            - chain_tasks (pandas.DataFrame): A dataframe containing the chain tasks to be executed.
            - debug (bool): A flag indicating whether to print debug information.

            Returns:
            - None
            """
            #将chain_tasks dataframe 倒序，以便后续遍历执行从末尾开始（优先处理double relay 然后 single 最后 none relay）
            #chain_tasks = chain_tasks.iloc[::-1]
            
            tasks =[]
            
              
            if debug:  
                for chain in chain_tasks.itertuples():
                    # print chain内的基础信息
                    # For Debug ：找出同时包含节点1主机名和节点2主机名的链
                    # if "ora01" in chain.chain and "pack02" in chain.chain:
                    #    print("b")
                    if next((tsk.node for tsk in chain.tasks.itertuples() if tsk.node == self.local_node), None) is not None:
                        print(f"\nchain:{chain.chain}, chain_type:{chain.chain_type}")
                    for task in chain.tasks.itertuples():
                        if task.node == self.local_node:
                            print(f"\tnode:{task.node.hostname}, task:{task.task}\n")
                            tasks.append(task.task)
            else:
                _ = [[tasks.append(tsk.task) for tsk in chain.itertuples() if tsk.node == self.local_node] for chain in chain_tasks.tasks]
            
            # tasks = adjust_nat_tasks_priority(tasks,debug=True)     
            backup_iptables()
            self.clear_swarmnat_iptables_rules(mode='nat')
            [execute_task(task) for task in tasks]
            save_nat_tasks()
            return
                                              
        def adjust_nat_tasks_priority(tasks, debug=False):
            # 优先级调整目的：为了避免多条 iptables -A 的nat规则因match项有覆盖情况，导致后加入的规则无法执行
            # 优先级调整方法：将nat规则中match要求越精细的规则越早插入，使得优先级提高
            # tasks 的数据结构如下: [ {node:node1,task:{nat_mode:,src_ip:,src_port:,dst_ip:,dst_port:,to_ip:,to_port:,chain_type:},
            #                        {node:node2,task:{nat_mode:,src_ip:,src_port:,dst_ip:,dst_port:,to_ip:,to_port:,chain_type:}] 
            # 返回：调整后的tasks

            # 优先级排序规则：nat_mode > src_ip > src_port > dst_ip > dst_port > to_ip > to_port
            tasks = df(tasks)
            tasks = tasks.sort_values(by=['nat_mode', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'to_ip', 'to_port'], ascending=False)
            tasks = tasks.fillna(value="").to_dict('records')
            if debug:
                print(f"\n\n Tasks after sort:")
                for task in tasks:
                    print(f"\t{task}\n")
            return tasks

        """
        中继处理逻辑：
        0. 没有relay:
            normal1 -> normal2:4789 - normal1 >(dnat>normal2_pub)->normal2:4789 > (snat>normal1_local) > normal2_socket:4789
            normal1 <- normal2:4789 - normal1_socket < (normal2_local<snat<) normal1 <- (normal1_pub<dnat<) normal2:4789
            normal1:4789 -> normal2 - normal1:4789 > (dnat>normal2_pub)-> normal2 > (snat>normal2_local) > normal2_socket
            normal1:4789 <- normal2 - normal1_socket:4789 <(normal2_local<snat<) normal1 <- (normal2_pub<dnat<) normal2
        1.单边relay:
            normal -> behind relay:4789 - normal >dnat-> relay:relay_port dnat(+snat>normal_local>) relayed:4789 
            normal <- behind relay:4789 - normal_socket <- relayed:4789 <snat <- normal <- [relay:relay_port < snat_on_POST (+normal_pub<dnat_output)] relayed:4789 
            behind relay -> normal:4789 - relayed dnat-> norml:relay_port -> [snat_input>relayed + dnat_pre>normal_local:4789]->normal_socket:4789
            behind relay <- normal:4789 - relayed <- relayed<dnat(+normal_local<snat) < relay <- [relay<dnat + relay_port<snat] < normal_socket:4789
        2.双边relay:
            relayed1 -> relayed2:4789 - relayed1 >dnat -> relay2:relay_port > dnat_prerouting> -> relayed2:4789 
            relayed1 <- relayed2:4789 - relayed1 <- [relayed1<dnat_prerouting + relayed2:4789<snat_prerouting] < relay1 <- [ relay1<dnat + relay2:relay_port<snat_output] < relayed2_socket:4789 
            relayed1:4789 -> relayed2 - relayed1_socket:4789 > [snat_output>relay1:relay_port + dnat_output>relay2] -> relay2 > [snat_prerouting>relayed1:4789 + dnat_prerouting>relayed2] -> relayed2
            relayed1:4789 <- relayed2 - relayed1:4789 <- relay1:4789<dnat_output < relay1:relay_port <- [relayed1:relay_port<dnat_output < relayed2
        注意：特例，40.8的服务器向外连用的是网关外网ip，外部连入是自己的外网ip。
        """           
        def handle_chain_no_relay(local_node:Node, remote_node:Node):
        # 0. 没有relay:
        #    chain_1: normal1 -> normal2:4789 - normal1 > (dnat>normal2_pub)->normal2:4789 > (snat>normal1_local) > normal2_socket:4789
        #    chain_2: normal1 <- normal2:4789 - normal1_socket < (normal2_local<snat<) normal1 <- (normal1_pub<dnat<) normal2:4789
        #    chain_3: normal1:4789 -> normal2 - normal1:4789 > (dnat>normal2_pub)-> normal2 > (snat>normal1_local) > normal2_socket
        #    chain_4: normal1:4789 <- normal2 - normal1_socket:4789 <(normal2_local<snat<) normal1 <- (normal1_pub<dnat<) normal2
        # chain_tasks的数据结构如下：
        # chain_tasks = df([{chain: node1:port -> node2:port,chain_type:..., tasks:[ {node:node1,task:{task_type:,mark,nat_mode:,src_ip:,src_port:,dst_ip:,dst_port:,to_ip:,to_port:,chain_type:},
        #                                                                           {node:node2,task:{task_type:,mark,nat_mode:,src_ip:,src_port:,dst_ip:,dst_port:,to_ip:,to_port:,chain_type:}}] 
        #}])
        # 本函数根据上述的链路处理逻辑，生成多条nat任务，并将之加入到chain_tasks中
            # For Debug
            # if local_node.hostname == "pack01" and remote_node.hostname == "ora02":
            #     print(f"handle_chain_no_relay: {local_node.hostname} -> {remote_node.hostname}")
            # 获取本地节点和远程节点的IP地址和端口号
            loc_loc_ip, loc_ext_ip = local_node.local_ip, local_node.external_ip
            rem_loc_ip, rem_ext_ip = remote_node.local_ip, remote_node.external_ip

            # 生成所有通讯链路的所有nat任务
            tasks1,tasks2,tasks3,tasks4 = [],[],[],[]
        

            # chain_1: normal1 -> normal2:4789
            # normal1 > (dnat>normal2_pub)->normal2:4789 > (snat>normal1_local) > normal2_socket:4789
            # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat task
            if not self.is_same_area_network(local_node, remote_node):
                # nat task 1.1  dnat>normal2_pub
                if remote_node.network_type != NetworkType.TYPE_1:
                    tasks1.append(
                        {'node': local_node, 'task': 
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': None, 
                             'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_ext_ip, 'to_port': None, 
                             'chain_type': 'OUTPUT'}})

                # nat task 1.2 snat>normal1_local
                if local_node.network_type != NetworkType.TYPE_1:
                    tasks1.append(
                        {'node': remote_node, 'task': 
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_ext_ip, 'src_port': None, 
                             'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_loc_ip, 'to_port': None, 
                             'chain_type': 'INPUT'}})
            
                # chain_2: normal1 <- normal2:4789
                # normal1_socket < (normal2_local<snat<) normal1 <- (normal1_pub<dnat<) normal2:4789
                # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat task
                # nat task 2.1 normal2_local<snat
                if remote_node.network_type != NetworkType.TYPE_1:
                    tasks2.append(
                        {'node': local_node, 'task': 
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_ext_ip, 'src_port': self.ingress_port, 
                             'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': rem_loc_ip, 'to_port': None, 
                             'chain_type': 'INPUT'}})

                # nat task 2.2 normal1_pub<dnat
                if local_node.network_type != NetworkType.TYPE_1:
                    tasks2.append(
                        {'node': remote_node, 'task': 
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port, 
                             'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': loc_ext_ip, 'to_port': None, 
                             'chain_type': 'OUTPUT'}})
                             
                # chain_3: normal1:4789 -> normal2
                # normal1:4789 > (dnat>normal2_pub)-> normal2 > (snat>normal1_local) > normal2_socket
                # nat task 3.1 dnat>normal2_pub
                if remote_node.network_type != NetworkType.TYPE_1:
                    tasks3.append(
                        {'node': local_node, 'task': 
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': self.ingress_port, 
                             'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': rem_ext_ip, 'to_port': None, 
                             'chain_type': 'OUTPUT'}})

                # nat task 3.2 snat>normal1_local
                if local_node.network_type != NetworkType.TYPE_1:
                    tasks3.append(
                        {'node': remote_node, 'task': 
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_ext_ip, 'src_port': self.ingress_port, 
                             'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': loc_loc_ip, 'to_port': None, 
                             'chain_type': 'INPUT'}})
                             
                # chain_4: normal1:4789 <- normal2
                # normal1_socket:4789 <(normal2_local<snat<) normal1 <- (normal1_pub<dnat<) normal2

                # nat task 4.1 normal2_local<snat
                if remote_node.network_type != NetworkType.TYPE_1:
                    tasks4.append(
                        {'node': local_node, 'task': 
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_ext_ip, 'src_port': None, 
                             'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_loc_ip, 'to_port': None, 
                             'chain_type': 'INPUT'}})

                # nat task 4.2 normal1_pub<dnat
                if local_node.network_type != NetworkType.TYPE_1:
                    tasks4.append(
                        {'node': remote_node, 'task': 
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': None, 
                             'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_ext_ip, 'to_port': None, 
                             'chain_type': 'OUTPUT'}})
            
            # 将nat任务加入到chain_tasks中
            
            self.chain_tasks=pd.concat([self.chain_tasks, df([
                {'chain': f'{local_node.hostname}:RANDOM -> {remote_node.hostname}:{self.ingress_port}', 'chain_type': 'NO_RELAY', 'tasks': df(tasks1)},
                {'chain': f'{remote_node.hostname}:{self.ingress_port} -> {local_node.hostname}:RANDOM', 'chain_type': 'NO_RELAY', 'tasks': df(tasks2)},
                {'chain': f'{local_node.hostname}:{self.ingress_port} -> {remote_node.hostname}:RANDOM', 'chain_type': 'NO_RELAY', 'tasks': df(tasks3)},
                {'chain': f'{remote_node.hostname}:RANDOM -> {local_node.hostname}:{self.ingress_port}', 'chain_type': 'NO_RELAY', 'tasks': df(tasks4)}
            ])], ignore_index=True)
                              
        def handle_chain_single_relay(local_node:Node, remote_node:Node):
            # 1. 单边relay:
            #    normal -> behind relay:4789 - normal >dnat-> relay:relay_port dnat(+snat>normal_local>) relayed:4789 
            #    normal <- behind relay:4789 - normal_socket <- relayed:4789 <snat <- normal <- [relay:relay_port < snat_on_post (+normal_pub<dnat_output)] relayed:4789 
            #    normal:4789 -> behind relay - normal_socket:4789 > [snat>normal:relay_port + dnat>relay] -> relay > dnat(+snat>normal_local>) -> relayed
            #    normal:4789 <- behind relay - normal_socket:4789 < [relayed<snat normal:4789<dnat]< normal:relay_port <- [relay<snat_on_post (+normal_pub:relay_port<dnat_output)]< relayed

            # For Debug
            # if (local_node.hostname == "pack01" and remote_node.hostname == "pack03") or \
            #     (remote_node.hostname == "pack03" and local_node.hostname== "ora02"):
            #     print("\na")
                
            # 获取本地节点和远程节点的IP地址和端口号
            loc_loc_ip, loc_ext_ip = local_node.local_ip, local_node.external_ip
            rem_loc_ip, rem_ext_ip = remote_node.local_ip, remote_node.external_ip
            if local_node.network_type == NetworkType.TYPE_5:
                loc_rel_node, loc_rel_loc_ip, loc_rel_ext_ip, loc_rel_relay_port = local_node.relay_node, local_node.relay_node.local_ip, \
                    local_node.relay_node.external_ip, local_node.get_relay_port(remote_node)
            if remote_node.network_type == NetworkType.TYPE_5:
                rem_rel_node, rem_rel_loc_ip, rem_rel_ext_ip, rem_rel_relay_port = remote_node.relay_node, remote_node.relay_node.local_ip, \
                    remote_node.relay_node.external_ip, remote_node.get_relay_port(local_node)

            # 生成所有通讯链路的所有nat任务
            tasks1,tasks2,tasks3,tasks4 = [],[],[],[]
            
            # chain_1: normal -> behind relay:4789
            # normal >dnat-> relay:relay_port dnat(+snat>normal_local>) relayed:4789
            # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat task
            if not self.is_same_area_network(local_node, remote_node):
                if local_node.network_type != NetworkType.TYPE_5 and remote_node.network_type == NetworkType.TYPE_5:
                    # nat task 1.1 dnat-> relay:relay_port
                    tasks1.append(
                        {'node': local_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': None,
                            'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_rel_ext_ip, 'to_port': rem_rel_relay_port,
                            'chain_type': 'OUTPUT'}})

                    # nat task 1.2 dnat > relayed:4789
                    tasks1.append(
                            {'node': rem_rel_node, 'task':
                                {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_ext_ip, 'src_port': None,
                                'dst_ip': rem_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': rem_loc_ip, 'to_port': self.ingress_port,
                                'chain_type': 'PREROUTING'}})
                    
                    # nat task 1.3  (+snat>normal_local>) relayed:4789
                    if local_node.network_type != NetworkType.TYPE_1:
                        tasks1.append(
                            {'node': rem_rel_node, 'task':
                                {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_ext_ip, 'src_port': None,
                                'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_loc_ip, 'to_port': None,
                                'chain_type': 'POSTROUTING'}})

                    # chain_2: normal <- behind relay:4789
                    # normal_socket <- relayed:4789 <snat < normal <- [relay:relay_port < snat_on_POST (+normal_pub<dnat_output)] relayed:4789
                    # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat task

                    # nat task 2.1 relayed:4789 <snat < normal                  
                    tasks2.append(
                        {'node': local_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_rel_ext_ip, 'src_port': rem_rel_relay_port,
                            'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': rem_loc_ip, 'to_port': self.ingress_port,
                            'chain_type': 'INPUT'}})
                    

                    # 不经过relay_node，直接从remote_node nat仿冒 relay_node
                    # nat task 2.2 relay:relay_port < snat_on_POSTROUTING (+normal_pub<dnat_output) relayed:4789
                    # normal_pub<dnat_output
                    
                    # if local_node.network_type != NetworkType.TYPE_1:
                    #     tasks2.append(
                    #         {'node': remote_node, 'task':
                    #             {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                    #             'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': loc_ext_ip, 'to_port': None,
                    #             'chain_type': 'OUTPUT'}})
                    
                    # #  nat task 2.3 relay:relay_port < snat_on_POSTROUTING            
                    # tasks2.append(
                    #     {'node': remote_node, 'task':
                    #         {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                    #         'dst_ip': loc_ext_ip, 'dst_port': None, 'to_ip': rem_rel_loc_ip, 'to_port': rem_rel_relay_port,
                    #         'chain_type': 'POSTROUTING'}})
                    
                    # 经过relay_node,从remote_node nat到relay再nat到normal
                    # nat task 2.2 relay < (rel_loc:rel_port<snat_post + rel_loc<dnat_output) < relayed:4789
                    tasks2.append(
                        {'node': remote_node, 'task':
                            {'task_type':'mark', 'mark':rem_rel_relay_port, 'nat_mode': None, 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                            'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': None, 'to_port': None,
                            'chain_type': 'OUTPUT'}})
                    
                    tasks2.append(
                            {'node': remote_node, 'task':
                                {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                                'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': rem_rel_loc_ip, 'to_port': None,
                                'chain_type': 'OUTPUT'}})
 
                    tasks2.append(
                            {'node': remote_node, 'task':
                                {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                                'dst_ip': rem_rel_loc_ip, 'dst_port': None, 'to_ip': None, 'to_port': rem_rel_relay_port,
                                'chain_type': 'POSTROUTING'}})
                                                            
                    # nat task 2.3 normal <- (normal_ext<dnat + rem_rel<snat)relay

                    tasks2.append(
                            {'node': rem_rel_node, 'task':
                                {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': rem_rel_relay_port,
                                'dst_ip': rem_rel_loc_ip, 'dst_port': None, 'to_ip': loc_ext_ip, 'to_port': None,
                                'chain_type': 'PREROUTING'}})
                                        
                    tasks2.append(
                            {'node': rem_rel_node, 'task':
                                {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': rem_rel_relay_port,
                                'dst_ip': loc_ext_ip, 'dst_port': None, 'to_ip': rem_rel_loc_ip, 'to_port': None,
                                'chain_type': 'POSTROUTING'}})
                                

                    # chain_3:  normal:4789 -> behind relay
                    # normal_socket:4789 > [snat>normal:relay_port + dnat>relay] -> relay > dnat(+snat>normal_local>) -> relayed
                    # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat task
                    # nat task 3.1 normal_socket:4789 > [snat>normal:relay_port + dnat>relay] -> relay
                    tasks3.append(
                        {'node': local_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': self.ingress_port,
                            'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': rem_rel_ext_ip, 'to_port': None,
                            'chain_type': 'OUTPUT'}})
                    tasks3.append(
                        {'node': local_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_loc_ip, 'src_port': self.ingress_port,
                            'dst_ip': rem_rel_ext_ip, 'dst_port': None, 'to_ip': None, 'to_port': rem_rel_relay_port,
                            'chain_type': 'POSTROUTING'}})
                    
                    # nat task 3.2 relay > dnat(+snat>normal_local>) -> relayed
                    tasks3.append(
                        {'node': rem_rel_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_ext_ip, 'src_port': rem_rel_relay_port,
                            'dst_ip': rem_rel_loc_ip, 'dst_port': None, 'to_ip': rem_loc_ip, 'to_port': None,
                            'chain_type': 'PREROUTING'}})
                    tasks3.append(
                        {'node': rem_rel_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_ext_ip, 'src_port': rem_rel_relay_port,
                            'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': loc_loc_ip, 'to_port': self.ingress_port,
                            'chain_type': 'POSTROUTING'}})
 
                    # chain_4:  normal:4789 <- behind relay 
                    # normal_socket:4789 < [relayed<snat normal:4789<dnat]< normal:relay_port <- [relay<snat_on_post (+normal_pub:relay_port<dnat_output)]< relayed
                    # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat task
                    
                    # 不经过relay_node，直接从remote_node nat仿冒 relay_node
                    # nat task 4.1 normal:relay_port <- [relay<snat_on_post (+normal_pub:relay_port<dnat_output)]< relayed
                    # tasks4.append(
                    #     {'node': remote_node, 'task':
                    #         {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': None,
                    #         'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_ext_ip, 'to_port': rem_rel_relay_port,
                    #         'chain_type': 'OUTPUT'}})
                    # tasks4.append(
                    #     {'node': remote_node, 'task':
                    #         {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': None,
                    #         'dst_ip': loc_ext_ip, 'dst_port': rem_rel_relay_port, 'to_ip': rem_rel_loc_ip, 'to_port': None,
                    #         'chain_type': 'POSTROUTING'}})
                    
                    # 经过relay_node,从remote_node nat到relay再nat到normal 
                    # nat task 4.1 normal:relay_port <- [relay<snat_post +normal_pub<dnat_pre)] < relay:relay_port<- dnat_output< relayed
                    
                    tasks4.append(
                        {'node': remote_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': None,
                            'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_rel_loc_ip, 'to_port': rem_rel_relay_port,
                            'chain_type': 'OUTPUT'}})
                    
                    tasks4.append(
                        {'node': rem_rel_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': None,
                            'dst_ip': rem_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': loc_ext_ip, 'to_port': None,
                            'chain_type': 'PREROUTING'}})
                                        
                    tasks4.append(
                        {'node': rem_rel_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': None,
                            'dst_ip': loc_ext_ip, 'dst_port': rem_rel_relay_port, 'to_ip': rem_rel_loc_ip, 'to_port': None,
                            'chain_type': 'POSTROUTING'}})
                    
                                   
                    # nat task 4.2 normal_socket:4789 < [relayed<snat normal:4789<dnat]< normal:relay_port
                    tasks4.append(
                        {'node': local_node, 'task':
                            {'task_type':'mark', 'mark':rem_rel_relay_port, 'nat_mode': None, 'src_ip': rem_rel_ext_ip, 'src_port': None,
                            'dst_ip': loc_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': None, 'to_port': None,
                            'chain_type': 'PREROUTING'}})
                    
                    tasks4.append(
                        {'node': local_node, 'task':
                            {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'dnat', 'src_ip': rem_rel_ext_ip, 'src_port': None,
                            'dst_ip': loc_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': None, 'to_port': self.ingress_port,
                            'chain_type': 'PREROUTING'}})
                    tasks4.append(
                        {'node': local_node, 'task':
                            {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'snat', 'src_ip': rem_rel_ext_ip, 'src_port': None,
                            'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_loc_ip, 'to_port': None,
                            'chain_type': 'INPUT'}})
                   
                    # 将nat任务加入到chain_tasks中 

                    self.chain_tasks=pd.concat([self.chain_tasks, df([
                        {'chain': f'{local_node.hostname}:RANDOM -> {remote_node.hostname}:{self.ingress_port}', 'chain_type': 'SINGLE_RELAY', 'tasks': df(tasks1)},
                        {'chain': f'{remote_node.hostname}:{self.ingress_port} -> {local_node.hostname}:RANDOM', 'chain_type': 'SINGLE_RELAY', 'tasks': df(tasks2)},
                        {'chain': f'{local_node.hostname}:{self.ingress_port} -> {remote_node.hostname}:RANDOM', 'chain_type': 'SINGLE_RELAY', 'tasks': df(tasks3)},
                        {'chain': f'{remote_node.hostname}:RANDOM -> {local_node.hostname}:{self.ingress_port}', 'chain_type': 'SINGLE_RELAY', 'tasks': df(tasks4)}
                    ])], ignore_index=True)
                    for tsks in self.chain_tasks.itertuples():
                        if tsks.chain ==f"DESKTOP-SKPL5RD:{self.ingress_port} -> pack01:RANDOM":
                        #if tsks.chain =="DESKTOP-SKPL5RD:RANDOM -> pack01:4789":
                            tt= tsks.tasks.task if len(tsks.tasks)>0 else None
                            return tt
                
        def handle_chain_double_relay(local_node:Node, remote_node:Node):
            # 2.双边relay:
            #     chain_1: relayed1 -> relayed2:4789 - relayed1 >dnat -> relay2:relay_port > dnat_prerouting> -> relayed2:4789 
            #     chain_2: relayed1 <- relayed2:4789 - relayed1 <- [relayed1<dnat_prerouting + relayed2:4789<snat_prerouting] < relay1 <- [ relay1<dnat + relay2:relay_port<snat_output] < relayed2_socket:4789 
            #     chain_3: relayed1:4789 -> relayed2 - relayed1_socket:4789 > [snat_output>relay1:relay_port + dnat_output>relay2] -> relay2 > [snat_prerouting>relayed1:4789 + dnat_prerouting>relayed2] -> relayed2
            #     chain_4: relayed1:4789 <- relayed2 - relayed1:4789 <- relay1:4789<dnat_output < relay1:relay_port <- [relayed1:relay_port<dnat_output < relayed2
   
            # For Debug
            # if (local_node.hostname == "pack01" and remote_node.hostname == "pack03") or \
            #     (remote_node.hostname == "pack03" and local_node.hostname== "ora02"):
            #     print("\na")
                     
            # 获取本地节点和远程节点的IP地址和端口号
            loc_loc_ip, loc_ext_ip = local_node.local_ip, local_node.external_ip
            rem_loc_ip, rem_ext_ip = remote_node.local_ip, remote_node.external_ip
            if local_node.network_type == NetworkType.TYPE_5:
                loc_rel_node, loc_rel_loc_ip, loc_rel_ext_ip, loc_rel_relay_port = local_node.relay_node, local_node.relay_node.local_ip, \
                    local_node.relay_node.external_ip, local_node.get_relay_port(remote_node)
            if remote_node.network_type == NetworkType.TYPE_5:
                rem_rel_node, rem_rel_loc_ip, rem_rel_ext_ip, rem_rel_relay_port = remote_node.relay_node, remote_node.relay_node.local_ip, \
                    remote_node.relay_node.external_ip, remote_node.get_relay_port(local_node)

            # 生成所有通讯链路的所有nat任务
            tasks1,tasks2,tasks3,tasks4 = [],[],[],[]
            if not self.is_same_area_network(local_node, remote_node): 
                '''
                #  方法1 不经过relay_node，直接从remote_node/loc_node nat仿冒 relay_node           
                # # chain_1: relayed1 -> relayed2:4789
                # # relayed1 >dnat-> relay2:relay_port > dnat_prerouting> -> relayed2:4789
                # # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat task 
                # # nat task 1.1 relayed1 >dnat -> relay2:relay_port
                # tasks1.append(
                #     {'node': local_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': None,
                #         'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_rel_ext_ip, 'to_port': rem_rel_relay_port,
                #         'chain_type': 'OUTPUT'}})

                # tasks1.append(
                #     {'node': local_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_loc_ip, 'src_port': None,
                #         'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_rel_ext_ip, 'to_port': None,
                #         'chain_type': 'POSTROUTING'}})
                
                # # nat task 1.2 dnat > relayed:4789
                # tasks1.append(
                #     {'node': rem_rel_node, 'task':
                #         {'task_type':'mark', 'mark':rem_rel_relay_port, 'nat_mode': None, 'src_ip': loc_rel_ext_ip, 'src_port': None,
                #         'dst_ip': rem_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': None, 'to_port': None,
                #         'chain_type': 'PREROUTING'}})
                
                # tasks1.append(
                #     {'node': rem_rel_node, 'task':
                #         {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'dnat', 'src_ip': loc_rel_ext_ip, 'src_port': None,
                #         'dst_ip': rem_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': rem_loc_ip, 'to_port': self.ingress_port,
                #         'chain_type': 'PREROUTING'}})
        
                # tasks1.append(
                #     {'node': rem_rel_node, 'task':
                #         {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'snat', 'src_ip': loc_rel_ext_ip, 'src_port': None,
                #         'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_loc_ip, 'to_port': None,
                #         'chain_type': 'POSTROUTING'}})
        
                # # chain_2: relayed1 <- relayed2:4789 
                # # relayed1 <- [relayed1<dnat_prerouting + relayed2:4789<snat_prerouting] < relay1 <- [ relay1<dnat + relay2:relay_port<snat_output] < relayed2_socket:4789 
                # # left node always is `remote_node`, right node always is `self`, dnat and snat is need be created nat task 
                # # nat task 2.1 relay1 <- [ relay1<dnat + relay2:relay_port<snat_output] < relayed2:4789
                # tasks2.append(
                #     {'node': remote_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                #         'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': loc_rel_ext_ip, 'to_port': None,
                #         'chain_type': 'OUTPUT'}})

                # tasks2.append(
                #     {'node': remote_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                #         'dst_ip': loc_rel_ext_ip, 'dst_port': None, 'to_ip': rem_rel_loc_ip, 'to_port': loc_rel_relay_port,
                #         'chain_type': 'POSTROUTING'}})

                # # nat task 2.2 relayed1 <- [relayed1<dnat_prerouting + relayed2:4789<snat_prerouting] < relay1
                # tasks2.append(
                #     {'node': loc_rel_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_rel_ext_ip, 'src_port': loc_rel_relay_port,
                #         'dst_ip': loc_rel_ext_ip, 'dst_port': None, 'to_ip': loc_loc_ip, 'to_port': None,
                #         'chain_type': 'PREROUTING'}})

                # tasks2.append(
                #     {'node': loc_rel_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_rel_ext_ip, 'src_port': loc_rel_relay_port,
                #         'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': rem_loc_ip, 'to_port': self.ingress_port,
                #         'chain_type': 'POSTROUTING'}})

                # # chain_3: relayed1:4789 -> relayed2
                # # relayed1_socket:4789 > [snat_output>relay1:relay_port + dnat_output>relay2] -> relay2 > [snat_prerouting>relayed1:4789 + dnat_prerouting>relayed2] -> relayed2
                # # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat tasks
                # # nat task 3.1 [snat_output>relay1:relay_port + dnat_output>relay2] -> relay2
                # tasks3.append(
                #     {'node': local_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': self.ingress_port,
                #         'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': rem_rel_ext_ip, 'to_port': None,
                #         'chain_type': 'OUTPUT'}})

                # tasks3.append(
                #     {'node': local_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_loc_ip, 'src_port': self.ingress_port,
                #         'dst_ip': rem_rel_ext_ip, 'dst_port': None, 'to_ip': loc_rel_loc_ip, 'to_port': loc_rel_relay_port,
                #         'chain_type': 'POSTROUTING'}})

                # # nat task 3.2 relay2 > [snat_prerouting>relayed1:4789 + dnat_prerouting>relayed2] -> relayed2
                # tasks3.append(
                #     {'node': rem_rel_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_rel_ext_ip, 'src_port': loc_rel_relay_port,
                #         'dst_ip': rem_rel_loc_ip, 'dst_port': None, 'to_ip': rem_loc_ip, 'to_port': None,
                #         'chain_type': 'PREROUTING'}})

                # tasks3.append(
                #     {'node': rem_rel_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_rel_ext_ip, 'src_port': loc_rel_relay_port,
                #         'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': loc_loc_ip, 'to_port': self.ingress_port,
                #         'chain_type': 'POSTROUTING'}})

                # # chain_4: relayed1:4789 <- relayed2 
                # # relayed1:4789 <- relay1:4789<dnat_output < relay1:relay_port <- [relayed1:relay_port<dnat_output < relayed2
                # # left node always is `remote_node`, right node always is `self`, dnat and snat is need be created nat task 
                # # nat task 4.1 relay1:relay_port <- [relayed1:relay_port<dnat_output < relayed2
                # tasks4.append(
                #     {'node': remote_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': None,
                #         'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_rel_ext_ip, 'to_port': rem_rel_relay_port,
                #         'chain_type': 'INPUT'}})

                # tasks4.append(
                #     {'node': remote_node, 'task':
                #         {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': None,
                #         'dst_ip': loc_rel_ext_ip, 'dst_port': rem_rel_relay_port, 'to_ip': rem_rel_ext_ip, 'to_port': None,
                #         'chain_type': 'POSTROUTING'}})

                # # nat task 4.2 relayed1:4789 <- relay1:4789<dnat_output < relay1:relay_port
                # tasks4.append(
                #     {'node': loc_rel_node, 'task':
                #         {'task_type':'mark', 'mark':rem_rel_relay_port, 'nat_mode': None, 'src_ip': rem_rel_ext_ip, 'src_port': None,
                #         'dst_ip': loc_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': None, 'to_port': None,
                #         'chain_type': 'OUTPUT'}})     
                         
                # tasks4.append(
                #     {'node': loc_rel_node, 'task':
                #         {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'dnat', 'src_ip': rem_rel_ext_ip, 'src_port': None,
                #         'dst_ip': loc_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': loc_loc_ip, 'to_port': self.ingress_port,
                #         'chain_type': 'OUTPUT'}})

                # tasks4.append(
                #     {'node': loc_rel_node, 'task':
                #         {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'snat', 'src_ip': rem_rel_ext_ip, 'src_port': None,
                #         'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_loc_ip, 'to_port': None,
                #         'chain_type': 'POSTROUTING'}})
                '''
                
                # 方法2：经过relay_node, 从remote_node/local_node nat到relay1再nat到relay2    
                # chain_1: relayed1 -> relayed2:4789
                # relayed1 >dnat -> relay1:relay_port>dnat>relay2>snat>relay1 -> relay2:relay_port > dnat_prerouting> -> relayed2:4789
                # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat task 
                # nat task 1.1 relayed1 >dnat -> relay1:relay_port>dnat>relay2>snat>relay1 -> relay2:relay_port
                tasks1.append(
                    {'node': local_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': None,
                        'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_rel_loc_ip, 'to_port': rem_rel_relay_port,
                        'chain_type': 'OUTPUT'}})
                
                tasks1.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': None,
                        'dst_ip': loc_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': rem_rel_ext_ip, 'to_port': None,
                        'chain_type': 'PREROUTING'}})

                tasks1.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_loc_ip, 'src_port': None,
                        'dst_ip': rem_rel_ext_ip, 'dst_port': rem_rel_relay_port, 'to_ip': loc_rel_ext_ip, 'to_port': None,
                        'chain_type': 'POSTROUTING'}})
                
                # nat task 1.2 dnat > relayed:4789
                tasks1.append(
                    {'node': rem_rel_node, 'task':
                        {'task_type':'mark', 'mark':rem_rel_relay_port, 'nat_mode': None, 'src_ip': loc_rel_ext_ip, 'src_port': None,
                        'dst_ip': rem_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': None, 'to_port': None,
                        'chain_type': 'PREROUTING'}})
                
                tasks1.append(
                    {'node': rem_rel_node, 'task':
                        {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'dnat', 'src_ip': loc_rel_ext_ip, 'src_port': None,
                        'dst_ip': rem_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': rem_loc_ip, 'to_port': self.ingress_port,
                        'chain_type': 'PREROUTING'}})
        
                tasks1.append(
                    {'node': rem_rel_node, 'task':
                        {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'snat', 'src_ip': loc_rel_ext_ip, 'src_port': None,
                        'dst_ip': rem_loc_ip, 'dst_port': self.ingress_port, 'to_ip': loc_loc_ip, 'to_port': None,
                        'chain_type': 'POSTROUTING'}})
        
                # chain_2: relayed1 <- relayed2:4789 
                # relayed1 <- [relayed1<dnat_prerouting + relayed2:4789<snat_prerouting] < relay1 <- [ relay1<dnat + relay2:relay_port<snat_output] < relayed2_socket:4789 
                # left node always is `remote_node`, right node always is `self`, dnat and snat is need be created nat task 
                # nat task 2.1.1 relay2 < (rel_loc2:rel_port<snat_post + rel_loc2<dnat_output) < relayed2:4789
                tasks2.append(
                    {'node': remote_node, 'task':
                        {'task_type':'mark', 'mark':rem_rel_relay_port, 'nat_mode': None, 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                        'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': None, 'to_port': None,
                        'chain_type': 'OUTPUT'}})
                
                tasks2.append(
                        {'node': remote_node, 'task':
                            {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                            'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': rem_rel_loc_ip, 'to_port': None,
                            'chain_type': 'OUTPUT'}})

                tasks2.append(
                        {'node': remote_node, 'task':
                            {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': self.ingress_port,
                            'dst_ip': rem_rel_loc_ip, 'dst_port': None, 'to_ip': None, 'to_port': rem_rel_relay_port,
                            'chain_type': 'POSTROUTING'}})
                                                        
                # nat task 2.1.2 relay1 <- (relay1_ext<dnat + relay2<snat)relay2

                tasks2.append(
                        {'node': rem_rel_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': rem_rel_relay_port,
                            'dst_ip': rem_rel_loc_ip, 'dst_port': None, 'to_ip': loc_rel_ext_ip, 'to_port': None,
                            'chain_type': 'PREROUTING'}})
                                    
                tasks2.append(
                        {'node': rem_rel_node, 'task':
                            {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': rem_rel_relay_port,
                            'dst_ip': loc_rel_ext_ip, 'dst_port': None, 'to_ip': rem_rel_loc_ip, 'to_port': None,
                            'chain_type': 'POSTROUTING'}})
                      

                # nat task 2.2 relayed1 <- [relayed1<dnat_prerouting + relayed2:4789<snat_prerouting] < relay1
                tasks2.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_rel_ext_ip, 'src_port': loc_rel_relay_port,
                        'dst_ip': loc_rel_ext_ip, 'dst_port': None, 'to_ip': loc_loc_ip, 'to_port': None,
                        'chain_type': 'PREROUTING'}})

                tasks2.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_rel_ext_ip, 'src_port': loc_rel_relay_port,
                        'dst_ip': loc_loc_ip, 'dst_port': None, 'to_ip': rem_loc_ip, 'to_port': self.ingress_port,
                        'chain_type': 'POSTROUTING'}})

                # chain_3: relayed1:4789 -> relayed2
                # relayed1_socket:4789 > [snat_output>relay1:relay_port + dnat_output>relay2] -> relay2 > [snat_prerouting>relayed1:4789 + dnat_prerouting>relayed2] -> relayed2
                # left node always is `self`, right node always is `remote_node`, dnat and snat is need be created nat tasks
                # nat task 3.1 relayed1:4789>dnat>relay1>snat>relay1:relay_port -> relay1>dnat>relay2>snat>relay1 -> relay2
                
                tasks3.append(
                    {'node': local_node, 'task':
                        {'task_type':'mark', 'mark':rem_rel_relay_port, 'nat_mode': None, 'src_ip': loc_loc_ip, 'src_port': self.ingress_port,
                        'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': None, 'to_port': None,
                        'chain_type': 'OUTPUT'}})
                tasks3.append(
                    {'node': local_node, 'task':
                        {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': self.ingress_port,
                        'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': loc_rel_loc_ip, 'to_port': None,
                        'chain_type': 'OUTPUT'}})
                tasks3.append(
                    {'node': local_node, 'task':
                        {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'snat', 'src_ip': loc_loc_ip, 'src_port': self.ingress_port,
                        'dst_ip': loc_rel_loc_ip, 'dst_port': None, 'to_ip': None, 'to_port': rem_rel_relay_port,
                        'chain_type': 'POSTROUTING'}})       
                         
                tasks3.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_loc_ip, 'src_port': rem_rel_relay_port,
                        'dst_ip': loc_rel_loc_ip, 'dst_port': None, 'to_ip': rem_rel_ext_ip, 'to_port': None,
                        'chain_type': 'PREROUTING'}})

                tasks3.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_loc_ip, 'src_port': rem_rel_relay_port,
                        'dst_ip': rem_rel_ext_ip, 'dst_port': None, 'to_ip': loc_rel_ext_ip, 'to_port': None,
                        'chain_type': 'POSTROUTING'}})
                

                # nat task 3.2 relay2 > [snat_prerouting>relayed1:4789 + dnat_prerouting>relayed2] -> relayed2
                tasks3.append(
                    {'node': rem_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': loc_rel_ext_ip, 'src_port': rem_rel_relay_port,
                        'dst_ip': rem_rel_loc_ip, 'dst_port': None, 'to_ip': rem_loc_ip, 'to_port': None,
                        'chain_type': 'PREROUTING'}})

                tasks3.append(
                    {'node': rem_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': loc_rel_ext_ip, 'src_port': rem_rel_relay_port,
                        'dst_ip': rem_loc_ip, 'dst_port': None, 'to_ip': loc_loc_ip, 'to_port': self.ingress_port,
                        'chain_type': 'POSTROUTING'}})

                # chain_4: relayed1:4789 <- relayed2 
                # relayed1:4789 <- relay1:4789<dnat_output < relay1:relay_port <- [relayed1:relay_port<dnat_output < relayed2
                # left node always is `remote_node`, right node always is `self`, dnat and snat is need be created nat task 
                # nat task 4.1 relay1:relay_port <- relay2<snat<relay1<dnat<relay2:relay_port <-dnat <relayed2
                tasks4.append(
                    {'node': remote_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': None,
                        'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_rel_loc_ip, 'to_port': rem_rel_relay_port,
                        'chain_type': 'OUTPUT'}})
                
                tasks4.append(
                    {'node': rem_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'dnat', 'src_ip': rem_loc_ip, 'src_port': None,
                        'dst_ip': rem_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': loc_rel_ext_ip, 'to_port': None,
                        'chain_type': 'PREROUTING'}})
                
                tasks4.append(
                    {'node': rem_rel_node, 'task':
                        {'task_type':'nat', 'mark':None, 'nat_mode': 'snat', 'src_ip': rem_loc_ip, 'src_port': None,
                        'dst_ip': loc_rel_ext_ip, 'dst_port': rem_rel_relay_port, 'to_ip': rem_rel_ext_ip, 'to_port': None,
                        'chain_type': 'POSTROUTING'}})
     
                # nat task 4.2 relayed1:4789 <- relay1:4789<dnat_output < relay1:relay_port
                tasks4.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'mark', 'mark':rem_rel_relay_port, 'nat_mode': None, 'src_ip': rem_rel_ext_ip, 'src_port': None,
                        'dst_ip': loc_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': None, 'to_port': None,
                        'chain_type': 'OUTPUT'}})     
                         
                tasks4.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'dnat', 'src_ip': rem_rel_ext_ip, 'src_port': None,
                        'dst_ip': loc_rel_loc_ip, 'dst_port': rem_rel_relay_port, 'to_ip': loc_loc_ip, 'to_port': self.ingress_port,
                        'chain_type': 'OUTPUT'}})

                tasks4.append(
                    {'node': loc_rel_node, 'task':
                        {'task_type':'nat', 'mark':rem_rel_relay_port, 'nat_mode': 'snat', 'src_ip': rem_rel_ext_ip, 'src_port': None,
                        'dst_ip': loc_loc_ip, 'dst_port': self.ingress_port, 'to_ip': rem_loc_ip, 'to_port': None,
                        'chain_type': 'POSTROUTING'}})
                
            # 将nat任务加入到chain_tasks中         
            self.chain_tasks=pd.concat([self.chain_tasks, df([
                {'chain': f'{local_node.hostname}:RANDOM -> {remote_node.hostname}:{self.ingress_port}', 'chain_type': 'DOUBLE_RELAY', 'tasks': df(tasks1)},
                {'chain': f'{remote_node.hostname}:{self.ingress_port} -> {local_node.hostname}:RANDOM', 'chain_type': 'DOUBLE_RELAY', 'tasks': df(tasks2)},
                {'chain': f'{local_node.hostname}:{self.ingress_port} -> {remote_node.hostname}:RANDOM', 'chain_type': 'DOUBLE_RELAY', 'tasks': df(tasks3)},
                {'chain': f'{remote_node.hostname}:RANDOM -> {local_node.hostname}:{self.ingress_port}', 'chain_type': 'DOUBLE_RELAY', 'tasks': df(tasks4)}
            ])], ignore_index=True)
 

        # 生成所有的chain_tasks
        def handle_on_chain(local_node:Node, remote_node:Node):
            chain_type = get_connection_type(local_node, remote_node)
            if chain_type == ChainType.NO_RELAY:
                handle_chain_no_relay(local_node, remote_node)
            elif chain_type == ChainType.SINGLE_RELAY:
                handle_chain_single_relay(local_node, remote_node)
                handle_chain_single_relay(remote_node, local_node)
            elif chain_type == ChainType.DOUBLE_RELAY:
                handle_chain_double_relay(local_node, remote_node)
        
  
        # 执行所有的chain_tasks
        for i in range(len(self.nodes)):
            for j in range(i+1, len(self.nodes)):
                # 因为handle_on_chain对loc_node, rem_node的处理是对称的，所以只需要处理一次
                # 通过保证 i < j，以确保只处理一次（前提是self.nodes内无重复成员）
                loc_node = self.nodes[i]
                rem_node = self.nodes[j]
                handle_on_chain(loc_node, rem_node)

        execute_chain_tasks(self.chain_tasks,debug=True)
