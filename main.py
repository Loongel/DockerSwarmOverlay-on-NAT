import argparse
from swarmnat import __main__

def main():
    parser = argparse.ArgumentParser(description='Swarmnat command-line tool.')
    parser.add_argument('cmd', 
                        choices=['','nat','clear','clear_all'], help='The command to execute \
                            (e.g., "nat":create nat rules for docker swarm; "clear":clear nat rules,"clear_all":clear all docker rules).')

    args = parser.parse_args()
    __main__.main(cmd=args.cmd)

if __name__ == "__main__":
    main()



# 远程debug
# server端复制保存完整工程文件后，终端执行下面命令
#mamba activate pydbg311 && nohup python3 -m debugpy --listen 0.0.0.0:62678 --wait-for-client main.py &
