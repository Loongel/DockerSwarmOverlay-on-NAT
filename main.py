import argparse
from swarmnat import __main__

def main():
    parser = argparse.ArgumentParser(description='Swarmnat command-line tool.')
    parser.add_argument('cmd', nargs='?', default='clear', type=str,
                        choices=['nat','clear','clear_all'], help='The command to execute (e.g., \
                            "nat":create nat rules for docker swarm; "clear":clear nat rules,"clear_all":clear all docker rules).')
    args = parser.parse_args()
    __main__.main(cmd=args.cmd)

if __name__ == "__main__":
    main()