# dockerSwarm_overlay_on_nat
docker swarm's overlay cannot work after nat networks. This tiny tool is used for this problem on debian/ubuntu linux via iptables 

## Tested OS
Debian 11
Ubuntu 22

## Prerequisites:

1. When the internal network node connects to the internet through NAT, the source port shoud not be changed.

2. The internal network nodes already use the same internal network node as gateway, which have a public IP.

## Useage

1. clone the rep

2. refer to `config.yml.template` to create config.yml file for your cluster configuration. 
    ```bash
    cd dockerSwarm_overlay_on_nat && \
    cp config.yml.template config.yml && \
    nano config.yml
    ```
    
3. run the tool.
    ```bash
    sudo bash run.sh
    ```

