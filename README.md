# Docker Swarm Overlay on NAT

`DockerSwarmOverlay-on-NAT` is a lightweight and secure tool built to solve the problem of Docker Swarm's overlay not functioning correctly after NAT networks. It runs on Debian and Ubuntu Linux distributions, exclusively using the system's built-in iptables. This ensures that there's no need for additional installations or deployments, making the tool both easy to use and safe.

## Supported Operating Systems

- Debian 11
- Ubuntu 22

## Prerequisites

Before using this tool, you need to ensure that:

- The internal network node is configured to connect to the internet via NAT, with no changes to the source port.
- All internal network nodes are set to use the same internal network node as a gateway.
- The gateway node has a public IP.

## Usage

Here's how to use `DockerSwarmOverlay-on-NAT`:

1. Clone the repository:
```shell
git clone https://github.com/loongel/DockerSwarmOverlay-on-NAT.git
```

2. Navigate to the cloned repository. Copy the `config.yml.template` file to create a `config.yml` file for setting your cluster configuration.
```shell
cd DockerSwarmOverlay-on-NAT
cp config.yml.template config.yml
nano config.yml
```

Customize the `config.yml` as needed. 

3. Execute the tool using the following command:

```shell
sudo bash run.sh
```



## Issues and Support

Please star and follow our project if it brings value to your operations. Your feedback and contributions are always appreciated. 

If you encounter any issues or need further assistance, don't hesitate to open an issue in this repository. 

