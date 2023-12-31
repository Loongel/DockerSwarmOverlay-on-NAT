# Docker Swarm Overlay on NAT

`DockerSwarmOverlay-on-NAT` is a lightweight and secure tool built to solve the problem of Docker Swarm's overlay not functioning correctly after NAT networks. It runs on Debian and Ubuntu Linux distributions, exclusively using the system's built-in iptables. This ensures that there's no need for additional installations or deployments, making the tool both easy to use and safe.

## Supported Operating Systems

- Debian 11
- Ubuntu 22

## Prerequisites

Before using this tool, you need to ensure that:
- The internal network node is configured to connect to the internet via NAT, with no changes to the source port.
- The internal network nodes are set to use the same internal network node as a gateway which has a public IP.
- Python and pip have been installed on each node

## Usage

Here's how to use `DockerSwarmOverlay-on-NAT`:

1. Clone the repository:
```bash
git clone https://github.com/loongel/DockerSwarmOverlay-on-NAT.git

```

2. Navigate to the cloned repository. Copy the `config.yml.template` file to create a `config.yml` file for setting your cluster configuration.
Customize the `config.yml` as needed.
```bash
cd DockerSwarmOverlay-on-NAT
cp config.yml.template config.yml
nano config.yml

```

3. Execute the tool using the following command:
```bash
sudo bash run.sh

```
If you encounter the following error during execution, 
```bash
    import pkg_resources
ImportError: No module named pkg_resources
Installing missing packages...
run.sh: line 6: pip: command not found

```
This is because there is no python or pip in the `PATH` of `sudo`, you can use the following script to execute.
```bash
sudo bash -c "export PATH=$PATH; bash run.sh"
```

4. Check the terminal output log. If there is no `CMD exec FAIL !!!!` information, it means the execution is successful. On the contrary, you need to find the reason according to the terminal output log.

5. restore the iptables rules
```bash
sudo iptables-restore iptables-backup.txt 

```

## Issues and Support

Please star and follow our project if it brings value to your operations. Your feedback and contributions are always appreciated. 

If you encounter any issues or need further assistance, don't hesitate to open an issue in this repository. 

