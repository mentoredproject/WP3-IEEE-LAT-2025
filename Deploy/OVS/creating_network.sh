#! /bin/bash

# Create a bridge between gateways.
if exist=$(sudo ovs-vsctl br-exists ovs-internet); then sudo ovs-vsctl del-br ovs-internet; fi		
sudo ovs-vsctl add-br ovs-internet
sudo ip address add 192.168.0.1/24 dev ovs-internet 
sudo ovs-docker add-port ovs-internet eth1 wp3-worker --ipaddress=192.168.0.2/24
sudo ovs-docker add-port ovs-internet eth1 wp3-worker4 --ipaddress=192.168.0.3/24
sudo ovs-docker add-port ovs-internet eth1 wp3-worker7 --ipaddress=192.168.0.4/24
sudo ovs-docker add-port ovs-internet eth1 wp3-worker10 --ipaddress=192.168.0.5/24
sudo ovs-docker add-port ovs-internet eth1 wp3-worker13 --ipaddress=192.168.0.6/24
sudo ovs-docker add-port ovs-internet eth1 wp3-worker16 --ipaddress=192.168.0.20/24

######################### Network 1 #########################################

# Create a bridge between the gateway and server the network 1
if exist=$(sudo ovs-vsctl br-exists ovs-lan1); then sudo ovs-vsctl del-br ovs-lan1; fi
sudo ovs-vsctl add-br ovs-lan1
sudo ip address add 192.168.10.1/26 dev ovs-lan1
sudo ovs-docker add-port ovs-lan1 eth2 wp3-worker --ipaddress=192.168.10.2/26
sudo ovs-docker add-port ovs-lan1 eth2 wp3-worker2 --ipaddress=192.168.10.3/26

# Create a bridge between the server and iot in the network 1
if exist=$(sudo ovs-vsctl br-exists sub-lan1); then sudo ovs-vsctl del-br sub-lan1; fi
sudo ovs-vsctl add-br sub-lan1
sudo ip address add 192.168.10.65/26 dev sub-lan1
sudo ovs-docker add-port sub-lan1 eth1 wp3-worker2 --ipaddress=192.168.10.66/26
sudo ovs-docker add-port sub-lan1 eth1 wp3-worker3 --ipaddress=192.168.10.67/26


######################### Network 2 #########################################

# Create a bridge between the gateway and server the network 2
if exist=$(sudo ovs-vsctl br-exists ovs-lan2); then sudo ovs-vsctl del-br ovs-lan2; fi
sudo ovs-vsctl add-br ovs-lan2
sudo ip address add 192.168.20.1/26 dev ovs-lan2
sudo ovs-docker add-port ovs-lan2 eth2 wp3-worker4 --ipaddress=192.168.20.2/26
sudo ovs-docker add-port ovs-lan2 eth2 wp3-worker5 --ipaddress=192.168.20.3/26

# Create a bridge between the server and iot in the network 2
if exist=$(sudo ovs-vsctl br-exists sub-lan2); then sudo ovs-vsctl del-br sub-lan2; fi
sudo ovs-vsctl add-br sub-lan2
sudo ip address add 192.168.20.65/26 dev sub-lan2
sudo ovs-docker add-port sub-lan2 eth1 wp3-worker5 --ipaddress=192.168.20.66/26
sudo ovs-docker add-port sub-lan2 eth1 wp3-worker6 --ipaddress=192.168.20.67/26


############################ Network 3 ########################################

# Create a bridge between the gateway and server the network 3
if exist=$(sudo ovs-vsctl br-exists ovs-lan3); then sudo ovs-vsctl del-br ovs-lan3; fi
sudo ovs-vsctl add-br ovs-lan3
sudo ip address add 192.168.30.1/26 dev ovs-lan3
sudo ovs-docker add-port ovs-lan3 eth2 wp3-worker7 --ipaddress=192.168.30.2/26
sudo ovs-docker add-port ovs-lan3 eth2 wp3-worker8 --ipaddress=192.168.30.3/26

# Create a bridge between the server and iot in the network 3
if exist=$(sudo ovs-vsctl br-exists sub-lan3); then sudo ovs-vsctl del-br sub-lan3; fi
sudo ovs-vsctl add-br sub-lan3
sudo ip address add 192.168.30.65/26 dev sub-lan3
sudo ovs-docker add-port sub-lan3 eth1 wp3-worker8 --ipaddress=192.168.30.66/26
sudo ovs-docker add-port sub-lan3 eth1 wp3-worker9 --ipaddress=192.168.30.67/26

############################ Network 4 ########################################

# Create a bridge between the gateway and server the network 4
if exist=$(sudo ovs-vsctl br-exists ovs-lan4); then sudo ovs-vsctl del-br ovs-lan4; fi
sudo ovs-vsctl add-br ovs-lan4
sudo ip address add 192.168.40.1/26 dev ovs-lan4
sudo ovs-docker add-port ovs-lan4 eth2 wp3-worker10 --ipaddress=192.168.40.2/26
sudo ovs-docker add-port ovs-lan4 eth2 wp3-worker11 --ipaddress=192.168.40.3/26

# Create a bridge between the server and iot in the network 4
if exist=$(sudo ovs-vsctl br-exists sub-lan4); then sudo ovs-vsctl del-br sub-lan4; fi
sudo ovs-vsctl add-br sub-lan4
sudo ip address add 192.168.40.65/26 dev sub-lan4
sudo ovs-docker add-port sub-lan4 eth1 wp3-worker11 --ipaddress=192.168.40.66/26
sudo ovs-docker add-port sub-lan4 eth1 wp3-worker12 --ipaddress=192.168.40.67/26

############################ Network 5 ########################################

# Create a bridge between the gateway and server the network 5
if exist=$(sudo ovs-vsctl br-exists ovs-lan5); then sudo ovs-vsctl del-br ovs-lan5; fi
sudo ovs-vsctl add-br ovs-lan5
sudo ip address add 192.168.50.1/26 dev ovs-lan5
sudo ovs-docker add-port ovs-lan5 eth2 wp3-worker13 --ipaddress=192.168.50.2/26
sudo ovs-docker add-port ovs-lan5 eth2 wp3-worker14 --ipaddress=192.168.50.3/26

# Create a bridge between the server and iot in the network 5
if exist=$(sudo ovs-vsctl br-exists sub-lan5); then sudo ovs-vsctl del-br sub-lan5; fi
sudo ovs-vsctl add-br sub-lan5
sudo ip address add 192.168.50.65/26 dev sub-lan5
sudo ovs-docker add-port sub-lan5 eth1 wp3-worker14 --ipaddress=192.168.50.66/26
sudo ovs-docker add-port sub-lan5 eth1 wp3-worker15 --ipaddress=192.168.50.67/26