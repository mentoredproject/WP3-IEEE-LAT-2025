#! /bin/bash

docker exec wp3-worker2 ip route del default 
docker exec wp3-worker2 ip route add default via 192.168.10.2
docker exec wp3-worker5 ip route del default 
docker exec wp3-worker5 ip route add default via 192.168.20.2
docker exec wp3-worker8 ip route del default
docker exec wp3-worker8 ip route add default via 192.168.30.2
docker exec wp3-worker11 ip route del default
docker exec wp3-worker11 ip route add default via 192.168.40.2
docker exec wp3-worker14 ip route del default
docker exec wp3-worker14 ip route add default via 192.168.50.2


# Rede 1
docker exec wp3-worker iptables -A FORWARD -i eth2 -j ACCEPT
docker exec wp3-worker iptables -A FORWARD -i eth1 -j ACCEPT
docker exec wp3-worker ip route add 192.168.20.0/24 via 192.168.0.3
docker exec wp3-worker ip route add 192.168.30.0/24 via 192.168.0.4
docker exec wp3-worker ip route add 192.168.40.0/24 via 192.168.0.5
docker exec wp3-worker ip route add 192.168.50.0/24 via 192.168.0.6
docker exec wp3-worker ip route add 192.168.10.64/26 via 192.168.10.3

# Rede 2
docker exec wp3-worker4 iptables -A FORWARD -i eth2 -j ACCEPT
docker exec wp3-worker4 iptables -A FORWARD -i eth1 -j ACCEPT
docker exec wp3-worker4 ip route add 192.168.10.0/24 via 192.168.0.2
docker exec wp3-worker4 ip route add 192.168.30.0/24 via 192.168.0.4
docker exec wp3-worker4 ip route add 192.168.40.0/24 via 192.168.0.5
docker exec wp3-worker4 ip route add 192.168.50.0/24 via 192.168.0.6
docker exec wp3-worker4 ip route add 192.168.20.64/26 via 192.168.20.3

# Rede 3
docker exec wp3-worker7 iptables -A FORWARD -i eth2 -j ACCEPT
docker exec wp3-worker7 iptables -A FORWARD -i eth1 -j ACCEPT
docker exec wp3-worker7 ip route add 192.168.10.0/24 via 192.168.0.2
docker exec wp3-worker7 ip route add 192.168.20.0/24 via 192.168.0.3
docker exec wp3-worker7 ip route add 192.168.40.0/24 via 192.168.0.5
docker exec wp3-worker7 ip route add 192.168.50.0/24 via 192.168.0.6
docker exec wp3-worker7 ip route add 192.168.30.64/26 via 192.168.30.3

# Rede 4
docker exec wp3-worker10 iptables -A FORWARD -i eth2 -j ACCEPT
docker exec wp3-worker10 iptables -A FORWARD -i eth1 -j ACCEPT
docker exec wp3-worker10 ip route add 192.168.10.0/24 via 192.168.0.2
docker exec wp3-worker10 ip route add 192.168.20.0/24 via 192.168.0.3
docker exec wp3-worker10 ip route add 192.168.30.0/24 via 192.168.0.4
docker exec wp3-worker10 ip route add 192.168.50.0/24 via 192.168.0.6
docker exec wp3-worker10 ip route add 192.168.40.64/26 via 192.168.40.3

# Rede 5
docker exec wp3-worker13 iptables -A FORWARD -i eth2 -j ACCEPT
docker exec wp3-worker13 iptables -A FORWARD -i eth1 -j ACCEPT
docker exec wp3-worker13 ip route add 192.168.10.0/24 via 192.168.0.2
docker exec wp3-worker13 ip route add 192.168.20.0/24 via 192.168.0.3
docker exec wp3-worker13 ip route add 192.168.30.0/24 via 192.168.0.4
docker exec wp3-worker13 ip route add 192.168.40.0/24 via 192.168.0.5
docker exec wp3-worker13 ip route add 192.168.50.64/26 via 192.168.50.3


# Rede 6 -> DDoS
docker exec wp3-worker16 iptables -A FORWARD -i eth1 -j ACCEPT &&
docker exec wp3-worker16 ip route add 192.168.10.0/24 via 192.168.0.2 &&
docker exec wp3-worker16 ip route add 192.168.20.0/24 via 192.168.0.3 &&
docker exec wp3-worker16 ip route add 192.168.30.0/24 via 192.168.0.4 &&
docker exec wp3-worker16 ip route add 192.168.40.0/24 via 192.168.0.5 &&
docker exec wp3-worker16 ip route add 192.168.50.0/24 via 192.168.0.6 

docker exec wp3-worker16 ip route del 10.128.10.0/24 &&
docker exec wp3-worker16 ip route add 10.128.10.0/24 via 192.168.0.2 &&
docker exec wp3-worker16 ip route del 10.128.20.0/24 &&
docker exec wp3-worker16 ip route add 10.128.20.0/24 via 192.168.0.3 &&
docker exec wp3-worker16 ip route del 10.128.30.0/24 &&
docker exec wp3-worker16 ip route add 10.128.30.0/24 via 192.168.0.4 &&
docker exec wp3-worker16 ip route del 10.128.40.0/24 &&
docker exec wp3-worker16 ip route add 10.128.40.0/24 via 192.168.0.5 &&
docker exec wp3-worker16 ip route del 10.128.50.0/24 &&
docker exec wp3-worker16 ip route add 10.128.50.0/24 via 192.168.0.6

# Duplicated rules to ensure that this configuration is applied
docker exec wp3-worker16 ip route add 10.128.10.0/24 via 192.168.0.2 &&
docker exec wp3-worker16 ip route add 10.128.20.0/24 via 192.168.0.3 &&
docker exec wp3-worker16 ip route add 10.128.30.0/24 via 192.168.0.4 &&
docker exec wp3-worker16 ip route add 10.128.40.0/24 via 192.168.0.5 &&
docker exec wp3-worker16 ip route add 10.128.50.0/24 via 192.168.0.6

# Snort drop packet
docker exec wp3-worker iptables -I FORWARD -j NFQUEUE --queue-num=20 --queue-bypass
docker exec wp3-worker4 iptables -I FORWARD -j NFQUEUE --queue-num=20 --queue-bypass
docker exec wp3-worker7 iptables -I FORWARD -j NFQUEUE --queue-num=20 --queue-bypass
docker exec wp3-worker10 iptables -I FORWARD -j NFQUEUE --queue-num=20 --queue-bypass
docker exec wp3-worker13 iptables -I FORWARD -j NFQUEUE --queue-num=20 --queue-bypass