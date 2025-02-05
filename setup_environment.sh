#! /bin/bash


# Add more resource for inotify
sudo sysctl fs.inotify.max_user_watches=524288
sudo sysctl fs.inotify.max_user_instances=512

# Create Kubernet Cluster
kind create cluster --name wp3 --config Deploy/kind-cluster.yaml --image kind-cni:wp3.v1

# Apply calico 3.25 manifest
docker exec wp3-control-plane kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/calico.yaml

# Apply the custom ippool
sleep 60
calicoctl delete ippools default-ipv4-ippool
sleep 60
calicoctl apply -f Deploy/ippool.yaml

# Apply our felix config
calicoctl delete felixconfig default 
calicoctl apply -f Deploy/felix_config.yaml

#
# Preciso mudar os nomes das imagens
#
kind load docker-image bonesi:wp3.v2 snort:wp3.v5 iot:wp3.v2 smd-metrica:wp3.v5 --name wp3

# Enable IP Spoofing
docker exec wp3-worker16 sysctl -w "net.ipv4.conf.all.rp_filter=0"