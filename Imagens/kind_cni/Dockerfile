FROM kindest/node:v1.25.3
RUN apt update; apt install wget \ 
    && wget https://github.com/containernetworking/plugins/releases/download/v1.1.1/cni-plugins-linux-amd64-v1.1.1.tgz \ 
    && tar -xvf cni-plugins-linux-amd64-v1.1.1.tgz \
    && mv bridge /opt/cni/bin/
