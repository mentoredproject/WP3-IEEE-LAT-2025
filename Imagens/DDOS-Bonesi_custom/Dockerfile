FROM ubuntu:20.04

RUN apt update  -y && apt install -y automake-1.15 
RUN apt install -y autoconf  gcc make libpcap-dev libnet-dev git build-essential libnet1-dev vim tcpdump
COPY bonesi BoNeSi
RUN cd BoNeSi/ && autoconf -f -i && ./configure && automake --add-missing && make && make install
