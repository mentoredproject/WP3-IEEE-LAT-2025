#!/bin/bash

# Primeiro Input eh diretorio no qual o script irah realizar as computacoes
WORK_DIR=$1

#Segundo Input Arquivo Pcap para converter para csv
original_pcap_file=$2

CROPPED_DIR="$WORK_DIR/cropped_pcap"
mkdir -p $CROPPED_DIR

#quebrar os pcaps em arquivos menores
# sudo tcpdump -r "$WORK_DIR/$original_pcap_file" -w "$CROPPED_DIR/server.pcap" -C 200 -Z root
tcpdump -r "$WORK_DIR/$original_pcap_file" -w "$CROPPED_DIR/server.pcap" -C 200 -Z root

# Encontra todos os novos pcaps
files=$(ls $CROPPED_DIR | grep .pcap)

CSV_DIR="$WORK_DIR/csv" 
mkdir -p $CSV_DIR 

for file in $files
do
    # sudo tshark -r "$CROPPED_DIR/$file" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
    # -e frame.time_epoch -e ip.src -e ip.dst -e frame.protocols -e ip.len -e tcp.payload -e udp.payload > "$CSV_DIR/$file.csv"
    tshark -r "$CROPPED_DIR/$file" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
    -e frame.time_epoch -e ip.src -e ip.dst -e frame.protocols -e ip.len -e tcp.payload -e udp.payload > "$CSV_DIR/$file.csv"
    echo "file $file done"
done
