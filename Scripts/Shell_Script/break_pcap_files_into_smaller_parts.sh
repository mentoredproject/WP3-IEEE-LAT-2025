#!/bin/bash

# Primeiro Input eh diretorio no qual o script irah realizar as computacoes
WORK_DIR=$1

#Segundo Input Arquivo Pcap para converter para csv
original_pcap_file=$2

#Terceiro Parametro indica onde os arquivos deverão ser salvos
OUTPUT=$3

mkdir -p "$OUTPUT"
sudo chmod 777 "$OUTPUT"

#quebrar os pcaps em arquivos menores
sudo tcpdump -r "$WORK_DIR/$original_pcap_file" -w "$OUTPUT/$original_pcap_file" -C 200 -Z root
