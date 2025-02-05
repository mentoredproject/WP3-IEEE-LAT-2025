#!/bin/bash

# Primeiro Input eh diretorio no qual o script irah encontrar os pcaps
CROPPED_DIR=$1
# Encontra todos os novos pcaps
files=$(ls $CROPPED_DIR | grep .pcap)

# Segundo Parametro eh onde serão salvos os arquivos csv
CSV_DIR=$2

mkdir -p $CSV_DIR 

count=0
for file in $files
do
    if [ $count -lt 2 ]  # Run up to two commands in parallel
    then
        # sudo tshark -r "$CROPPED_DIR/$file" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
        # -e frame.time_epoch -e ip.src -e ip.dst -e frame.protocols -e ip.len -e tcp.payload -e udp.payload > "$CSV_DIR/$file.csv"
        tshark -n -r "$CROPPED_DIR/$file" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
        -e frame.time_epoch -e ip.src -e ip.dst -e frame.protocols -e ip.len > "$CSV_DIR/$file.csv"
        echo "file $file done"
    else
        wait  # Wait for a running command to finish before starting another
        count=0
    fi
done
