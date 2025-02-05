#!/bin/bash

# Output Folder
OUTPUT_DIR=$1

#Second Input Folder with the pcaps files
PCAP_DIR=$2

# CROPPED_DIR="$WORK_DIR/cropped_pcap"
# mkdir -p $CROPPED_DIR

# Encontra todos os novos pcaps
files=$(ls $PCAP_DIR | grep .pcap)

# CSV_DIR="$WORK_DIR/csv"
mkdir -p $OUTPUT_DIR

for file in $files
do
    filename=${file:0:6}
    tshark -Q -r "$PCAP_DIR/$file" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
    -e frame.time_epoch -e ip.src -e ip.dst -e frame.protocols -e ip.len -e tcp.payload -e udp.payload > "$OUTPUT_DIR/$filename.csv"
done
