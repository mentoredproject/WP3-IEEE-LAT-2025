
#!/bin/bash

# Primeiro Input eh diretorio no qual o script irah encontrar os pcaps
CROPPED_DIR=$1
# Encontra todos os novos pcaps
files=$(ls $CROPPED_DIR | grep .pcap)

# Segundo Parametro eh onde serão salvos os arquivos csv
CSV_DIR=$2
mkdir -p $CSV_DIR 

for file in $files
do
    # sudo tshark -r "$CROPPED_DIR/$file" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
    # -e frame.time_epoch -e ip.src -e ip.dst -e frame.protocols -e ip.len -e tcp.payload -e udp.payload > "$CSV_DIR/$file.csv"
    tshark -r "$CROPPED_DIR/$file" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
    -e frame.time_epoch -e ip.src -e ip.dst -e frame.protocols -e ip.len -e tcp.payload -e udp.payload > "$CSV_DIR/$file.csv"
    echo "file $file done"
done
