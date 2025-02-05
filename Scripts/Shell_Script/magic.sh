#!/usr/bin/env bash

# Receive as parameter the Directory path where the Script will work
if [ -z "$1" ]; then
  echo "Please inform the directory path"
  exit 1
fi

if [ -z "$2" ] || [ "$2" -gt 4 ] || [ "$2" -lt 1 ]; then
  echo "Please inform the fase of the experiment {1 | 2 | 3 | 4}"
  exit 1
fi

WORK_DIR=$1
OUTPUT_DIR="$WORK_DIR/Output"
mkdir -p $OUTPUT_DIR

FILE_BENIGN_IPS="/wp3-experiment/Scripts/Python_Script/ips.json"

# GET the time of the experiment start
FILE="$WORK_DIR/tempo_inicializacao.txt"

# Check if the file exists
if [ -f "$FILE" ]; then
    # Read the first line of the file
    read -r first_line < "$FILE"

    # Get the time of the experiment begin from the first line
    TIME=( $(grep -oE -m 1 "[0-9]+" <<< "$first_line") )
else
    echo "File not found: $FILE"
fi

# Activate the python virtual envinronment 
source /wp3-experiment/Scripts/Python_Script/venv/bin/activate

for ((i=1; i<=3; i++))
do 
    SERVER_DIR="$WORK_DIR/Server/Server_0$i"
    OUTPUT="$OUTPUT_DIR/Network_0$i"
    mkdir -p $OUTPUT
    mkdir -p "$OUTPUT_DIR/Summary"
    python3 /wp3-experiment/Scripts/Python_Script/main.py -i "$SERVER_DIR/csv" -o $OUTPUT -t $TIME -c $FILE_BENIGN_IPS -e tshark --attack_protocol 'UDP' 'ICMP'
    python3 /wp3-experiment/Scripts/Python_Script/packet_loss.py -s "$SERVER_DIR/csv" -i "$WORK_DIR/Network_0$i" -o $OUTPUT -t $TIME -n $i -c $FILE_BENIGN_IPS -e tshark -w 60 1200
    # python3 /wp3-experiment/Scripts/Python_Script/packet_loss_v2.py -s "$SERVER_DIR/csv" -i "$WORK_DIR/Network_0$i" -o $OUTPUT -t $TIME -n $i -c $FILE_BENIGN_IPS -e tshark

#    if [ "$2" -eq 2 ]; then
#    	# The affect of packet loss in the IoT device when a attack is happening
#    	# Using the protocol UDP
#	TIME_WINDOW=( $(python3 /wp3-experiment/Scripts/Python_Script/attack_time.py -a "$WORK_DIR/Bonesi" -o $OUTPUT -t $TIME -p "UDP") )
#	python3 /wp3-experiment/Scripts/Python_Script/packet_loss.py -s "$SERVER_DIR/csv" -i "$WORK_DIR/Network_0$i" -o $OUTPUT -t $TIME -n $i -c $FILE_BENIGN_IPS -e tshark -w ${TIME_WINDOW[0]} ${TIME_WINDOW[1]}
#	# Using the protocol ICMP
#    	TIME_WINDOW=( $(python3 /wp3-experiment/Scripts/Python_Script/attack_time.py -a "$WORK_DIR/Bonesi" -o $OUTPUT -t $TIME -p "ICMP") )
#    	python3 /wp3-experiment/Scripts/Python_Script/packet_loss.py -s "$SERVER_DIR/csv" -i "$WORK_DIR/Network_0$i" -o $OUTPUT -t $TIME -n $i -c $FILE_BENIGN_IPS -e tshark -w ${TIME_WINDOW[0]} ${TIME_WINDOW[1]}
# 	
#	# Calculate the packet loss in the attack
#        python3 /wp3-experiment/Scripts/Python_Script/attacK_packet_loss.py -s "$WORK_DIR/Server/Server_01/csv" -a "$WORK_DIR/Bonesi" -o "$OUTPUT_DIR/Network_01" -t $TIME -n 1 -e tshark -c $FILE_BENIGN_IPS
#    fi

    # Make a summary from the packet loss metrics
    INPUT=$OUTPUT
    python3  /wp3-experiment/Scripts/Python_Script/summary.py -i "$INPUT/packet_loss_0$i""_window_60_1200.csv" -o "$OUTPUT_DIR/Summary" -n $i

    
done

# Packet loss for TCP 
python3 /wp3-experiment/Scripts/Python_Script/tcp_loss.py -i "$WORK_DIR/Server" -o $OUTPUT_DIR -t $TIME -z 3
