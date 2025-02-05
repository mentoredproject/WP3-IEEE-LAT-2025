#!/usr/bin/env bash

set -e

# Verify if the parameter is empty
if [ -z "$1" ]; then
  echo "Parameter is empty"
  exit 1
fi


ITER=$1
echo "Number of iteration: $ITER"


current_time=$(date +"%H%M")
current_date=$(date +"%d%m%Y")

# conntrack flush tcp conections
#sudo conntrack -D -s 192.168.00.1/24 -p tcp
#echo "Flush -s 192.168.00.1/24"
#sudo conntrack -D -s 192.168.10.1/24 -p tcp
#echo "Flush -s 192.168.10.1/24"
#sudo conntrack -D -s 192.168.20.1/24 -p tcp
#echo "Flush -s 192.168.20.1/24"
#sudo conntrack -D -s 192.168.30.1/24 -p tcp
#echo "Flush -s 192.168.30.1/24"
# sudo conntrack -D -s 192.168.40.1/24 -p tcp
# echo "Flush -s 192.168.40.1/24"
# sudo conntrack -D -s 192.168.50.1/24 -p tcp
# echo "Flush -s 192.168.50.1/24"

BASE_PATH="."

WORDIR="$BASE_PATH/Emulation_Raw_Data/$current_date"_"$current_time"
mkdir -p "$WORDIR"

OUTPUT_VOL="$BASE_PATH/Volumes/Output"
mkdir -p "$OUTPUT_VOL"

for i in $(seq 0 $((ITER-1)))
do
	echo "Executando a emulação $i / $ITER"
	# Export the configuration /  Environment Variable for Kubernetes to work
	kind export kubeconfig --name wp3

	# Clear the Output folder for the next emulation
	$BASE_PATH/Scripts/Shell_Script/clean_output.sh
	
	# Get the Unix Epoch Time
	epoch_time=$(date +%s)

	# Create a file to save the emulation begin time
	touch $BASE_PATH/Volumes/Output/tempo_inicializacao.txt
	
	# Change the permition to anyone can read and write
	sudo chmod a+rw $BASE_PATH/Volumes/Output/tempo_inicializacao.txt
	
	# Save the epoch time inside the file
	echo "time inicialization: $epoch_time" > $BASE_PATH/Volumes/Output/tempo_inicializacao.txt
	
	
 	#####################
	# Start the Emulation
	#####################
	$BASE_PATH/Scripts/fase_04/rand_start.sh $RANDOM
	
	# Change the permition of all the files inside the output folder
	sudo chmod -R a+rw $BASE_PATH/Volumes/Output

	# Convert the pcaps files to csv files
	#$BASE_PATH/Scripts/Shell_Script/convert_pcap_csv.sh "$OUTPUT_VOL/Server/Server_01" "server1.pcap"
	#$BASE_PATH/Scripts/Shell_Script/convert_pcap_csv.sh "$OUTPUT_VOL/Server/Server_02" "server2.pcap"
	#$BASE_PATH/Scripts/Shell_Script/convert_pcap_csv.sh "$OUTPUT_VOL/Server/Server_03" "server3.pcap"

	# Collect the metrics
	#$BASE_PATH/Scripts/Shell_Script/magic.sh $BASE_PATH/Volumes/Output 2

	sudo chmod -R a+rw $BASE_PATH/Volumes/Output	

	# Get the current date and time to name the file
	current_time=$(date +"%H%M")
	current_date=$(date +"%d%m%Y")
	name="$current_date"_"$current_time"_emulation"$i"
	
	# Print on the file name
	echo "Current date: $name"

	cp $BASE_PATH/Volumes/Output/kube_status.txt /tmp/kube_status.txt

	# Compact all the file inside the folder Output
	# The compact file will be saved inside the folder $WORDIR
	# In this script also convert the pcap files to csv	
	$BASE_PATH/Scripts/Shell_Script/compact_output.sh $name $WORDIR
	
	echo "Encerrando a emulação $i"

	# Send a email to Samuel informing the emulation conclusion 
	python3 $BASE_PATH/Scripts/Python_Script/send_email.py -n $i -c /home/sbrisio/email/my_email_information.json
done

