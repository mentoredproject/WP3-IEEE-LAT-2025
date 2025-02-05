#!/bin/bash
# set -e

# Pasta de destino para os arquivos gerados pela execução desse script
OUTPUT_DIR=$1

# Pasta que contem as emulações de uma fase já descompactados
# A caminho do diretório não pode conter "/" no final
DIR_EMULATIONS=$2

# Salve the path of the current directory
WORK_DIR=$(pwd)

# Change the active diretory 
# for ls commmnad capture only the folder names
cd "$DIR_EMULATIONS" || exit
tar_files=$(ls -- *.tar.gz)

# Return the active diretory for the one that call this script
cd "$WORK_DIR" || exit

echo "***************************************"
echo "Log:  Start For Loop for each emulation"
echo "***************************************"


for tar_file in $tar_files
do
    # Descompact the tar.gz file
    tar -C "$DIR_EMULATIONS" -zxf "$DIR_EMULATIONS/$tar_file" --one-top-level

    # filename="19122023_0416_emulation34.tar.gz"
    # base_filename=$(basename "$filename" .tar.gz)
    # echo "$base_filename"  # Output: 19122023_0416_emulation34
    emulation_name=$(basename "$tar_file" .tar.gz)
    emulation_name="$emulation_name/"

    # Create a folder with information about the emulation  
    # Example: $OUTPUT_DIR/28082023_1541_emulation7
    mkdir -p "$OUTPUT_DIR/$emulation_name/net_01"
    mkdir -p "$OUTPUT_DIR/$emulation_name/net_02"
    mkdir -p "$OUTPUT_DIR/$emulation_name/net_03"

    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids1/envio"* "$OUTPUT_DIR/$emulation_name/net_01/"
    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids2/envio"* "$OUTPUT_DIR/$emulation_name/net_02/"
    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids3/envio"* "$OUTPUT_DIR/$emulation_name/net_03/"

    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids1/recebe"* "$OUTPUT_DIR/$emulation_name/net_01/"
    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids2/recebe"* "$OUTPUT_DIR/$emulation_name/net_02/"
    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids3/recebe"* "$OUTPUT_DIR/$emulation_name/net_03/"

    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids1/encaminhamento"* "$OUTPUT_DIR/$emulation_name/net_01/"
    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids2/encaminhamento"* "$OUTPUT_DIR/$emulation_name/net_02/"
    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/Snort/nids3/encaminhamento"* "$OUTPUT_DIR/$emulation_name/net_03/"

    cp "$DIR_EMULATIONS/$emulation_name/wp3-experiment/Volumes/Output/tempo_inicializacao.txt" "$OUTPUT_DIR/$emulation_name/tempo_inicializacao.txt"

    emulation_path="$DIR_EMULATIONS/$emulation_name"
    rm -r "${emulation_path:?}" 

done