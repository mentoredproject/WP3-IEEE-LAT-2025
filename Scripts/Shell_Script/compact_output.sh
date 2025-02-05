set -e

# Receive as parameter the name for the output file
if [ -z "$1" ]; then
  echo "Please inform the name of the file"
  exit 1
else
  echo "File name $1"
fi


if [ -z "$2" ]; then
  echo "Please inform where the file will be saved"
  exit 1
fi

FILE_NAME=$1
OUTPUT_VOL="./Volumes/Output"
WORKDIR=$2

# Compact the files inside the folder Output
# And write the file name as DDMMYYYY_hhmm_emulation_X [ 26062023_1155_emulation_2]
tar -cvzf "$WORKDIR/$FILE_NAME.tar.gz" $OUTPUT_VOL
