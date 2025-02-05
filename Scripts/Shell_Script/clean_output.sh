set -e

WORK_DIR="./Volumes/Output"

# Remove Every file and Directory inside the Folder Output
rm -f -r $WORK_DIR

# Create all the folder used in the emulation
mkdir $WORK_DIR
mkdir "$WORK_DIR/Bonesi"
mkdir "$WORK_DIR/Snort"
mkdir "$WORK_DIR/Snort/nids1"
mkdir "$WORK_DIR/Snort/nids2"
mkdir "$WORK_DIR/Snort/nids3"
mkdir "$WORK_DIR/Snort/nids4"
mkdir "$WORK_DIR/Snort/nids5"
mkdir "$WORK_DIR/Server"
mkdir "$WORK_DIR/Server/Server_01"
mkdir "$WORK_DIR/Server/Server_02"
mkdir "$WORK_DIR/Server/Server_03"
mkdir "$WORK_DIR/Server/Server_04"
mkdir "$WORK_DIR/Server/Server_05"
mkdir "$WORK_DIR/Network_01"
mkdir "$WORK_DIR/Network_02"
mkdir "$WORK_DIR/Network_03"
mkdir "$WORK_DIR/Network_04"
mkdir "$WORK_DIR/Network_05"