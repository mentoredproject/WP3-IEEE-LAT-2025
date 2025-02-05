import argparse
import numpy as np
import pandas as pd

from attack_packet_loss import load_bonesi_logs

# Stop showing warning
pd.options.mode.chained_assignment = None  # default='warn'

def main():
    args = argumentsParsing()

    # assign directory
    dir_attack_log = args.attack

    # Get the experiment start time
    first_packet_time = args.time
   
    # Get the code for a given protocol
    # Example: The code for the protocol UDP is 17
    protocol = get_protocol_code(args.protocol)

    # Open the log file
    df_log_attack = load_bonesi_logs(dir_attack_log, first_packet_time)
    # Filter the dataframe
    df_filter = df_log_attack['protocol'] == protocol
    df_log_attack = df_log_attack[df_filter]

    attack_time = [[], [], [], [], []]

    for server_ip in df_log_attack['dstIp'].unique():
        df_filter = df_log_attack['dstIp'] == server_ip
        df_server_attack =df_log_attack[df_filter]

        index = 0
        if(server_ip == '10.128.10.30'):
            index = 0
        elif(server_ip == '10.128.20.30'):
            index = 1
        elif(server_ip == '10.128.30.30'):
            index = 2
        elif(server_ip == '10.128.40.30'):
            index = 3
        elif(server_ip == '10.128.50.30'):
            index = 4
        
        start_time = np.floor(float(df_server_attack['Attack_begin'].min()))
        start_time = int(start_time)
        end_time = np.ceil(df_server_attack['Attack_end'].max())
        end_time = int(end_time)
        
        attack_time[index] = [start_time, end_time]

    np_array = np.asarray(attack_time)
    np_array = np_array.flatten()
    np_array = np_array.astype(str)
    array_str = " ".join(np_array)
    print(array_str)

   
def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'attack_time',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./attack_time.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Directory with attack log file
    parser.add_argument('-a', '--attack', required=True, help= "Directory to attack log files")

    # Time of the first packet 
    parser.add_argument('-t', '--time', type= int, required=True, help= 'Time of the first packet send in the input directory')

    # Protocol used in the attack
    parser.add_argument('-p', '--protocol', type= str, required=True, help='Protocol used in the attack')

    return parser.parse_args()

def get_protocol_code(protocol):
    if protocol == 'UDP':
        return 17
    if protocol == 'ICMP':
        return 1

if __name__ == "__main__":
    main()
