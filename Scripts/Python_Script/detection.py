import pandas as pd
import numpy as np
import argparse
import os

from utils import convert_tshark_csv_to_wireshark
from mitigation import snort_get_first_attack_packet

# DIR_SNORT_CSV = "/home/samuelbrisio/Documents/WP3/wp3-experiment/Scripts/Python_Script/Teste/Snort/nids1/csv"
# SNORT_JSON = "Teste/Snort/nids1/alert.json"
# TIME = 1698072902
# PROTO = ['UDP', 'ICMP']


def main():
    args = argumentsParsing()
    DIR_SNORT_CSV = args.snort_traffic
    SNORT_JSON = args.snort_log
    TIME = args.time
    EXPORT_MODE = args.export
    PROTO = args.protocol
    TZ = args.snort_tz

    snort_pcap = pcap_snort_first_attack_packet(DIR_SNORT_CSV, PROTO, TIME, EXPORT_MODE)
    snort_log = snort_get_first_attack_packet(SNORT_JSON, PROTO, TIME, TZ)

    output_path = os.path.join(args.output, f"detection_net_0{args.number}.txt")
    f = open(output_path, "w")
    f.write(f"Protocol,Snort_First_Attack_Packet,Snort_Detection\n")
    f.write(f"UDP,{snort_pcap['UDP']},{snort_log['UDP']}\n")
    f.write(f"ICMP,{snort_pcap['ICMP']},{snort_log['ICMP']}")
    f.close()

def pcap_snort_first_attack_packet(DIR_SNORT_CSV, PROTO, emulation_start_time, export_mode = "tshark"):
    df_server_malign = load_traffic_and_filter_by_source_IP(DIR_SNORT_CSV, emulation_start_time, export_mode)

    server_first_attack_packet = {}

    for proto in PROTO:
        protocol_filter = df_server_malign['Protocol'] == proto
        df_server_proto = df_server_malign[protocol_filter]
        df_server_proto.sort_values(by="Time")

        server_first_attack_packet[proto] = df_server_proto['Time'].min()

    return server_first_attack_packet
    pass



def load_traffic_and_filter_by_source_IP(csv_directory, first_packet_time, export_mode = "tshark"):
    df_server_iot_traffic = pd.DataFrame()

    # iterate over files in
    # that directory
    for filename in os.listdir(csv_directory):
        f = os.path.join(csv_directory, filename)
        
        # checking if it is a file
        if not os.path.isfile(f):
            continue

        # Iterar sobre os arquivos
        df = pd.read_csv(f)

        if (export_mode == "tshark"):
            df = convert_tshark_csv_to_wireshark(df)

        # df = convert_udp_payload(df, 'udp.payload')

        # Convert this column to a relative time
        df['Time'] -= first_packet_time

        df_server_iot_traffic = pd.concat([df_server_iot_traffic, df], ignore_index=True)

    return df_server_iot_traffic

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'mitigation.py',
    description= 'Mitigation Analysis Program',
    # End of help message
    epilog= '''
    ./mitigation.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Directory with the csv files from the server
    parser.add_argument('--snort_traffic', required=True, help= "directory with csv files from the server")

    # Directory with attack log file
    parser.add_argument('--snort_log', required=True, help= "Path to a Snort logfile")

    # Output Directory
    parser.add_argument('-o', '--output', required=True, help= 'Output Directory')

    # Time of the first packet 
    parser.add_argument('-t', '--time', type= int, required=True, help= 'Time of the first packet send in the input directory')

    # Tool used to convert pcap to csv
    parser.add_argument('-e', '--export', type=str, required=True, help= 'Tool used to convert pcap to csv')

    # number of the network
    parser.add_argument('-n', '--number', type=int, required=True, help= 'Network number')

    parser.add_argument('--protocol', type=str, required=True, nargs=2, help= 'Protocols used in the attack')

    parser.add_argument('--snort_tz', type=int, required=True, help='Time zone used in Snort log')

    return parser.parse_args()


if __name__ == "__main__":
    main()