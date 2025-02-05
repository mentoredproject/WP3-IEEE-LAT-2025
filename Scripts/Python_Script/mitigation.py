import pandas as pd
import numpy as np
import argparse
from datetime import datetime
import os
import pytz

from utils import load_ips, load_traffic_and_filter_by_source_IP

# PROTO = ['UDP', 'ICMP']
# TIME = 1698072902

# dir_server_csv = "/home/samuelbrisio/Documents/WP3/wp3-experiment/Scripts/Python_Script/Teste/Server_raw_data/Server_1/csv_files/"
# snort_json = "Teste/Snort/nids1/alert.json"
# ips_file = "ips.json"

def main():
    args = argumentsParsing()
    dir_server_csv = args.server
    snort_json = args.snort
    TIME = args.time
    ips_file = args.config
    export_mode = args.export
    PROTO = args.protocol
    tz = args.snort_tz

    ips = list_of_ips(ips_file)
    server_first_attack_packet = server_get_first_attack_packet(dir_server_csv, PROTO, TIME, export_mode, ips)
    snort_first_attack_packet = snort_get_first_attack_packet(snort_json, PROTO, TIME, tz)


    output_path = os.path.join(args.output, f"mitigation_net_0{args.number}.txt")
    f = open(output_path, "w")
    f.write(f"Protocol,Server_First_Attack_Packet,Snort_Detection\n")
    f.write(f"UDP,{server_first_attack_packet['UDP']},{snort_first_attack_packet['UDP']}\n")
    f.write(f"ICMP,{server_first_attack_packet['ICMP']},{snort_first_attack_packet['ICMP']}")
    f.close()


def server_get_first_attack_packet(server_csv, PROTO, emulation_start_time, export_mode, IPS):
    df_server_malign = load_traffic_and_filter_by_source_IP(server_csv, export_mode, emulation_start_time, IPS, negation=True)

    server_first_attack_packet = {}

    for proto in PROTO:
        protocol_filter = df_server_malign['Protocol'] == proto
        df_server_proto = df_server_malign[protocol_filter]
        df_server_proto.sort_values(by="Time")

        server_first_attack_packet[proto] = df_server_proto['Time'].iloc[0]

    return server_first_attack_packet

def snort_get_first_attack_packet(snort_json, PROTO, emulation_start_time, tz):
    snort_first_attack_packet = {}

    for proto in PROTO:
        df = load_snort_log(snort_json, proto, emulation_start_time, tz)
        snort_first_attack_packet[proto] = df.min()
    
    return snort_first_attack_packet

def load_snort_log(snort_json, proto, emulation_start_time, tz):
    # Get the year of a given unix epoch
    dt = datetime.fromtimestamp(emulation_start_time)
    
    df_times = pd.Series(name='Time')

    for chunk in pd.read_json(snort_json, lines=True, chunksize=100000):
        if chunk.empty:
            continue
        
        filter_proto = chunk['proto'] == proto
        df = chunk[filter_proto]
        times = df['timestamp'].apply(convert_datetime_to_unix_epoch, args=(dt.year, tz))
        times -= emulation_start_time
        df_times = pd.concat([df_times, times], ignore_index=True)
    
    return df_times

def convert_datetime_to_unix_epoch(datetime_str, year, time_zone):
    # Bug Detect: Its not convert to unix epoch, because the function doenst handle the timezone

    # Define the format of your datetime string
    datetime_format = "%Y/%m/%d-%H:%M:%S.%f"
    datetime_str_with_year = f"{year}/{datetime_str}"

    # Parse the datetime string
    parsed_datetime = datetime.strptime(datetime_str_with_year, datetime_format)

    # -3 horas = 180 minutos
    offset_tz = pytz.FixedOffset(offset=time_zone*60)

    offset_dt_aware = offset_tz.localize(parsed_datetime, is_dst=None)
    utc_dt = offset_dt_aware.astimezone(pytz.utc)

    # Convert the parsed datetime to a Unix epoch timestamp
    unix_epoch = datetime.timestamp(utc_dt)
    return unix_epoch

def list_of_ips(ips_file):
    ips = load_ips(ips_file)
    ips = list(ips.values())
    return flatten_comprehension(ips)

def flatten_comprehension(matrix):
    return [item for row in matrix for item in row]

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
    parser.add_argument('--server', required=True, help= "directory with csv files from the server")

    # Directory with attack log file
    parser.add_argument('--snort', required=True, help= "Path to a Snort logfile")

    # Output Directory
    parser.add_argument('-o', '--output', required=True, help= 'Output Directory')

    # Time of the first packet 
    parser.add_argument('-t', '--time', type= int, required=True, help= 'Time of the first packet send in the input directory')

    # Json file with the ips of the servers and IoTs
    parser.add_argument('-c', '--config', type=str, required=True, help= 'Path to a Json file with the ips of the servers and IoTs')

    # Tool used to convert pcap to csv
    parser.add_argument('-e', '--export', type=str, required=True, help= 'Tool used to convert pcap to csv')

    # number of the network
    parser.add_argument('-n', '--number', type=int, required=True, help= 'Network number')

    parser.add_argument('--protocol', type=str, required=True, nargs=2, help= 'Protocols used in the attack')

    parser.add_argument('--snort_tz', type=int, required=True, help='Time zone used in Snort log')

    return parser.parse_args()


if __name__ == "__main__":
    main()
