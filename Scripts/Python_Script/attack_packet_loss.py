import pandas as pd
import argparse
import os

from utils import load_ips, load_traffic_and_filter_by_source_IP

# Stop showing warning
pd.options.mode.chained_assignment = None  # default='warn'

def main():
    args = argumentsParsing()

    # assign directory
    csv_directory = args.server
    dir_attack_log = args.attack
    output_directory = args.output

    first_packet_time = args.time

    # Load malign Ip addrs
    ips = load_ips(args.config)
    net_benning_IP = ips[f'iot_network_{args.number}'] + ips['servers']
    df_server_malign = load_traffic_and_filter_by_source_IP(csv_directory, args.export, first_packet_time, net_benning_IP, negation=True)
    df_server_malign = select_analysis_window(df_server_malign, 60, 1200)


    df_log_attack = load_bonesi_logs(dir_attack_log, first_packet_time)

    packet_loss = {
        'Protocol':[],
        'Packets_send':[],
        'Packets_receive':[],
        'Attack_begin':[],
        'Attack_end':[]
    }


    for p in df_log_attack['protocol'].unique():
        protocol_filter = df_log_attack['protocol'] == p
        server_filter = df_log_attack['dstIp'] == ips['servers'][args.number-1]
        df_protocol = df_log_attack[protocol_filter * server_filter]

        packet_loss['Protocol'].append(p)
        packet_loss['Packets_send'].append(df_protocol['Total_of_packets_send'].sum())
        packet_loss['Attack_begin'].append(df_protocol['Attack_begin'].min())
        packet_loss['Attack_end'].append(df_protocol['Attack_end'].max())

        filter = (df_server_malign['Time'] < df_protocol['Attack_begin'].min()) + (df_server_malign['Time'] > df_protocol['Attack_end'].max()+20)
        packet_loss['Packets_receive'].append(len(df_server_malign[~filter]))


    df_packet_loss = pd.DataFrame(data = packet_loss)

    output_name = f'attack_packet_loss_net_0{args.number}.csv'
    f = os.path.join(args.output, output_name)
    df_packet_loss.to_csv(f, sep='\t', mode='w')

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'attack_packet_loss.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./attacK_packet_loss.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Directory with the csv files from the server
    parser.add_argument('-s', '--server', required=True, help= "directory with csv files from the server")

    # Directory with attack log file
    parser.add_argument('-a', '--attack', required=True, help= "Directory to attack log files")

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

    return parser.parse_args()

def select_analysis_window(df: pd.DataFrame, begin:int, end: int ):
    filter = (df['Time'] < begin) + (df['Time'] > end)
    return df[~filter]

def load_bonesi_logs(directory, time):
    df_log_summary = pd.DataFrame()

    # iterate over files in
    # that directory
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        # checking if it is a file
        if not os.path.isfile(f):
            continue

        # Iterar sobre os arquivos
        df = pd.read_csv(f)

        df['Attack_begin'] -= time
        df['Attack_end'] -= time

        df_log_summary = pd.concat([df_log_summary, df], ignore_index=True)

    return df_log_summary

if __name__ == "__main__":
    main()
