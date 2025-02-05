import pandas as pd
import numpy as np
import os
import json
import argparse

from utils import convert_tshark_csv_to_wireshark, convert_udp_payload

# Stop showing warning
pd.options.mode.chained_assignment = None  # default='warn'

def main():

    args = argumentsParsing()
    
    # assign directory
    csv_directory = args.server
    iot_directory = args.iot 
    output_directory = args.output

    first_packet_time = args.time
    window = args.window

    # Benign Ip addrs
    ips = load_ips(args.config)
    iot_net = ips[f'iot_network_{args.number}']

    df_server_iot_traffic = load_benign_iot_traffic(csv_directory, args.export, first_packet_time, iot_net)
    df_server_iot_traffic = select_analysis_window(df_server_iot_traffic, window[0], window[1])

    server_packet_receive_per_iot = np.zeros(15)
    iot_packet_send = np.zeros(15)

    for filename in os.listdir(iot_directory):
        f = os.path.join(iot_directory, filename)
        # checking if it is a file
        if not os.path.isfile(f) or f[-4:] == 'pcap':
            continue

        # iot_device is the number of that iot device in the network
        iot_device = int(filename[4:6]) - 1
        iot_ip = iot_net[iot_device]

        # Calculate the number of packet that the server receive
        filter = df_server_iot_traffic['Source'] == iot_ip
        df_server_receive_iot_packets = df_server_iot_traffic[filter]

        server_packet_receive_per_iot[iot_device] = df_server_receive_iot_packets.shape[0] 

        # 
        df = pd.read_csv(f)
        df['Time'] = df['Time'].values - first_packet_time
        df = select_analysis_window(df, window[0], window[1])
        iot_packet_send[iot_device] = df.shape[0]

    output_name = f'packet_loss_0{args.number}_window_{window[0]}_{window[1]}.csv'


    # Salvar o numero da pacotes enviados, e recebidos pelo servidor
    # Perda de pacotes absoluto e em porcentagem   
    packet_loss = iot_packet_send - server_packet_receive_per_iot
    packet_loss_percentage = (packet_loss/iot_packet_send)*100
    
    data = {'Packets_Send':iot_packet_send, 
            'Packets_Receive':server_packet_receive_per_iot,
            'Packets_Loss':packet_loss,
            'Packets_Loss(%)':packet_loss_percentage
    } 

    df_packet_loss = pd.DataFrame(data = data)
    
    f = os.path.join(output_directory, output_name)
    df_packet_loss.to_csv(f, sep='\t', mode='w')

# Filter the server data frame, to select only the time windown used for analysis 
def select_analysis_window(df: pd.DataFrame, begin:int, end: int ):
    filter = (df['Time'] < begin) + (df['Time'] > end)
    return df[~filter]

    
def load_benign_iot_traffic(csv_directory, export_mode, first_packet_time, iot_net):
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

         # Separa o trafego dos dispositivos IoT   
        traffic = traffic_filter(df, iot_net)

        #traffic = convert_udp_payload(traffic, 'udp.payload')

        # Convert this column to a relative time
        traffic['Time'] -= first_packet_time

        df_server_iot_traffic = pd.concat([df_server_iot_traffic, traffic], ignore_index=True)

    return df_server_iot_traffic

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'packet_loss.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./packet_loss.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Directory with the csv files from the server
    parser.add_argument('-s', '--server', required=True, help= "directory with csv files from the server") 

    # Directory with the csv files from the iot device
    parser.add_argument('-i', '--iot', required=True, help= "directory with csv files from the iot device") 

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

    # Time window where the analysis will be made
    parser.add_argument('-w', '--window', type=int, required=True, nargs=2, help= 'Time Window use in the analysis')

    return parser.parse_args()


def load_ips(filename):
    # Open the JSON file
    with open(filename) as file:
        data = json.load(file)

    # return the contents of the JSON file
    return data


def traffic_filter(df, iot_net):
     # Pegar tempo benigno do servidor e dos dispositivos IoT
    benign_iots_filter = df['Source'].isin(iot_net)
    iot_traffic = df[benign_iots_filter]

    return iot_traffic

main()
