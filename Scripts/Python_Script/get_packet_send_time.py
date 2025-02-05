import os
import pandas as pd
import numpy as np
import argparse

from utils import convert_udp_payload, convert_tshark_csv_to_wireshark, load_ips, load_traffic_and_filter_by_source_IP

def main():
    args = argumentsParsing()
    
    # Argumentos passados pela linha de comando
    csv_directory = args.iot_device
    dir_server_csv = args.server
    emulation_start_time = args.time

    # Benign Ip addrs
    ips = load_ips(args.config)
    iot_net = ips[f'iot_network_{args.number}']

    # df_iots = load_traffic_and_filter_by_source_IP(dir_server_csv, args.export, emulation_start_time, iot_net)
    df_server = load_server_traffic(dir_server_csv, emulation_start_time, iot_net, args.export)    

    # For each iot device network traffic file
    for filename in os.listdir(csv_directory):
        f = os.path.join(csv_directory, filename)
        # checking if it is a file
        if not os.path.isfile(f):
            continue

        # Open IoT log file
        df_iot = load_iot_traffic(f, emulation_start_time)
        # Get its ip address
        iot_ip = df_iot['Source'].unique()[0]
        # Filter to select only the packets that have the iot_ip as Source
        df_iot = df_iot[df_iot['Source'] == iot_ip]

        # Filter the server traffic to select only the packets that has the same Source ip
        iot_filter = df_server['Source'] == iot_ip
        df_server_iot = df_server[iot_filter]


        if df_iot['Packet_ID'].unique().size != len(df_iot):
            print(f"Unique ID: {df_iot['Packet_ID'].unique().size}")
            print(f"Num of Rows: {len(df_iot)}")
            df_iot.to_csv('/tmp/iot_delay_dataframe.csv')
            print('***********  This Dataframe have duplicated Packet ID ***********')
            exit(2)

        # Join the two dataframes -> iot device traffic and the filted server traffic
        left_merged = pd.merge(
            df_iot, 
            df_server_iot, 
            how="left", 
            on=["Packet_ID", "Source", "Destination"]
        )

        left_merged['Delay_seconds'] =  left_merged['Receive_time_interface'] - left_merged['Send_time_interface']
        left_merged['Delay_microseconds'] = left_merged['Delay_seconds'] * 10**6
        left_merged.to_csv(os.path.join(args.output, filename), index=False)

def load_server_traffic(dir_server_csv, emulation_start_time, iot_net, csv_convertion_method):
    df = load_traffic_and_filter_by_source_IP(dir_server_csv, csv_convertion_method, emulation_start_time, iot_net)
    df = convert_udp_payload(df, 'udp.payload')

    df.drop('ip.len', axis=1, inplace=True)
    df.drop('tcp.payload', axis=1, inplace=True)
    df.drop('Packet_Data_File_Line', axis=1, inplace=True)
    df.drop('Value_Capture_by_the_Sensor', axis=1, inplace=True)
    df.drop('Packet_Send_Time', axis=1, inplace=True)
    df.drop('Protocol', axis=1, inplace=True)
    df.rename(columns={"Time": "Receive_time_interface"}, inplace=True)

    return df
    
def load_iot_traffic(f, emulation_start_time):
    df = pd.read_csv(f)
    df = convert_tshark_csv_to_wireshark(df)
    df = convert_udp_payload(df, 'udp.payload')
    df['Packet_Send_Time'] = df['Packet_Send_Time'].astype(np.float64)

    df['Time'] = df['Time'] - emulation_start_time
    df['Packet_Send_Time'] = df['Packet_Send_Time'] - emulation_start_time
    df.rename(columns={"Time": "Send_time_interface", "Packet_Send_Time": "Send_time_log"}, inplace=True)

    df.dropna(inplace=True, subset=['Packet_ID'])

    if df['Protocol'].unique().size > 2:
        print('This dataframe dont have only the UDP')
        exit(2)


    df.drop('ip.len', axis=1, inplace=True)
    df.drop('Protocol', axis=1, inplace=True)
    df.drop('Packet_Data_File_Line', axis=1, inplace=True)
    df.drop('Value_Capture_by_the_Sensor', axis=1, inplace=True)
    df.drop('tcp.payload', axis=1, inplace=True)

    return df

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'main.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./main.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Directory with the csv files from the server
    parser.add_argument('-s', '--server', required=True, help= "directory with csv files from the server") 

    # Directory with the csv files from the iot Device
    parser.add_argument('-i', '--iot_device', required=True, help= "directory with csv files from the iot device") 
    
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

if __name__ == '__main__':
    main()