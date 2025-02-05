import pandas as pd
import numpy as np
import argparse
import datetime
import os
import matplotlib.pyplot as plt

from utils import load_ips


# Stop showing warning
pd.options.mode.chained_assignment = None  # default='warn'

def main():
    args = argumentsParsing()
    
    # assign directory
    latency_file = args.latency_file
    dir_output = args.output
    
    # Benign Ip addrs
    ips = load_ips(args.config)
    iot_net = ips[f'iot_network_{args.number}']

    df_iots = pd.read_csv(latency_file)

    output_path = os.path.join(dir_output, f'plot_delay_net_0{args.number}.png')
    plot_graph(df_iots, iot_net, output_path)



def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'normalization.py',
    description= 'Normalization Analysis Program',
    # End of help message
    epilog= '''
    ./nomalization.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    parser.add_argument('--latency_file', required=True, help= "Path to a file with the iot_latency") 
    
    # Output Directory
    parser.add_argument('-o', '--output', required=True, help= 'Output Directory')

    # Json file with the ips of the servers and IoTs
    parser.add_argument('-c', '--config', type=str, required=True, help= 'Path to a Json file with the ips of the servers and IoTs')

    # number of the network
    parser.add_argument('-n', '--number', type=int, required=True, help= 'Network number')

    
    return parser.parse_args()

def plot_graph(df: pd.DataFrame, net_ip, output):
    count = 1

    plt.figure(figsize=(10,10))
    for ip in net_ip:
        filter =  df['Source'] == ip
        df_iot = df[filter]

        plt.plot(df_iot['Send_time_interface'], df_iot['Delay_microseconds'])
        
        if count >= 3:
            break
        count +=1

    # Legend
    plt.title("Time vs Delay")
    plt.xlabel('Time (s)')
    plt.ylabel('Delay (ms)')
    
    # Ticks
    plt.xticks(np.arange(0, 1270, 100))

    plt.savefig(output)


if __name__ == '__main__':
    main()
