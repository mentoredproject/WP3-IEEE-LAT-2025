import pandas as pd
import numpy as np
import os
import json
import argparse

from utils import  convert_tshark_csv_to_wireshark

# Stop showing warning
pd.options.mode.chained_assignment = None  # default='warn'

def main():

    args = argumentsParsing()
    
    # assign directory
    dat_directory = args.output
    csv_directory = args.input 

    first_packet_time = args.time
    
    # Benign Ip addrs
    ips = load_ips(args.config)
    benign_servers = ips['servers']
    benign_iots = ips['iot_network_1'] + ips['iot_network_2'] + ips['iot_network_3'] + ips['iot_network_4'] + ips['iot_network_5']


    # Remover arquivos existentes no diretorio de saida
    for filename in os.listdir(dat_directory):
        f = os.path.join(dat_directory, filename)
        # checking if it is a file
        if os.path.isfile(f):
            os.remove(f)

    # Caminho dos arquivos de Saida
    outputfiles = [
        os.path.join(dat_directory, 'benign_iot_traffic.dat'),
        os.path.join(dat_directory, 'benign_servers_traffic.dat'),
        os.path.join(dat_directory, 'malign_traffic.dat')
    ]

    time_windown = (0, 0)

    # iterate over files in
    # the csv directory
    for filename in os.listdir(csv_directory):
        f = os.path.join(csv_directory, filename)
        # checking if it is a file
        if not os.path.isfile(f):
            continue

        # Iterar sobre os arquivos
        df = pd.read_csv(f)

        if (args.export == "tshark"):
            df = convert_tshark_csv_to_wireshark(df)

        # Convert this column to a relative time
        df['Time'] -= first_packet_time

        # Separa o trafego em iot, servidor e maligno
        traffic = traffic_filter(df, benign_iots, benign_servers, args.attack_protocol)


        # Calcula em qual intervalo de tempo os pacates serao discretizados
        time_windown = calc_time_windown(df)

        process_data(traffic, time_windown, outputfiles)


def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'main.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= './main.py -i <input-path-directory> -o <output-path-directory> -t <time-of-first-packets> -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark>'
    )

    # Directory with the csv files
    parser.add_argument('-i', '--input', required=True, help= "input directory") 

    # Output Directory
    parser.add_argument('-o', '--output', required=True, help= 'Output Directory')

    # Time of the first packet 
    parser.add_argument('-t', '--time', type= int, required=True, help= 'Time of the first packet send in the input directory')

    # Json file with the ips of the servers and IoTs
    parser.add_argument('-c', '--config', type=str, required=True, help= 'Path to a Json file with the ips of the servers and IoTs')

    # Tool used to convert pcap to csv
    parser.add_argument('-e', '--export', type=str, required=True, help= 'Tool used to convert pcap to csv')
    
    # attack type
    parser.add_argument('-a', '--attack_protocol', type=str, required=True, nargs=2, help='Protocols used in the attack')

    return parser.parse_args()


def load_ips(filename):
    # Open the JSON file
    with open(filename) as file:
        data = json.load(file)

    # return the contents of the JSON file
    return data


def traffic_filter(df, benign_iots, benign_servers, att_protocol):
    # Pegar tempo benigno do servidor e dos dispositivos IoT
    benign_iots_filter = df['Source'].isin(benign_iots)
    benign_iot_traffic = df[benign_iots_filter]
    
    benign_servers_filter = df['Source'].isin(benign_servers) * df['Destination'].isin(benign_servers)
    benign_servers_traffic = df[benign_servers_filter]
    
    
    # Trafego maligno
    benign_filter = benign_iots_filter + benign_servers_filter
    tcp_filter = ( (df['Protocol'] == att_protocol[0]) + (df['Protocol'] == att_protocol[1]) ) * (~ df['Source'].isin(benign_servers))
    malign_filter = (~benign_filter * tcp_filter)
    malign_traffic = df[malign_filter]

    return [benign_iot_traffic, benign_servers_traffic, malign_traffic]

def process_data(traffic: list, time_windown: int, output_filenames: str):
    for i in range(len(traffic)):
        df = traffic[i]
        output_filename = output_filenames[i]
        packets_per_second(df, time_windown)
        save_data_to_plot(output_filename, df)

    

# Salva os dados no formato csv
# Se a função for chamada na primeira iteração ela cria o arquivo
# Se não só adiciona conteudo ao um arquivo já criado
def save_data_to_plot(file_name: str, df: pd.DataFrame):
    data_to_save = (pd.value_counts(df['Discretized_Time'], sort=False))

    if not os.path.exists(file_name):
        data_to_save.to_csv(file_name, sep='\t', mode='w')
    else:
        data_to_save.to_csv(file_name, sep='\t', mode='a', header=False)
    


# Descritizar quantos pacotes chegarao por segundo
def packets_per_second(df: pd.DataFrame, time_windown: int):
    # Cria o intervalo dos bins
    time_bins = [i for i in range(time_windown[0] ,time_windown[1]+1)]
    
    # O intervalo dos bins é aberto na esquerda e fechado na direita
    # E portanto ele não está discretizando o tempo 0.00
    if time_windown[0] == 0:
        time_bins[0] -= 1
    
    # Cria os rotulos 
    time_label = [i for i in range(time_windown[0]+1, time_windown[1]+1)]

    df['Discretized_Time'] = pd.cut(df['Time'], bins=time_bins, labels=time_label)

def calc_time_windown(df: pd.DataFrame):
    min = df['Time'].min()
    min = int(np.floor(min))

    max = df['Time'].max()
    max= int(np.ceil(max))

    return min, max


main()
