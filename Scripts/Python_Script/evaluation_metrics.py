import pandas as pd
import argparse
from datetime import datetime
import pytz
import json
import math
import os
# from mitigation import convert_datetime_to_unix_epoch


def main(args):

    experiment_ips = args.experiment_ips
    protocols = args.protocol
    time = args.time
    snort_log = args.snort_log
    snort_timezone = args.snort_tz
    network_number = args.number
    output_dir = args.output
    id = args.emulation_id
    bonesi_log = args.bonesi_log



    server_ips, benign_ips, malign_ips = get_experiment_ips(experiment_ips)

    bonesi_attack=  get_bonesi_data(bonesi_log, server_ips[network_number-1], time)

    # Estrutura de dados que será utilizado para salvar os valores
    # SLB -> Snort Log Number of Benign events 
    # SLM -> Snort Log Number of Malign events 

    N = 20
    table = {'missed_malign_packets': {'UDP': 0, 'ICMP': 0},
             'detection': {'UDP': 0, 'ICMP': 0},
             'slb': {'UDP': 0, 'ICMP': 0},
             'slm': {'UDP': 0, 'ICMP': 0}
            }

    server_number_of_malign_packets(
        args.snort_traffic, 
        args.export,
        args.protocol, 
        bonesi_attack, 
        args.time,
        benign_ips, 
        malign_ips, 
        table
        )
    
    snort_log_get_number_of_benign_and_malign_events(
        snort_log,
        protocols,
        bonesi_attack, 
        time, 
        snort_timezone,  
        benign_ips, 
        malign_ips, 
        table
        )
   
    # Summaring all values in the dictionary
    snort_log_number_of_lines_during_the_udp_attack = table['detection']['UDP'] / 2 # Counted two times
    snort_log_number_of_lines_during_the_icmp_attack = table['detection']['ICMP'] / 2
    SLB_UDP = table['slb']['UDP']
    SLB_ICMP = table['slb']['ICMP']
    SLM_UDP = table['slm']['UDP']
    SLM_ICMP = table['slm']['ICMP']

    file_output_udp = os.path.join(f"{output_dir}/UDP/{id}_udp.csv")
    file_output_icmp = os.path.join(f"{output_dir}/ICMP/{id}_icmp.csv")
    
    f = open(file_output_udp, "w")
    f.write("id,Bonesi_number_packets,missed_malign_packets,number_of_detection,correct_detection,false_detection\n")
    f.write(f"{id},{bonesi_attack['UDP']['Total_of_packets_send']},{table['missed_malign_packets']['UDP']},{snort_log_number_of_lines_during_the_udp_attack},{SLM_UDP},{SLB_UDP}")

    f = open(file_output_icmp, "w")
    f.write("id,Bonesi_number_packets,missed_malign_packets,number_of_detection,correct_detection,false_detection\n")
    f.write(f"{id},{bonesi_attack['ICMP']['Total_of_packets_send']},{table['missed_malign_packets']['ICMP']},{snort_log_number_of_lines_during_the_icmp_attack},{SLM_ICMP},{SLB_ICMP}")
    
def server_number_of_malign_packets(snort_traffic, export_mode, protocol, attacks, emulation_start_time, benign_ips, malign_ips, table):
    for filename in os.listdir(snort_traffic):
        f = os.path.join(snort_traffic, filename)
        
        # checking if it is a file
        if not os.path.isfile(f):
            continue

        # Iterar sobre os arquivos
        chunk = pd.read_csv(f)

        if (export_mode == "tshark"):
            chunk = convert_tshark_csv_to_wireshark(chunk)

        # Convert this column to a relative time
        chunk['Time'] -= emulation_start_time    

        # Numero de linha que possuem trafego maligno
        server_get_number_of_malign_packets(chunk, malign_ips, protocol, attacks, table, 'missed_malign_packets')


def snort_log_get_number_of_benign_and_malign_events(snort_json, proto, attacks, emulation_start_time, tz, benign_ips, malign_ips, table):
    for chunk in pd.read_json(snort_json, lines=True, chunksize=100000):
        if chunk.empty:
            continue
        
        # Get the year of a given unix epoch
        dt = datetime.fromtimestamp(emulation_start_time)

        chunk['unix_epoch'] = chunk['timestamp'].apply(convert_datetime_to_unix_epoch, args=(dt.year ,tz))
        chunk['unix_epoch'] -= emulation_start_time
        chunk[['src_ip', 'src_port']] = chunk['src_ap'].str.split(':', expand=True)

        # snort_log_get_number_events(df, index,malign_ips, proto, table, 'slm')
        snort_log_get_number_events(chunk, benign_ips, proto, attacks, table, 'slb')
        snort_log_get_number_events(chunk, malign_ips, proto, attacks, table, 'slm')
        

def server_get_number_of_malign_packets(df_input, ips, protocol, attacks, table, key):
    for p in protocol:
        attack = attacks[p]

        # Select only the data inside the attack period plus more 60 seconds
        filter = (df_input['Time'] < attack['Attack_begin']) + (df_input['Time'] > attack['Attack_end']+60)
        df = df_input[~filter]

       # Select only the benign or malign ips
        filter = df['Source'].isin(ips)
        df = df[filter]
    
        # Group by protocol and count in a single operation:
        counts = df.groupby('Protocol')['Protocol'].count()

        # Update the table with the counts:
        table[key][p] += counts.get(p, 0)  # Handle missing protocols
        
def snort_log_get_number_events(df_input, ips, protocol, attacks, table, key):
    for p in protocol:
        attack = attacks[p]

        # Select only the data inside the attack period plus more 60 seconds
        filter = (df_input['unix_epoch'] < attack['Attack_begin']) + (df_input['unix_epoch'] > attack['Attack_end']+60)
        df = df_input[~filter]

        table['detection'][p] += df.shape[0]

        # Select only the benign or malign ips
        filter = df['src_ip'].isin(ips)
        df = df[filter]

        # Group by protocol and count in a single operation:
        counts = df.groupby('proto')['proto'].count()

        # Update the table with the counts:
        table[key][p] += counts.get(p, 0)  # Handle missing protocols
    

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

# Retorna 
def get_experiment_ips(json_path):
    with open(json_path) as file:
        data = json.load(file)

    server_ips = data['servers']

    # IPS used by iot devices and servers
    benign_ips = get_benign_ips(json_path)

    # IPS used by the DDOS tool BoNeSi
    malign_ips = get_malign_ips(json_path)
    malign_ips = expand_ip_range(malign_ips)

    return server_ips, benign_ips, malign_ips

def get_benign_ips(file_path):
    # Open the JSON file
    with open(file_path) as file:
        data = json.load(file)

    # Remove the malign ips
    data.pop('bonesi')

    data = list(data.values())
    # return the benign ips in the json file
    return flatten_comprehension(data)

def flatten_comprehension(matrix):
    return [item for row in matrix for item in row]

def get_malign_ips(file_path):
    # Open the JSON file
    with open(file_path) as file:
        data = json.load(file)

    # Get the malign ips
    data = data.pop('bonesi')
    
    # return the malign ips in the json file
    return data



def get_bonesi_data(file_path, server_ip, experiment_start_time):

    df_bonesi = pd.read_csv(file_path)
    filter = df_bonesi['dstIp'] == server_ip
    df_bonesi = df_bonesi[filter]
    df_bonesi['Attack_end'] -= experiment_start_time
    df_bonesi['Attack_begin'] -= experiment_start_time

    filter = df_bonesi['protocol'] == 17
    attack_time_udp = dict(df_bonesi[filter][['Total_of_packets_send','Attack_begin', 'Attack_end']].iloc[0])
    
    filter = df_bonesi['protocol'] == 1
    attack_time_icmp = dict(df_bonesi[filter][['Total_of_packets_send','Attack_begin', 'Attack_end']].iloc[0])

    return {'UDP':attack_time_udp, 'ICMP':attack_time_icmp}

def expand_ip_range(ip_range):
  """Expande um intervalo de endereços IP com máscara de rede /24 para /32.

  Args:
    ip_range: Uma lista de endereços IP com máscara de rede /24.
    mask_len: O comprimento da máscara de rede para a expansão.

  Returns:
    Uma lista de endereços IP com máscara de rede /32.
  """

  expanded_range = []
  for ip in ip_range:
    octets = ip.split(".")
    octets.append(0)

    for i in range(0,256):
        octets[3] = str(i)
        expanded_range.append(".".join(octets))
  return expanded_range

def convert_tshark_csv_to_wireshark(df: pd.DataFrame):
    # Rename the columns name to match the wireshark name
    df.rename(
        columns = {
            'frame.time_epoch': 'Time',
            'ip.src' : 'Source',
            'ip.dst' : 'Destination',
            'frame.protocols' : 'Protocol'
            },
            inplace=True
    )

    # Drop all lines that have missing values in a subset of columns
    df.dropna(subset=['Time', 'Source', 'Destination', 'Protocol', 'ip.len'], inplace=True)

    # change the data in protocols to have the same name as in Wireshark
    df['Protocol'] = df['Protocol'].apply(convert_tshark_protocols_name)
   
    return df

def convert_tshark_protocols_name(string):
    if "eth:ethertype:ip:udp" in string:
        return "UDP"
    if "eth:ethertype:ip:tcp" in string:
        return "TCP"
    if "eth:ethertype:ip:icmp" in string:
        return "ICMP"
    return "OTHER"

    

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'evaluation_metrics.py',
    description= 'Evaluation Metrics Analysis Program',
    # End of help message
    epilog= '''
    ./evaluation_metrics.py 
    --snort_log <snort logs path> 
    --snort_traffic <snort network traffic> 
    --experiment_ips <files_with_ip_address_used_in_the_experiment> 
    -o <Output Directory>
    -t < Time that the experiment start>
    -e <wireshark | tshark> 
    -n <number of the network>
    --protocol < UDP ICMP >
    '''
    )

    # Directory with the csv files from the server
    parser.add_argument('--snort_log', required=True, help= "directory with csv files from the server")

    # Output Directory
    parser.add_argument('-o', '--output', required=True, help= 'Output Directory')

    # Time of the first packet 
    parser.add_argument('-t', '--time', type= int, required=True, help= 'Time of the first packet send in the input directory')

    # Json files_with_ip_address_used_in_the_experiment
    parser.add_argument('--experiment_ips', type=str, required=True, help= 'Path to a Json file with the ips of the servers and IoTs')

    # number of the network
    parser.add_argument('-n', '--number', type=int, required=True, help= 'Network number')

    parser.add_argument('--protocol', type=str, required=True, nargs=2, help= 'Protocols used in the attack')

    parser.add_argument('--snort_tz', type=int, required=True, help='Time zone used in Snort log')

    parser.add_argument('--bonesi_log', type=str, required=True, help='Path to the file')

    parser.add_argument('--emulation_id', type=str, required=True, help='Emulation Identification')

    parser.add_argument('--snort_traffic', required=True, help= "Path to a Snort logfile")
    
    parser.add_argument('-e', '--export', type=str, required=True, help= 'Tool used to convert pcap to csv')

    return parser.parse_args()

if __name__ == "__main__":

    args = argumentsParsing()
    main(args)

