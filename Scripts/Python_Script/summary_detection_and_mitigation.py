import pandas as pd
import numpy as np
import argparse
import os


def main(args):
    input_directory = args.input
    metric = args.mode
    output_directory = args.output


    df_net_01 = pd.DataFrame()
    df_net_02 = pd.DataFrame()
    df_net_03 = pd.DataFrame()
    df_net_04 = pd.DataFrame()
    df_net_05 = pd.DataFrame()

    # iterate over files in
    # the csv directory
    for emulation_name in os.listdir(input_directory):
        emulation_path = os.path.join(input_directory, emulation_name)
        # checking if it is a file
        if not os.path.isdir(emulation_path):
            continue

        for filename in os.listdir(emulation_path):
            file_path = os.path.join(emulation_path, filename)
            df = pd.read_csv(file_path)
            df["emulation_id"] = emulation_name 

            if "1" in filename:
                df_net_01 = pd.concat([df_net_01, df], ignore_index=True)
            elif "2" in filename:
                df_net_02 = pd.concat([df_net_02, df], ignore_index=True)
            elif "3" in filename:
                df_net_03 = pd.concat([df_net_03, df], ignore_index=True)
            elif "4" in filename:
                df_net_04 = pd.concat([df_net_04, df], ignore_index=True)
            elif "5" in filename:
                df_net_05 = pd.concat([df_net_05, df], ignore_index=True)
    
    save_summary(df_net_01, output_directory, metric, 1)
    save_summary(df_net_02, output_directory, metric, 2)
    save_summary(df_net_03, output_directory, metric, 3)
    save_summary(df_net_04, output_directory, metric, 4)
    save_summary(df_net_05, output_directory, metric, 5)


def save_summary(df_input, output_path, metric, net):
    df_input.set_index('emulation_id', inplace=True)

    for proto in ['UDP', 'ICMP']:
        filter = df_input['Protocol'] == proto
        df = df_input[filter]
        df = df.drop(['Protocol'], axis=1)

        df.to_csv(os.path.join(f"{output_path}/{metric}_net_0{net}_{proto}.csv"), sep=',', mode='w')

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'summary_detection_and_mitigation.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./summary_detection_and_mitigation.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Input file
    parser.add_argument('-i', '--input', required=True, help= "input file") 
    
    # Output path
    parser.add_argument('-o', '--output', required=True, help= 'Output path')

    # The mode that the program will operate
    parser.add_argument('--mode', type=str, required=True, help='Select the type of operation that the script will do' )

    
    args = parser.parse_args()

    return args



if __name__ == "__main__":
    args = argumentsParsing()
    main(args)