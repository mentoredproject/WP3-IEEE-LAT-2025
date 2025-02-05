import pandas as pd
import numpy as np
import argparse
import os


def main(args):
    input_directory = args.input
    output_path = args.output

    df_net = pd.DataFrame()

    # iterate over files in
    # the csv directory
    for filename in os.listdir(input_directory):
        file_path = os.path.join(input_directory, filename)
        # checking if it is a file
        if not os.path.isfile(file_path):
            continue

        emulation_id = filename[:-4]

        df = pd.read_csv(file_path)
        df["emulation_id"] = emulation_id

        df_net = pd.concat([df_net, df], ignore_index=True)

    df_net.set_index('emulation_id', inplace=True)
    df_net.to_csv(os.path.join(output_path), sep=',', mode='w')  



def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'summary_evaluation_metrics.py',
    description= 'Summary Evaluation Metrics',
    # End of help message
    epilog= '''
    ./summary_evaluation_metrics.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Input file
    parser.add_argument('-i', '--input', required=True, help= "input file") 
    
    # Output path
    parser.add_argument('-o', '--output', required=True, help= 'Output path')
    
    args = parser.parse_args()

    return args



if __name__ == "__main__":
    args = argumentsParsing()
    main(args)