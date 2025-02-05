import pandas as pd
import numpy as np
import argparse
import os

def main():
    args = argumentsParsing()

    df_input = pd.read_csv(args.input, sep='\t', index_col=0)
    
    # Packet_loss summary
    pl_summary = {"emulation_id" : args.id,
                  "min_send": 0, 
                  "max_send": 0,
                  "Total_send": 0,
                  "Std_error_send": 0,
                  "min_recv": 0,
                  "max_recv": 0,
                  "Total_recv": 0,
                  "Std_error_recv": 0,
                  "min_packet_loss": 0,
                  "max_packet_loss": 0,
                  "Total_packet_loss": 0,
                  "Std_error_packet_loss": 0
                  }

    pl_summary["min_send"] = df_input['Packets_Send'].min()
    pl_summary['max_send'] = df_input['Packets_Send'].max()
    pl_summary['Total_send'] = df_input['Packets_Send'].sum()
    pl_summary['Std_error_send'] = df_input['Packets_Send'].std()

    pl_summary["min_recv"] = df_input['Packets_Receive'].min()
    pl_summary['max_recv'] = df_input['Packets_Receive'].max()
    pl_summary['Total_recv'] = df_input['Packets_Receive'].sum()
    pl_summary['Std_error_recv'] = df_input['Packets_Receive'].std()

    pl_summary["min_packet_loss"] = df_input['Packets_Loss'].min()
    pl_summary['max_packet_loss'] = df_input['Packets_Loss'].max()
    pl_summary['Total_packet_loss'] = df_input['Packets_Loss'].sum()
    pl_summary['Std_error_packet_loss'] = df_input['Packets_Loss'].std()

    df_summary = pd.DataFrame(data = pl_summary, index=[0])

    print(args.output)
    df_summary.to_csv(args.output, index=False)

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'summary.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./summary.py -i <input-file-path> -o <output-path-directory>
    '''
    )

    # Packet Loss input file
    parser.add_argument('-i', '--input', required=True, help= "Input file in the format csv") 

    # Output path
    parser.add_argument('-o', '--output', required=True, help= 'Output path')

    # number of the network
    parser.add_argument('-n', '--number', type=int, required=True, help= 'Network number')

    parser.add_argument('--id', type=str, required=True, help='<Emulation> Identifier')
    
    return parser.parse_args()


if __name__ == '__main__':
    main()