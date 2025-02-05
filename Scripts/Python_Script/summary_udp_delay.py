import pandas as pd
import argparse
import numpy as np
import sys

from utils import select_analysis_window

np.seterr(all="ignore")

def main():
    args = argumentsParsing()
    if args.mode == 'iot':
        get_iot_summary(args.window, args.input, args.output, args.id)
    elif args.mode == 'net':
        get_net_summary(args.input, args.output, args.id)
    elif args.mode == 'server':
        get_server_summary(args.window, args.input, args.output, args.id)


def get_server_summary(window, input, output, emulation_id):
    window_start_time, window_end_time = window

    df = pd.read_csv(input)
    df = select_analysis_window(df, 'timestamp_snd', window_start_time, window_end_time)

    data = {}

    data['emulation_id'] = emulation_id
    data['min_us'] = df['delay_us'].min()
    data['max_us'] = df['delay_us'].max()
    data['mean_us'] = df['delay_us'].mean()
    data['median_us'] = df['delay_us'].median()
    data['stderror_us'] = df['delay_us'].std()
    data['amount_of_data'] = (df.shape)[0]

    df_data = pd.DataFrame(data, index=[0])
    df_data.to_csv(output, index=False)


def get_net_summary(input, output, emulation_id):
    df = pd.read_csv(input)

    data = {}

    data['emulation_id'] = emulation_id
    data['min_us(net)'] = df['min_us'].min()
    data['max_us(net)'] = df['max_us'].max()
    data['mean_us(iot)'] = df['mean_us'].mean()
    data['median_us(net)'] = df['median_us'].median()
    data['stderror_us(mean_iot)'] = df['stderror_us'].std()
    data['amount_of_data(mean_iot)'] = df['amount_of_data'].median()

    df_data = pd.DataFrame(data, index=[0])
    df_data.to_csv(output, index=False)

def get_iot_summary(window, input, output, id):
    window_start_time, window_end_time = window

    df = pd.read_csv(input)
    df = select_analysis_window(df, 'Send_time_interface', window_start_time, window_end_time)

    data = {}

    data['iot_id'] = id
    data['min_us'] = df['Delay_microseconds'].min() if df['Delay_microseconds'].count() != 0 else np.NAN
    data['max_us'] = df['Delay_microseconds'].max() if df['Delay_microseconds'].count() != 0 else np.NAN
    data['mean_us'] = df['Delay_microseconds'].mean() if df['Delay_microseconds'].count() != 0 else np.NAN
    data['median_us'] = df['Delay_microseconds'].median() if df['Delay_microseconds'].count() != 0 else np.NAN
    data['stderror_us'] = df['Delay_microseconds'].std() if df['Delay_microseconds'].count() != 0 else np.NAN
    data['amount_of_data'] = (df.shape)[0]

    df_data = pd.DataFrame(data, index=[0])
    df_data.to_csv(output, index=False)

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'summary_udp_delay.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./summary_udp_delay.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Input file
    parser.add_argument('-i', '--input', required=True, help= "input file") 
    
    # Output path
    parser.add_argument('-o', '--output', required=True, help= 'Output path')

    # Time window where the analysis will be made
    parser.add_argument('-w', '--window', type=int, required=False, nargs=2, help= 'Time Window use in the analysis')

    parser.add_argument('--mode', type=str, required=True, help='Select the type of operation that the script will do' )

    parser.add_argument('--id', type=str, required=True, help='<IoT|Emulation> Identifier')
    
    # Adicione a condição para tornar o segundo argumento obrigatório
    args = parser.parse_args()

    if (args.mode == 'iot' or args.mode == 'server') and args.window is None:
        parser.error("--window é obrigatório no modo iot ou server")

    return args

if __name__ == '__main__':
    main()