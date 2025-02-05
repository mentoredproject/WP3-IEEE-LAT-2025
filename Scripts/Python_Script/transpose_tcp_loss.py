import pandas as pd
import argparse

def main():
    args = argumentsParsing()

    file = open(args.input)
    output = args.output

    data = {}

    for i in file:
        # Quebra a string quando encontrar (whitespace + , + whitespace)
        x  = i.split(' , ')
        # Remove quebra de linha
        x[1] = x[1].replace('\n', '')
        # Remove '%' dos dados que possuem esses simbolos
        x[1] = x[1].replace('%', '')
        
        data[x[0]] = x[1]

    df = pd.DataFrame(data, index=[0])
    df['emulation'] = args.emulation
    
    df.to_csv(output)

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'transpose_tcp_loss.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./transpose_tcp_loss.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    ) 

    # input file path
    parser.add_argument('-i', '--input', required=True, help= "input file path") 
    
    # output path and name
    parser.add_argument('-o', '--output', required=True, help= 'output path and name')

    parser.add_argument('--emulation', required=False, help= 'Output path')
    
    return parser.parse_args()  


if __name__ == '__main__':
    main()