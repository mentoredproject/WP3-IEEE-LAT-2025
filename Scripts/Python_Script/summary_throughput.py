import pandas as pd
import os
import argparse

def main(args):
    # Input Dir
    #                              Throughput
    #                             /    |     \
    #                      /           |           \
    #              /                   |                 \
    #      net_01                    net_02               net_03 
    #        |
    #    emulations
    #        |
    #      files

    # files = benign_iot_traffic.dat | benign_servers_traffic.dat | malign_traffic.dat
    networks_path = args.input

    # df_all_iot = pd.read_csv()
    # df_all_server = pd.read_csv()
    # df_all_malign = pd.read_csv()

    files_dict = {}


    # Carrega todos os caminhos dos arquivos necessários 
    # Para um dicionário
    for net in os.listdir(networks_path):

        if net not in files_dict:
            files_dict[net] = {} 

        net_path = os.path.join(networks_path, net)

        for emulation in os.listdir(net_path):
            emu_path = os.path.join(net_path, emulation)

            for file in os.listdir(emu_path):
                file_path = os.path.join(emu_path, file)
                
                # Verifica se o chave já existe no dicionario 
                if file in files_dict[net]:
                    files_dict[net][file].append(file_path)
                else:
                    files_dict[net][file] = [file_path]

    summary_path = args.output

    # Para cada arquivo de throughput em cada
    # Calcula a média e salva o arquivo na pasta de destino
    for net in files_dict:
        for file in files_dict[net]:
            df = join_dataframes(files_dict[net][file])
            file_output_path = os.path.join(summary_path, net, file)
            df.to_csv(file_output_path, sep='\t')

def join_dataframes(paths):
    # Abre um arquivo e utiliza a coluna Discretized_Time como index
    file_path = paths.pop()
    df = pd.read_csv(file_path, sep="\t", index_col=0)

    # Muda o nome da coluna de count para 0
    df.rename(columns={df.columns[-1]: 0}, inplace=True)
    
    # Variavel utilizada para nomear as colunas
    count = 1
    
    for file_path in paths:
        df2 = pd.read_csv(file_path, sep="\t", index_col=0)
        # Junta os dataframes
        df = pd.merge(df, df2, on=df.index.name, how="outer")
        df.rename(columns={df.columns[-1]: count}, inplace=True) 
        count += 1
    
    # Ordena o dataframe pelo index
    df.sort_index(inplace=True)

    # Calcula a média com base no número de valores
    df['mean'] = df.mean(axis=1)
    df_mean = df['mean']
    
    return df_mean

    

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'summary_throughput.py',
    description= 'Troughput Summary Program',
    # End of help message
    epilog= '''
    ./summary_throughput.py -i <iot-path-directory> -s <server-path-directory> -o <output-path-directory> -t <time-of-first-packets> 
    -c <json-file-with-from-server-and-IoT> -e <wireshark | tshark> -n <number of the network>
    '''
    )

    # Input Directory
    parser.add_argument('-i', '--input', required=True, help= "input directory") 
    
    # Output Directory
    parser.add_argument('-o', '--output', required=True, help= 'Output directory')
    
    args = parser.parse_args()

    return args

if __name__ == "__main__":
    args = argumentsParsing()
    main(args)
