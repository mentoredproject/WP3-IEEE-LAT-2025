
import os
import pandas as pd
import argparse
import shutil

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'tcp_script.py',
    description= 'packet loss analysis (at the aplication level) for TCP communication beetween the servers',
    # End of help message
    epilog= '''
    ./tcp_script.py -i <input-directory(Server dir)> -o <output-path-directory> -t <time-of-first-packets> 
    '''
    )
    # Directory with the csv files from the iot device
    parser.add_argument('-i', '--input', required=True, help= "directory where the output directories for each server are located") 

    # Output Directory
    parser.add_argument('-o', '--output', required=True, help= 'Output Directory')

    # Time of the first packet 
    parser.add_argument('-t', '--time', type= int, required=True, help= 'Time of the first packet send in the input directory')

    # save pre processer output files (default = delete)
    parser.add_argument('-s', '--save', type= bool, required=False, help= 'Save ', default=False)

    # Time window where the analysis will be made
    parser.add_argument('-w', '--window', type=int, required=False, nargs=2, help= 'Time Window use in the analysis')
    
    return parser.parse_args()

def delete_last_line_from_csv(file_path):
    # Read all lines except the last one
    with open(file_path, 'r') as file:
        lines = file.readlines()[:-1]

    # Open the same file in write mode to overwrite its contents
    with open(file_path, 'w') as file:
        file.writelines(lines)

def pre_process(server_num, input_dir, output_dir):
    output_dir=f"{output_dir}/output_{server_num}"
    
    # Create a directory to store the separate CSV files
    os.makedirs(output_dir, exist_ok=True)

    file_path = os.path.join(input_dir, f"Server_{server_num}/server.csv")
    
    # Delete last line of the input file because it may be broken
    delete_last_line_from_csv(file_path)
    
    lines_to_keep = []

    # Open the file and read its content
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Filter out lines with the correct number of columns
    for line in lines:
        if len(line.split(',')) == 6:
            lines_to_keep.append(line)

    # Open the file again in write mode and overwrite it with the filtered content
    with open('/tmp/server_filter.csv', 'w') as file:
        file.writelines(lines_to_keep)

    file_path = '/tmp/server_filter.csv'
    
    # Order of data types for columns
    dtype_list = [str, str, int, int, int, str]  
    
    # Provide column names (optional)
    column_names = ['source_ip', 'destination_ip', 'seq_number', 'timestamp', 'micro_sec', 'identifier']
    
    # Read the CSV file with specified data types and column names (if available)
    df = pd.read_csv(file_path, header=None, dtype=dict(zip(range(len(dtype_list)), dtype_list)), names=column_names)
    
    # Write the modified DataFrame back to the CSV file without a header
    clean_file_path = os.path.join(output_dir, f'cleanData_{server_num}.csv')
    df.to_csv(clean_file_path, index=False, header=True)
    
    # Group the DataFrame by the unique pairs of IP addresses
    grouped = df.groupby(['source_ip', 'destination_ip'])
    
    # Iterate over the groups and save each group as a separate CSV file
    for (source_ip, destination_ip), group_df in grouped:
        filename = f"{source_ip}_{destination_ip}.csv"
        filepath = os.path.join(output_dir, filename)
        group_df.to_csv(filepath, index=False)
        print(f"<data_pre_processor> Saved {filepath}")

def post_process(input1: str, input2: str, input3: str, input4: str, output: str, epoch_emulation_start: int):
    # Order of data types for columns
    # source_ip/dest_ip/epoch_time/micro_sec/pkt_id
    dtype_list = [str, str, int, int, int, str]  

    # read input {smd[i]   snd  smd[i+1]}
    df1 = pd.read_csv(input1, dtype=dict(zip(range(len(dtype_list)), dtype_list)))
    # read input {smd[i+1] rcv  smd[i]}
    df2 = pd.read_csv(input2, dtype=dict(zip(range(len(dtype_list)), dtype_list)))
    # read input {smd[i+1] snd  smd[i]}
    df3 = pd.read_csv(input3, dtype=dict(zip(range(len(dtype_list)), dtype_list)))
    # read input {smd[i}   rcv  smd[i+1}
    df4 = pd.read_csv(input4, dtype=dict(zip(range(len(dtype_list)), dtype_list)))

    # {merge (snd,rcv) pairs}
    # merged_df1 = pd.merge(df1, df2, how="left", on=["source_ip","destination_ip","identifier"])
    # merged_df2 = pd.merge(df3, df4, how="left", on=["source_ip","destination_ip","identifier"])
    merged_df1 = pd.merge(df1, df2, how="left", on=["source_ip","destination_ip","identifier", "seq_number"])
    merged_df2 = pd.merge(df3, df4, how="left", on=["source_ip","destination_ip","identifier", "seq_number"])

    # output (smd[i] <~~> smd[i+1])
    output_df=pd.concat([merged_df1,merged_df2], ignore_index=True)

    # Calculate timestamp_snd and timestamp_rcv relative to 
    output_df['timestamp_snd'] = round(output_df['timestamp_x']-epoch_emulation_start + output_df['micro_sec_x'] / 1000000, 6)
    output_df['timestamp_rcv'] = round(output_df['timestamp_y']-epoch_emulation_start + output_df['micro_sec_y'] / 1000000, 6)


    output_df['delay_us'] = round(1000000*(output_df['timestamp_rcv']-output_df['timestamp_snd']),0)
    # Retira os valores extremos de latencia
    # Devido a duplicação de pacotes 
    # E o casamento erroneo entre esses pacotes 
    filter = (output_df['delay_us'] < 0) + (output_df['delay_us'] > 2000)
    output_df = output_df[~filter]

    output_df.sort_values(by='timestamp_snd', ascending=True, inplace=True)

    output_df[["identifier","source_ip","destination_ip", 'seq_number', "timestamp_snd","timestamp_rcv","delay_us"]].to_csv(output, index=False)
    # output_df[["identifier","source_ip","destination_ip", 'seq_number_x', "timestamp_snd","timestamp_rcv","delay_us"]].to_csv(output, index=False)
    
    print(f"<data_post_processor> Saved {output}")

# Filter the server data frame, to select only the time windown used for analysis 
def select_analysis_window(df: pd.DataFrame, begin:int, end: int ):
    filter = (df['timestamp_snd'] < begin) + (df['timestamp_snd'] > end)
    return df[~filter]


def merge_csv_files_in_folder(folder_path, output_file):
    """
    Merge all CSV files in the given folder into a single CSV file.

    Args:
        folder_path (str): Path to the folder containing CSV files.
        output_file (str): Path to the output merged CSV file.
    """
    all_files = [f for f in os.listdir(folder_path) if f.endswith('.csv')]
    
    if not all_files:
        print("No CSV files found in the folder.")
        return
    
    dataframes = []
    for file in all_files:
        file_path = os.path.join(folder_path, file)
        try:
            print(f"Reading file: {file}")
            df = pd.read_csv(file_path)
            dataframes.append(df)
        except Exception as e:
            print(f"Error reading {file}: {e}")
    
    if dataframes:
        merged_df = pd.concat(dataframes, ignore_index=True)
        merged_df = merged_df.sort_values(by="timestamp_snd")
        try:
            merged_df.to_csv(output_file, index=False)
            print(f"Merged file saved as: {output_file}")
        except Exception as e:
            print(f"Error saving merged file: {e}")
    else:
        print("No valid CSV files to merge.")

def main():
    # int main() {{{

        # command line arguments
        # {
    args = argumentsParsing()
    input_base_dir = f"{args.input}" 
    output_base_dir = f"{args.output}"
    start_epoch = args.time
        # }

        # preprocess the data from the servers (Smd_01,Smd_02,Smd_03)
        # {
    server_numbers = ['01', '02', '03', '04', '05']

    for server_num in server_numbers:
        pre_process(server_num, input_base_dir, output_base_dir)

    os.makedirs(f"{output_base_dir}/tmp_SMDs", exist_ok=True)

    for s in server_numbers:
        os.makedirs(f"{output_base_dir}/tmp_SMDs/{s}", exist_ok=True)
        # }

        # postprocess the data to generate the output
        # {
    smd= [1,2,3,4,5]
    for i in smd:
        for k in range(len(smd)-1):
            j=i-1
            post_process(
                f"{output_base_dir}/output_0{smd[j]}/10.128.{smd[j]}0.30_10.128.{(smd[j]+k)%5+1}0.30.csv",# {smd[i]   snd  smd[i+1]} input file
                f"{output_base_dir}/output_0{(smd[j]+k)%5+1}/10.128.{smd[j]}0.30_10.128.{(smd[j]+k)%5+1}0.30.csv",    # {smd[i+1] rcv  smd[i]}   input file
                f"{output_base_dir}/output_0{(smd[j]+k)%5+1}/10.128.{(smd[j]+k)%5+1}0.30_10.128.{smd[j]}0.30.csv",    # {smd[i+1] snd  smd[i]}   input file
                f"{output_base_dir}/output_0{smd[j]}/10.128.{(smd[j]+k)%5+1}0.30_10.128.{smd[j]}0.30.csv",        # {smd[i}   rcv  smd[i+1}  input file
                f"{output_base_dir}/tmp_SMDs/0{smd[j]}/smd_0{smd[j]}_0{(smd[j]+k)%5+1}.csv", start_epoch  # output file && emulation start time
            )

    os.makedirs(f"{output_base_dir}/SMDs", exist_ok=True)

    for s in server_numbers:    
        merge_csv_files_in_folder(f"{output_base_dir}/tmp_SMDs/{s}", os.path.join(f"{output_base_dir}/SMDs", f"smd_{s}.csv"))

        # delete extra files [pre_process() outputs]
        # {
    if args.save == False:
        shutil.rmtree(f"{output_base_dir}/tmp_SMDs")
        print(f"<main> deleting folder {output_base_dir}/tmp_SMDs ...")
        for server_num in server_numbers: 
            shutil.rmtree(f"{output_base_dir}/output_{server_num}")
            print(f"<main> deleting folder {output_base_dir}/output_{server_num} ...")
        # }

    # }}}

if __name__ == "__main__":
    main()
