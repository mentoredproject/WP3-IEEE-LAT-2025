import pandas as pd
import os
import argparse

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'concatenate.py',
    description= 'concatenete multiple csv files into one file',
    # End of help message
    epilog= '''
    ./concatenate.py -c <dir-path>
    '''
    )

    # Directory with the csv files
    parser.add_argument('-c', '--csv', required=True, help= "directory with csv files") 

    # Output path
    parser.add_argument('-o', '--output', required=True, help= 'Output path')

    return parser.parse_args()  

args = argumentsParsing()

# Specify the directory containing the CSV files
csv_directory = args.csv

# Get a list of all CSV files in the directory
csv_files = [f for f in os.listdir(csv_directory) if f.endswith('.csv')]

# Initialize an empty DataFrame to store the concatenated data
concatenated_data = pd.DataFrame()

# Loop through each CSV file and concatenate its data
for csv_file in csv_files:
    file_path = os.path.join(csv_directory, csv_file)
    
    # Read the CSV file into a DataFrame
    data = pd.read_csv(file_path)
    
    # Concatenate the data to the existing DataFrame
    concatenated_data = pd.concat([concatenated_data, data], ignore_index=True)

# Save the concatenated data to a new CSV file
# concatenated_data.sort_values(by=['Send_time_interface'], inplace=True)
concatenated_data.to_csv(args.output, index=False)

print(f"Concatenation completed. Data saved to {args.output}.")

