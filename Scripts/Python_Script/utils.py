import pandas as pd
import numpy as np
import json
import os

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
    print(string)
    return "OTHER"

    

def hex_to_text(hex):
    if pd.notna(hex):
        return bytes.fromhex(hex).decode('ascii')
    return np.nan

def udp_payload_slip_string(df, column_name):
    
    def str_split(string: str): 
        att = string.split(' ')
        if len(att) != 4:
            print(string)
            return [np.NAN, np.NAN, np.NAN, np.NAN]
        return att

    df["TMP2"] =  df[column_name].apply(str_split)


    def list_split(df):
        df['Packet_ID'] = ""
        df['Packet_Send_Time'] = ""
        df['Packet_Data_File_Line'] = ""
        df['Value_Capture_by_the_Sensor'] = ""

        for i in df.index:
            payload = df['TMP2'][i]
            # print(payload[0])
            # payload = ast.literal_eval(df["TMP"][i])
            df.loc[i, "Packet_ID"] = payload[0]
            df.loc[i, "Packet_Send_Time"] = payload[1]
            df.loc[i, "Packet_Data_File_Line"] = payload[2]
            df.loc[i, "Value_Capture_by_the_Sensor"] = payload[3]
        
        return df


    df = list_split(df)
    
    df.to_csv('/tmp/iot_delay_dataframe_inteiro2.3.2.csv')
    df.drop("TMP2", axis=1, inplace=True)
    df['Packet_ID'] = pd.to_numeric(df['Packet_ID'])
    return df 
   

def convert_udp_payload(df: pd.DataFrame, column_name):
    
    df["TMP"] = df[column_name].apply(hex_to_text)
    df = udp_payload_slip_string(df, "TMP")
    df.drop("TMP", axis=1, inplace=True)
    return df

def load_ips(filename):
    # Open the JSON file
    with open(filename) as file:
        data = json.load(file)

    # return the contents of the JSON file
    return data


def load_traffic_and_filter_by_source_IP(csv_directory, export_mode, first_packet_time, iot_net, negation=False):
    df_server_iot_traffic = pd.DataFrame()

    # iterate over files in
    # that directory
    for filename in os.listdir(csv_directory):
        f = os.path.join(csv_directory, filename)
        # checking if it is a file
        if not os.path.isfile(f):
            continue

        # Iterar sobre os arquivos
        df = pd.read_csv(f)

        if (export_mode == "tshark"):
            df = convert_tshark_csv_to_wireshark(df)

        # df = convert_udp_payload(df, 'udp.payload')

        # Convert this column to a relative time
        df['Time'] -= first_packet_time

        # Separa o trafego em iot, servidor e maligno
        traffic = traffic_filter(df, iot_net, negation)

        df_server_iot_traffic = pd.concat([df_server_iot_traffic, traffic], ignore_index=True)

    return df_server_iot_traffic

def traffic_filter(df, iot_net, negation):
     # Pegar tempo benigno do servidor e dos dispositivos IoT
    filter = df['Source'].isin(iot_net)

    if negation:
        return df[~filter]
    else:
        return df[filter]

# Filter the server data frame, to select only the time windown used for analysis 
def select_analysis_window(df: pd.DataFrame, column:str, begin:float, end: float ):
    filter = (df[column] < begin) + (df[column] > end)
    return df[~filter]
