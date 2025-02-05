import re
import pandas as pd
import datetime
import os


input_directory = "Output/"
output_directory = "Tempo_de_compartilhamento/emulation"

def main():

    for emulation_name in os.listdir(input_directory):
        emulation_path = os.path.join(input_directory, emulation_name)
        # checking if it is a file
        if not os.path.isdir(emulation_path):
            continue

        df = emulation_process(emulation_path)

        output_path = os.path.join(output_directory, f"{emulation_name}.csv")
        df.to_csv(output_path, index=False)
        print(df)
    
    
def emulation_process(emulation_path):
    df = pd.DataFrame()

    time = load_time(os.path.join(emulation_path, "tempo_inicializacao.txt"))
    
    for net in os.listdir(emulation_path):
        net_path = os.path.join(emulation_path, net)
        
        # checking if it is a directory
        if not os.path.isdir(net_path):
            continue
        df = network_process(net_path, time, net, df)
    
    df.sort_values('TIME', inplace=True)
    return df

def network_process(net_path, time, net, df_merge):

    for file in os.listdir(net_path):
        file_path = os.path.join(net_path, file)

        if not os.path.isfile(file_path):
            continue

        new_df = pd.DataFrame()

        if 'encaminhamento' in file or 'envio' in file:
            df = load_to_pandas(file_path)
            if df.empty:
                continue
            df = datetime_to_epoch(df, time)

            filter = df['STATUS'] == 'SUCESS'
            df = df[filter]

            new_df = df.loc[:, ['TIME', 'IP ORIGEM', 'IP DESTINO']]
            new_df['NETWORK'] = net[4:]
            if 'envio' in file:
                new_df['OPERATION'] = 'S'
            else:
                new_df['OPERATION'] = 'F'
            new_df['PROTOCOL'] = df['REGRA'].apply(extract_protocol)
            new_df['ID'] = df.index

        elif 'recebe' in file:
            df = load_to_pandas(file_path)
            if df.empty:
                continue
            df = datetime_to_epoch(df, time)

            new_df = df.loc[:, ['TIME', 'IP ORIGEM', 'IP DESTINO']]
            new_df['NETWORK'] = net[4:]
            new_df['OPERATION'] = 'R'
            new_df['PROTOCOL'] = df['REGRA'].apply(extract_protocol)
            new_df['ID'] = df.index

        
        df_merge = pd.concat([df_merge, new_df], ignore_index=True)
    
    return df_merge

def extract_protocol(string):
    """Extracts the protocol from a Snort rule-like string."""
    words = string.split()
    return str.upper(words[1])  # The protocol is typically the second word

def load_time(file_path):
    with open(file_path, "r") as f:
        line = f.readline()

    return int(line.split(":")[1])
    
def timezone_to_int(timezone):
    return int(timezone.split(':')[0])


def datetime_to_epoch(df, emulation_start_time):
    df['TIMEZONE'] = df['TIMEZONE'].apply(timezone_to_int)
    tz = df['TIMEZONE'].unique()[0]

    df['Epoch'] = df['TIME (HH:MM::SS::NANOSECONDS) '].apply(to_unix_epoch, args=(tz, emulation_start_time))
    df['TIME'] = df['Epoch'] - emulation_start_time

    return df


def load_to_pandas(file_path): 
    file = open(file_path, "r")
    new_file = open("bla.csv", "w")
    
    for line in file:
        new_file.write(colocar_aspas(line))

    new_file.close()

    return pd.read_csv("bla.csv", skipinitialspace = True, quotechar="'")


def colocar_aspas(texto):
    """
    Coloca aspas nas strings de um texto ao encontrar o seguinte padrão:
    * Começa com "alert"
    * Termina com um ")"

    Args:
    texto: O texto a ser processado.

    Returns:
    O texto com as aspas nos locais corretos.
    """

    # Primeiro, encontramos todas as strings que começam com "alert".
    return re.sub(r"(alert\s+.*?\))", r"'\1'", texto)


def to_unix_epoch(time_str, timezone, emulation_start_time):
    """Converts a time string with nanoseconds and timezone to Unix epoch in UTC."""

    # using the datetime.fromtimestamp() function  
    dt_emulation_start_time = datetime.datetime.fromtimestamp( emulation_start_time )


    # Define the format of your datetime string
    datetime_format = "%Y/%m/%d-%H:%M:%S:%f"
    datetime_str_with_year = f"{dt_emulation_start_time.year}/{dt_emulation_start_time.month}/{dt_emulation_start_time.day}-{time_str[:-3]}"


    # datetime_format = "%H:%M:%S:%f"
    # datetime_str_with_year = f"{time_str[:-3]}"
    datetime_str_with_year=datetime_str_with_year.strip()

    # Parse the datetime string
    parsed_datetime = datetime.datetime.strptime(datetime_str_with_year, datetime_format)

    # Create a timezone object
    tz_info = datetime.timezone(datetime.timedelta(hours=int(timezone)))

    # Combine parsed time and timezone
    aware_time = parsed_datetime.replace(tzinfo=tz_info)

    # Convert to Unix epoch in UTC
    unix_epoch = aware_time.timestamp()

    return unix_epoch



if __name__ == "__main__":
    main()