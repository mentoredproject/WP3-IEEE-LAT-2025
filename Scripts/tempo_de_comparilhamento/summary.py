import re
import pandas as pd
import datetime
import os

input_directory = "Tempo_de_compartilhamento/emulation"
output = "Tempo_de_compartilhamento/new_summary.csv"

def main():
    merged_df = pd.DataFrame()

    # Carrego todos os arquivos para um unico data frame
    for file in os.listdir(input_directory):
        file_path = os.path.join(input_directory, file)
        # checking if it is a file
        if not os.path.isfile(file_path):
            continue

        df = pd.read_csv(file_path)
        df = preenche_nan(df)
        merged_df = pd.concat([merged_df, df], ignore_index=True)
    
    summary_df = merged_df.groupby(['IP ORIGEM' ,'IP DESTINO', 'NETWORK', 'OPERATION', 'PROTOCOL', 'ID'],  as_index=False)['TIME'].mean()
    summary_df.sort_values('TIME', inplace=True)

    summary_df.to_csv(output, index=False)


def preenche_nan(df):
    """
    Preenche os valores NAN de um DataFrame pelos valores das células acima.

    Args:
    df: O DataFrame a ser preenchido.

    Returns:
    O DataFrame preenchido.
    """

    for i in range(len(df)):
        for j in range(len(df.columns)):
            if pd.isna(df.iloc[i, j]):
                df.iloc[i, j] = df.iloc[i - 1, j]
    return df


if __name__ == "__main__":
    main()