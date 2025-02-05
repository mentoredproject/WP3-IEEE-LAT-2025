import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px


# df = pd.read_csv("Tempo_de_compartilhamento/new_summary.csv")

# print(df)


df = pd.DataFrame([
    dict(Start='1970-01-01 00:01:07', Finish='1970-01-01 00:01:23', Resource="network 1", Color="Send UDP Rule"),
    dict(Start='1970-01-01 00:04:11', Finish='1970-01-01 00:04:17', Resource="network 2", Color="Send UDP Rule"),
    dict(Start='1970-01-01 00:07:12', Finish='1970-01-01 00:07:18', Resource="network 3", Color="Send UDP Rule"),
    dict(Start='1970-01-01 00:10:12', Finish='1970-01-01 00:10:35', Resource="network 2", Color="Send ICMP Rule"),
    dict(Start='1970-01-01 00:14:12', Finish='1970-01-01 00:14:15', Resource="network 1", Color="Send ICMP Rule"),
    dict(Start='1970-01-01 00:18:13', Finish='1970-01-01 00:18:17', Resource="network 3", Color="Send ICMP Rule"),
 
])



fig = px.timeline(df, x_start="Start", x_end="Finish", y="Resource", color="Color"
                 )

# you can manually set the range as well
fig.update_layout(
                height=400,
                width=2500,
                xaxis=dict(
                    title='Time', 
                    tickformat = '%M:%S',
                    range = ['1970-01-01 00:00:00','1970-01-01 00:20:00'],
                    tick0 = '1970-01-01 00:01:00',
                    dtick = 60*1000 # Number of milliseconds in one minute

                ))

fig.show()