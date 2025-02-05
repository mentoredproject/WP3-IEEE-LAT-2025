import csv
import datetime
import argparse

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'tcp_loss.py',
    description= 'packet loss analysis (at the aplication level) for TCP communication beetween the servers',
    # End of help message
    epilog= '''
    ./tcp_loss.py -i <input-directory(Server dir)> -o <output-path-directory> -t <time-of-first-packets> 
    '''
    )
    # Directory with the csv files from the iot device
    parser.add_argument('-i', '--input', required=True, help= "directory where the output directories for each server are located") 

    # Output Directory
    parser.add_argument('-o', '--output', required=True, help= 'Output Directory')

    # Time of the first packet 
    parser.add_argument('-t', '--time', type= int, required=True, help= 'Time of the first packet send in the input directory')

    # Time of the first packet 
    parser.add_argument('-z', '--deltaFromBRT', type= int, required=False, help= 'Delta of Hours of hours from BRT (UTC=+3)',default=0)
    
    parser.add_argument('--window', required=True, type=int, nargs=2, help="Time window where the analysis will be made")
    
    # number of the network
    parser.add_argument('-n', '--number', type=int, required=False, help= 'Network number')
    
    return parser.parse_args()

def count_rows_in_time_range(file_name, start_time, end_time):
    row_count = 0

    with open(file_name, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row

        for row in reader:
            timestamp = datetime.datetime.strptime(row[1], '%H:%M:%S').time()

            if start_time <= end_time:
                if start_time <= timestamp <= end_time:
                    row_count += 1
            else:
                if start_time <= timestamp or timestamp <= end_time:
                    row_count += 1
    return row_count

args = argumentsParsing()

input_dir = f"{args.input}" 
output_dir = f"{args.output}"

dt1 = datetime.datetime.fromtimestamp(args.time+args.window[0]-(3600*args.deltaFromBRT))
dt2 = datetime.datetime.fromtimestamp(args.time+args.window[1]-(3600*args.deltaFromBRT))

start_time = dt1.time()
end_time = dt2.time()

# Map server numbers to their respective file types and communication counterparts
mode= [
    "active", 
    "passive"
]

action = [
    "Rcv", "Send"
]

server_ip = {
    1: "10.128.10.30",
    2: "10.128.20.30",
    3: "10.128.30.30",
    4: "10.128.40.30",
    5: "10.128.50.30",
}

# servers_count -> [serverA][serverB][action][mode]
servers_count = {}



print(start_time, end_time)

for serverA, ipA in server_ip.items():
    servers_count[serverA] = {}
    for act in action:
        servers_count[serverA][act] = {}
        for serverB, ipB in server_ip.items():
            if serverA==serverB:
                continue
            servers_count[serverA][act][serverB] = {}
            for m in mode:
                servers_count[serverA][act][serverB][m] = count_rows_in_time_range(f"{input_dir}/Server_0{serverA}/{m}{act}_{server_ip[serverB]}.csv", start_time, end_time)

# Aggregate send/receive totals for each server
totals = {}
for server in server_ip:
    print(f"Processing server: smd{server}")
    
    # Calculate total sends for the server
    totals[f"smd{server}snd"] = sum(
        servers_count[server]["Send"][serverB][m]
        for serverB in servers_count[server]["Send"]
        for m in servers_count[server]["Send"][serverB]
    )
    
    # Calculate total receives for the server
    totals[f"smd{server}rcv"] = sum(
        servers_count[server]["Rcv"][serverB][m]
        for serverB in servers_count[server]["Rcv"]
        for m in servers_count[server]["Rcv"][serverB]
    )

print(totals)

# Calculate total send, receive, and loss
total_snd = sum(totals[f"smd{server}snd"] for server in server_ip)
total_rcv = sum(totals[f"smd{server}rcv"] for server in server_ip)

if args.number:
    total_snd = totals[f"smd{args.number}snd"]
    total_rcv = totals[f"smd{args.number}rcv"]


qntloss = total_snd - total_rcv
loss_percent = (qntloss / total_snd * 100) if total_snd else 0

# Write results to the output file
with open(f"{output_dir}/tcp_loss_output.csv", "w") as file:
    file.write(f"totalSnd , {total_snd}\n")
    file.write(f"totalRcv , {total_rcv}\n")
    file.write(f"qntloss , {qntloss}\n")
    file.write(f"loss(%) , {loss_percent}%\n")

    if args.number:
        file.write(f"smd{args.number}snd , {totals[f'smd{args.number}snd']}\n")
        file.write(f"smd{args.number}rcv , {totals[f'smd{args.number}rcv']}\n")

        for serverB in server_ip:
            if args.number == serverB:
                continue
            for act in action:
                file.write(
                    f"smd{args.number}-{'rcv' if act == 'Rcv' else 'snd'}-smd{serverB} , "
                    f"{servers_count[args.number][act][serverB][mode[0]] + servers_count[args.number][act][serverB][mode[1]]}\n" 
                    )

    else:
        for server in server_ip:
            file.write(f"smd{server}snd , {totals[f'smd{server}snd']}\n")
            file.write(f"smd{server}rcv , {totals[f'smd{server}rcv']}\n")
            
        for server in server_ip:
            for serverB in server_ip:
                if server == serverB:
                    continue
                for act in action:
                    file.write(
                        f"smd{server}-{'rcv' if act == 'Rcv' else 'snd'}-smd{serverB} , "
                        f"{servers_count[server][act][serverB][mode[0]] + servers_count[server][act][serverB][mode[1]]}\n" 
                        )