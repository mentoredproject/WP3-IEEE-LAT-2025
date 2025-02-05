# Evaluating-robustness-and-reliability-of-a-C-NIDS-for-IoT-networks-in-virtualized-environments (IEEE Latin America Transactions - Submission ID: 9287)
Protecting thousands of smart devices across multiple IoT domains requires robust and collaborative security solutions, such as Collaborative Network Intrusion Detection Systems (C-NIDS). In this context, collaboration among NIDS improves intrusion detection by sharing information about local threats. However, most current solutions neglect the reliability and robustness assessment of these systems, especially when we consider C-NIDS. Thus, the lack of standardized and robust assessments to measure the reliability and accuracy of C-NIDS in attacks detection results in significant uncertainties regarding their ability to correctly identify threats. In this paper, we present an evaluation of a collaborative NIDS that integrates standalone NIDS to share information about detected and mitigated threats, improving overall intrusion detection. The evaluation took place in a virtualized IoT environment and results showed that collaborative NIDS detected DDoS attacks with an accuracy of at least 99.94%, a minimum recall of 99.94%, a precision of 100%, and F1 score of 1 in all evaluated scenarios. Those results highlight the development and adoption of uniform evaluation criteria to ensure the effectiveness and reliability of C-NIDS.

The paper associated with this work has been accepted for publication in IEEE Latin America Transactions (Submission ID: 9287).

This repository contains the emulation files and the necessary codes to process data from emulations performed on a virtualized environment.

## Contents

### Folder

`Deploy` : This folder contains Kubernetes manifests and the testbed Kubernetes configuration.

`Imagens` : This folder contains files responsible for creating Docker images.

`Scripts` : This folder contains multiple scripts responsible for collecting metrics and running the experiment.

`Volumes` : This folder is shared between the experiment and our system. It temporarily holds the output files from the emulation and stores data from real IoT devices, which are used by the emulated IoT devices to simulate real devices in the experiment.

### Files

`setup_environment.sh` : A Bash script that sets up the testbed environment and applies the IP pool and Felix configuration.

`Deploy/OVS/creating_network.sh` : This script sets up the network infrastructure between the pods.

`Deploy/OVS/config_network.sh` : This file defines the IP rules necessary to ensure proper communication between pods.

`Scripts/fase_04/batch.sh` : This script is responsible for running the emulation. It initializes the pods, stores the data in a temporary folder called "Volume/Output," and, once the emulation is complete, compresses the data into a .tar.gz file before moving it to "Emulation_Raw_Data."

`Scripts/fase_04/analysis.sh` :  This script calls multiple Python programs to compute metrics for each emulation present in the specified folder.

## How to Execute this code

### System Information

#### Hardware Used

Hard Drive Memory: 450 MB  
RAM: 32 GB  


#### Software Used

Operating System: Ubuntu 22.04.2 LTS               
Kernel: Linux 5.15.0-130-generic   
Docker: 24.0.2  
KIND: v0.17.0
kindest/node: v1.25.3 (modified)  
Go Version: go1.19.2
Kubectl: 1.27.2  
Python: 3.10.12

### Create Python Environment

Go inside the folder "Scripts/Python_Script" and execute

`python -m venv venv` or `python3 -m venv venv`

```
source venv/bin/activate
pip install -r requirements.txt
```

### Creating Kubernet Environment

To create the kubernet Environment it's need to do the following steps:
- Create Image
- Setup Environment
    - Create Environment
    - Isolate Environment
    - OVS Configuration

#### Creating Image

Go to the folder "Imagens", then read the README for the instructions to create the images

#### Setup the Environment

Inside the root folder of this repository execute the following commandas.

##### Create the Kubernet Environment
Execute the script located in the repository's root folder.

```
./setup_environment.sh
```
> Warning: This process will take approximately 1 hour.

##### Isolate the Environment

To isolate the environment from acessing the internet we need to know the ip address the kubernet create in the previus command use.


Exemple


```
$ kubectl get nodes -o wide
NAME                STATUS   ROLES           AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION      CONTAINER-RUNTIME
wp3-control-plane   Ready    control-plane   20d   v1.25.3   172.18.0.5    <none>        Ubuntu 22.04.1 LTS   5.15.0-73-generic   containerd://1.6.9
wp3-worker          Ready    <none>          20d   v1.25.3   172.18.0.2    <none>        Ubuntu 22.04.1 LTS   5.15.0-73-generic   containerd://1.6.9
wp3-worker2         Ready    <none>          20d   v1.25.3   172.18.0.3    <none>        Ubuntu 22.04.1 LTS   5.15.0-73-generic   containerd://1.6.9
wp3-worker3         Ready    <none>          20d   v1.25.3   172.18.0.4    <none>        Ubuntu 22.04.1 LTS   5.15.0-73-generic   containerd://1.6.9
wp3-worker4         Ready    <none>          20d   v1.25.3   172.18.0.6    <none>        Ubuntu 22.04.1 LTS   5.15.0-73-generic   containerd://1.6.9
```
Therefore in this case the environment uses 172.18.0.0 range, so when executing `sudo iptables -t nat -L POSTROUTING` we get a list of ip rules inclusive the one connecting the Testbed to the internet.

```
$ sudo iptables -t nat -L POSTROUTING

Chain POSTROUTING (policy ACCEPT)
target     prot opt    source        destination         
MASQUERADE  all  --  172.17.0.0/16    anywhere            
MASQUERADE  tcp  --  172.18.0.5       172.18.0.5    tcp dpt:6443
MASQUERADE  all  --  172.18.0.0/16    anywhere 
```

To remove the rule that connects the cluster to the Internet, it is necessary to identify its position and remove it by executing the command below. For example, the rule that connects the cluster to the Internet is located at position 3.

```
$ sudo iptables -t nat -D POSTROUTING 3
```

>Warning
>To execute the script ./setup_environment.sh, the cluster must have internet access. If the connection was removed using the previous steps, reconnect the environment by running the command below.
`$ sudo iptables -t nat -I POSTROUTING -s 172.18.0.1/16 -j MASQUERADE`


##### OVS Configuration
```
./Deploy/OVS/creating_network.sh
./Deploy/OVS/config_network.sh
```

### Executing the Environment


#### Run the experiments
```
sudo ./Scripts/fase_04/batch.sh <Number-of-Emulation>
# Exemple -> To run 35 emulations
sudo ./Scripts/fase_04/batch.sh 35
```

This will create a folder `Emulation_Raw_Data/<time_date>`, where each emulation will be save in a compact format inside.

#### Getting the metrics from the raw data

Create a new folder where the analysis will be saved.

```
mkdir Analysis
```

And execute the script to compute the metrics.

```
./Scripts/fase_04/analysis.sh <OUTPUT_DIR> <RAW_DATA_DIR>
# Exemple
./Scripts/fase_04/analysis.sh Analysis/ Emulation_Raw_Data/05022025_1742/
```
> Warning
> The first and second parameter need to end with '/'

## Contact

For questions, suggestions, or requests, please contact:

- Agnaldo Batista: [asbatista@inf.ufpr.br](mailto:asbatista@inf.ufpr.br)
