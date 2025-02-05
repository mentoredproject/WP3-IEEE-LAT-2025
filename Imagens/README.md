## Content
Each directory presents in this folder correspond to a image, therefore to create the images used in this experiment is need to go inside each folder to execute the command to create the image.

#### BoNeSi DDoS
Inside the folder "DDOS-Bonesi_custom" execute the command:
docker build -t bonesi:wp3.v2 .

#### Snort
Inside the folder "snort" execute the command:
docker build -t snort:wp3.v5

#### Server Monitor Data
Inside the folder "SMD" execute the command:
docker build -t smd-metrica:wp3.v5

#### IoT Device
Inside the folder "txtdisp" execute the command:
docker build -t iot:wp3.v2

#### Kind-CNI
Inside the folder "kind_cni" execute the command:
docker build -t kind-cni:wp3.v1 .
