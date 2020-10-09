# Passive Attack on a Security Camera

Final project in the course "Protection of wireless and mobile networks" at Ariel University 2020.

A Passive Attack tool that intercepts packets from a Security Camera, retrieves JPEG images and saves them.


**Created by:**

[Odelia Hochman](https://github.com/OdeliaHochman)

[Efrat Cohen](https://github.com/EfratCohen100)

[Max Marmer](https://github.com/MarmerMax)


## Working Environment:
The code was written in python 3.6.8 in Linux operating system.

## Requirements:
* Wifi Adapter Card supports the Linux operating system.
* Security Camera
* Python Libraries - aircrcak-ng, scapy


## Run the code:
* clone this project
* `sudo su`
* `python3 project.py`

## Attack Stages:
1. Turning a Wifi Adapter Card into a monitor mode
2. Scanning networks and selecting the device we want to attack (in this case the Security Camera)
3. Perform sniffing and retrieving all packages of this device
4. Decoding information of the packages
5. Receiving the JPEG Images



![image](https://user-images.githubusercontent.com/45036697/95592159-ede80780-0a50-11eb-9582-ecb65687a127.png)

