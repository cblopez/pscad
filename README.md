# PSCAD*  
### \*Python Services Checker & Anomaly Detector
##### Created by Christian Barral Lopez, May 2019  

  This application is the second of the four modules that build ISAT(Internal Security Audit Toolkit).
   A tool created in Python 3, executable within every Linux Operating System divided into two modules: 
   The **scanner** module, which focuses on services and OS recognition, and the **sniffer** module, 
   aimed to capture network packets thanks to a MITM (Man In The Middle) technique.  
  
## Installation

   #####**Keep in mind! You need to have nmap installed before using this application. You can find how [here](https://nmap.org/download.html).**

   ### Automatic installation  
   For using the application, you will need Python 3.3+ and the package manager, pip.  
   **Run `sudo pip install pscad`** and you should be able to execute `pscad --help` on your terminal
   without using the `python` keyword.
   
   ### Manual installation
   
   #### setup.py  
   Download the application code and go to the root directory of the project. Then execute `sudo python setup.py install`.
   
  
   #### Old school  
     
   There's an `install.sh` file that comes with the project, you can find it in the root directory. Move there 
   and execute `sudo ./install.sh`.  
     
     
   If all of these three methods fail. Please install the requirements manually
   - Nmap: Install it with your OS package manager (`sudo yum install nmap`, `sudo pacman -S nmap`, ...)
   - netifaces: Install it with pip: `pip install netifaces`
   - reportlab: Install it with pip: `pip install reportlab`
   - scapy: Install it with pip: `pip install scapy`
   - configparser: Install it with pip: `pip install configparser`
   - python-nmap: Install it with pip: `pip install python-nmap`  
   ##### Keep in mind: If you install by 'Old school' you'll need to execute `python pscad.py` on the PSCAD directory to make it work.
  
## Launch the application  
The application is launched by the `pscad` command. Two sub-commands are avaliable to use: `scan` 
and `sniff`.  
To display the commands and a brief description, execute `pscad -h` or `pscad --help`.

### Scan  
PSCAD's scanner uses the nmap application behind the scenes, but it offers a new abstraction level to configure standard nmap scans 
a bit easier and adds some new options for CSV and PDF exportation, as well as scan comparison and persistent scanning features.  
You can execute `pscad scan --help` to display the options.  

**Mandatory options  (choose one)**  

| Option | Description |  
|--------|:---------|
| -t  |  Specify targets IP addresses. See help menu for examples.  |  
| -i  |  Specify a .txt file to read one IP per line. |  
  
**Optional arguments**  
  
| Option | Description |  
|--------|:---------|
| -p  |  Specify the ports to scan. See help menu for examples.  |  
| -o  |  Select path to export all the generated files. |  
| -n  |  Write a base name for the CSV file. |  
| --type  |  Choose scan type. See help menu for more documentation. |  
| --closed-ports  | Export closed ports information to CSV file. |  
| --skip-os  | Do not scan OS. |  
| --diff DIFF_FILE  | Select a previously created CSV file to compare those results with the scan to be performed. |  
| --output-pdf  | Create a PDF file containing the scan information. |  
  
When the `scan` is executed, it will scan ports from 1 to 1024 and the Operating System for the selected hosts. All 
the optional arguments are explained on the application's `--help` menu.  
##### PDF File  
The **PDF file** is filled with the information found under the config/ directory. The **pdf.ini** has the text that will be written
to it and it is completely customizable. The file assets/logo.jpg is the image used to generate the PDF cover. **If you would like to change that image, override
the file with your own, but it has to be named "logo.jpg"**.  

##### Command examples  
- `pscad scan -t 192.168.1.0/24 -p 21,22,53 --type NO_PING_SERVICES --output-pdf -o /tmp -n example`: Scan the hole 192.168.1.0 network,
looking for ports 21,22 and 53 and export the CSV file to /tmp with "example" as base name. Use a non-ICMP scan (force scan). Then, generate
a PDF file with the results.  
- `pscad scan -i targets.txt --closed-ports -n another_example --diff /tmp/previous_scan.csv --persistent`: Scan the targets inside the "targets.txt" file,
scan default ports (1-1024) and export closed ports information, with "another_example" as base name. Keep running until user interruption 
and for each scan, create a .log file with the differences between the one being executed and the previous_scan.csv.  

#### Sniff  
The PSCAD's sniffer uses ARP Poisoning to capture data from any host on the network and analyze packets based on a previous 
 scan. You can execute `pscad sniff --help` to display the options. *Warning: Using the sniffer may cause network issues due to the ARP Poisoning performed. It is the user's responsibility
to use it properly,*

**Positional arguments**  

| Option | Description |  
|--------|:---------|
| interface  |  Name of the network interface to be used.  |  
| gateway |  IP address of the network's gateway. |  

**Mandatory options  (choose one)**  

| Option | Description |  
|--------|:---------|
| -t, --target |  Specify the targets IP addresses. See help menu for examples.  |  
| -l, --localnet  | Poison the hole network. Uses GARP (read below). |  
| -r, --randomize | Specify a number of random objectives to poison. The sniffer will poison the first N targets that respond to ARP. |  
  
**Optional arguments**  
  
| Option | Description |  
|--------|:---------|
| -o |  Select path to export all the generated files. |  
| -n |  Write a base name for the .pcap file. |  
| -i | Select a CSV file generated by the scan and use it to generate a network profile for packet analyzing. |  
| -f, --filter | Apply a BPF filter. |  
| --timeout  | Select a number of seconds to sniff. |  
| --packet-count | Set a packet limit to capture. |  
| --type  | Select the type of G-ARP to use on --localnet sniffing. | 
| -v, --verbose  | Level of verbosity. From 0 to 3. | 

##### G-ARP (Gratuitous ARP): One packet, hole network.  
As said in the `sniff` mandatory options, the `l, --localnet` poison uses a packet called G-ARP. This type of packet is used
to force ARP tables to update, but it may cause the network hosts to disconnect from the internet for a short time. See [RFC 5227](https://tools.ietf.org/html/rfc5227) 
for more information. The `--type` option is used to select which type of ARP packets are going to be used. Normally, GARP should be "who-is" type, but
due to wrong OS implementations, some hosts may respond to "is-at" instead.

##### Command examples  
- `pscad sniff -t 192.168.1.2-192.168.1.5 -o /tmp -n example --packet-count 4000 eth0 192.168.1.1`: Poison targets from 192.168.1.2 to 
192.168.1.5, export the .pcap file to /tmp with 'example' as base name. After counting 4000 packets, stop. Use the eth0 interface
and know that 192.168.1.1 is the gateway.
- `pscad sniff -l --type 3 -i /tmp/previous_scan.csv -f tcp --timeout 300 wlan0 10.10.10.1`: Poison the hole network and use both "who-is" and "is-at" ARP packets. Use 
the previous_scan.csv file to analyze captured packets and export that information to a .log file. Only capture packets for 5 minutes and
just those which have the TCP protocol.

## Troubleshooting  
- **The application says that a directory X is not valid**: Make sure, if your are
 accessing a directory from the current execution path, that the directory starts with "./", like "./X".
- **The scanner does not show any result in the outputted CSV**: The scanner only
writes in the CSV file when the host responded but had no opened ports or there
were some opened ports. If the target could not be scanned, that target will not
appear in the output CSV file.
- **The scanner does not show opened top ports, but they really are**: The scanner does not
scan top ports by default, but well-known ports (1-1024). Use the `-p` parameter to specify
another port range. 
- **Using the** `--output-pdf` **option takes too long**: If it's taking too long,
make sure you do not use the `--closed-ports` parameter, it may cause serious delays
when passing that information to the PDF file.
- **The sniffer does not capture the specified hosts' packets**: Make sure the network
uses dynamic ARP and an ARP Proxy is not configured.  
- **The .log file generated by the** `-i` **parameter from the sniffer shows weird characters
when reading it from the terminal**: Expand your terminal to full screen and that will fix it.