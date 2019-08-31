# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019

import nmap
import csv
import time

import PSCAD.lib.helpers.ip_utils as ip_utils
import PSCAD.lib.helpers.file_helper as file_helper

from datetime import timedelta
from PSCAD.lib.core.PDFWriter import *
from PSCAD.lib.helpers.colors import *
from PSCAD.lib.scanner.ScanComparator import ScanComparator


class Scanner:
    """Implementation of a nmap scanner and file exporter.

    This class is responsible for executing scans on any specified targets if possible, scanning for targets alive,
    ports, services, states and operating systems. It contains several pre-defined scan types and are gathered in
    the class variable SCAN_TYPES:
        TCP_CONNECT: For each target, execute a complete handshake between the two parts
        TCP_SYN: Sends a TCP-SYN and waits for a SYN-ACK as a response. Self responds with RST to close session.
        UDP: Sends an empty UDP Package for every port. An ICMP error will tell that port is closed, a "Destination
             unreachable" will tell that the ports is filtered. An UDP package will confirm that the port is open.
        FULL_UDP_TCP: Full TCP connection + UDP scan (TCP_CONNECT + UDP)
        FAST_UDP_TCP: TCP-SYN connection + UDP scan (TCP_SYN + UDP)
        SERVICES: Scan for service versions.
        NO_PING_SERVICES: Scan for service versions even without response from ICMP Ping.

    As the scan of a hole network could be really long, this class parses the specified targets into individual IPs
    and scans them one at a time, just for the purpose of presenting the information gradually. Ports are also parsed,
    just to obtain a list of all requested ports and know which ports need to be printed as closed (in case the user
    selects to print the closed ports). When the scan finishes, it creates a CSV file and exports them to the selected
    output directory with the desired name.

    Targets for scan can be specified manually (-t <targets>, from application parameters) or from an input file
    (-i <input_file(.txt | .csv)>, from application parameters). If the user selects an input file, the application
    behaviour differs depending on the extension:
        - TXT file: Read a single IP from each line.
        - CSV file: Expected file from previous step on the overall procedural application. Read IPs from the first
        column and store the rest of useful information, appending it to the output CSV as additional columns.

    User can request a scan difference (--diff <csv_file>, from application parameters), it uses
    the ScanComparator class to implement the logic for comparing two different scans: The one selected when using the
    --diff option, and the scan that is being executed.

        :param scan_type: Scan string representing the options to use.
        :param ports: Target ports
        :param output_directory: Output directory path
        :param output_file: Output file name.
        :param closed_ports: If True, print closed ports, if not, do not show them
        :param skip_os: If True, skip OS scan and set to 'Unknown'
        :param diff_file: CSV file for scan comparison.
        :param persistent: If True, keep scanning until user stops execution.
        :param output_pdf: If True, creates a PDF file with gathered information.
        :type scan_type: str
        :type ports: str
        :type output_directory: str
        :type output_file: str
        :type closed_ports: bool
        :type skip_os: bool
        :type diff_file: str
        :type persistent: bool
        :type output_pdf: bool

    Apart from class __init__ arguments, there are another attributes.
    Attributes:
        __previous_info: dict. Contains all the info gathered from the CSV input, if there is some.
        __add_preivous_info: bool. Flag attribute that is set to True if there was any information gathered
            from the input CSV (if there is one), False in any other case.
        __id: int. Current target ID, used to maintain ID even when __service_scan() ends.

    note::
        The purpose of this class is to scan hosts, so no IDS/IPS or firewall evasion is implemented, which
        translates in maximum speed on packed sending.

    see_also::
        lib.core.ip_utils to see IP related parsing.
        lib.core.ConfigurationLoader to see application parameters.
        lib.scanner.ScanComparator to see how scans are treated.

    """

    SCAN_TYPES = {
        'TCP_CONNECT': '-sT',
        'TCP_SYN': '-sS',
        'UDP': '-sU',
        'FULL_UDP_TCP': '-sT -sU',
        'FAST_UDP_TCP': '-sS -sU',
        'SERVICES': '-sV',
        'NO_PING_SERVICES': '-Pn -sV'
    }

    def __init__(self,
                 scan_type,
                 ports,
                 output_directory,
                 output_file,
                 closed_ports,
                 skip_os,
                 diff_file,
                 persistent,
                 output_pdf):
        try:
            self.__nmap_scanner = nmap.PortScanner()
        except nmap.PortScannerError:
            halt_fail("Nmap not found. Please install nmap on the system with \'apt-get install nmap\'")

        self.__scan_arguments = Scanner.SCAN_TYPES[scan_type]
        self.__ports = ports
        # Check for directory existence, and assign the directory to class attribute
        self.__output_directory = directory_helper.test_directory(output_directory)
        self.__output_file = output_file
        ip_utils.parse_ports_from_str(ports)
        self.__closed_ports = closed_ports
        self.__skip_os = skip_os
        self.__diff_file = diff_file
        self.__persistent = persistent
        self.__output_pdf = output_pdf

        # CSV Input information from previous step
        self.__previous_info = {}
        self.__add_previous_info = False

        # ID attribute
        self.__id = 1

    @property
    def nmap_scanner(self):
        return self.__nmap_scanner

    @property
    def ports(self):
        return self.__ports

    @property
    def scan_arguments(self):
        return self.__scan_arguments

    @property
    def output_directory(self):
        return self.__output_directory

    @property
    def output_file(self):
        return self.__output_file

    @property
    def closed_ports(self):
        return self.__closed_ports

    @property
    def skip_os(self):
        return self.__skip_os

    @property
    def diff_file(self):
        return self.__diff_file

    @property
    def output_pdf(self):
        return self.__output_pdf

    def init_from_file(self, input_file):
        """ Reads an input file searching for all the targets inside it. It then
            starts the scan for those targets.

            If the given file is a CSV file, it extracts all the IPs from each row, that are supposed
            to be on the first column. This file is received from the previous tool of the procedural
            security application. It also extracts the MAC address, hostname, processor, RAM and disk capacity from
            each target, stores them and sets the attribute flat __add_previous_info to True, so the output CSV from
            performing the scan will also have that information appended.
            A TXT file can also be selected, in which each IP must be on an individual line.
        
            :param input_file: initial .csv file to read the targets
            :type input_file: String
        """

        # Input file checks
        if file_helper.check_file_existence(input_file):
            print_success("Valid input file: {}".format(input_file))
        else:
            halt_fail("Could not find given file: {}. Exiting...".format(input_file))

        print_warning("Extracting targets from file.")
        # If input file is a CSV
        if '.csv' in input_file:
            # Read and parse de file
            with open(input_file) as targets_file:
                csv_reader = list(csv.reader(targets_file, delimiter=','))
                # Targets are the first column of each line. Store them and delete duplicates
                targets_list = list(set([row[0] for row in csv_reader]))

                # If no targets found, show error
                if not len(targets_list):
                    halt_fail("Could not extract targets from CSV file."
                              "Please make sure that the IP Addresses are on the first field of every line. Exiting...")

                mac_addr = None
                hostname = None
                processor = None
                ram = None
                disk_capacity = None
                # For each target
                for target in targets_list:
                    try:
                        # Get the first line where the target appears
                        target_csv_row = [x for x in csv_reader if x[0] == target][0]
                        # Get target information from the respective column.
                        mac_addr, hostname, processor, ram, disk_capacity = (target_csv_row[1],
                                                                             target_csv_row[2], target_csv_row[4],
                                                                             target_csv_row[5], target_csv_row[6])
                    except IndexError:
                        # If index error, information is missing.
                        halt_fail('Input CSV does not have the expected fields.')

                    # Add information from previous target
                    self.__previous_info[target] = [mac_addr, hostname, processor, ram, disk_capacity]
                # Set flag to True, so the Scanner knows he has to append additional information
                self.__add_previous_info = True

        # iF .txt file
        elif '.txt' in input_file:
            with open(input_file) as targets_file:
                targets_list = [x.strip() for x in targets_file.readlines()]

                # If no targets found, show error
                if not len(targets_list):
                    halt_fail("Could not extract targets from files. "
                              "Please specify all the IP Addresses on separate lines. Exiting...")

        # In any other case...
        else:
            # Assign targets_list to None, to avoid non declared variable when calling __perform_Scan
            targets_list = None
            halt_fail('Unsupported file extension on {}'.format(input_file))

        print_success("Targets parsing finished successfully.")

        # Start performing the scan
        self.__perform_scan(targets_list)

    def init_from_targets(self, targets):
        """ Parsed the targets string and inits the scan.

            :param targets: Targets string to be parsed
            :type targets: str
        """
        # Parse specified targets
        targets_list = ip_utils.parse_targets(targets)

        # If no targets on list, show error
        if not len(targets_list):
            halt_fail("Could not parse any targets. "
                      "Please specify all the IP addresses correctly. Exiting...")

        print_success("Targets parsing finished successfully.")

        # Start performing the scan
        self.__perform_scan(targets_list)

    @staticmethod
    def append_closed_ports(port_list):
        """ Having a list of open/filtered ports, it creates a list with the rest of non responding ports
        from 0 to 65535, directly classifying them as closed ports.

            :param port_list: List of open/filtered ports
            :type port_list: list
            :return: List with all supposed closed ports
            :rtype: list
        """
        closed_ports = []
        all_ports = range(1, 65536)
        for port in all_ports:
            if port not in port_list:
                closed_ports.append(port)

        return closed_ports

    def __build_file_name(self):
        """Builds the output file depending on the output directory and desired file name, appending the current
        date time and ending the file with the '.csv' extension if it does not have it.
        """

        file_base_name = self.output_file
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Remove extension, if it exists
        if '.' in file_base_name:
            file_base_name = re.sub('\..*', '', self.output_file)

        # Output directory/filename_datetime.csv
        return directory_helper.process_directory(self.output_directory) + '/' + file_base_name + '_' + \
               current_datetime + '.csv'

    def __os_scan(self, target):
        """Perform an OS scan for a single target. The nmap --oscan-guess option is used, to ensure at least
        one Operating System. All the OS matching the current target will be printed to terminal, from the most
        accurate to the least one. The only OS returning will be the most accurate one, which is the first
        OS from the python-nmap resulting list.

            :param target: IP address of the target
            :type target: str
            :return: OS name
            :return: 'Unknown' for skipped or failed scan
            :rtype: str
        """

        # OS scan arguments: Operating system scan, at max speed, no hostname resolution and with OS guessing.
        os_scan_arguments = '-O --osscan-guess -T4 -n'
        # If user selected NO_PING_SERVICES, add -Pn option to OS Scan.
        if '-Pn' in self.scan_arguments:
            os_scan_arguments += ' -Pn'

        # Attempt OS scan
        try:
            self.nmap_scanner.scan(target, arguments=os_scan_arguments)
        except nmap.PortScannerError as e:
            halt_fail('Unknown error when scanning OS: {}'.format(e))

        # If no key is found, the scan was not successful
        try:
            self.nmap_scanner[target]
        except KeyError:
            print('[{0}] OS: Unknown'.format(target))
            return 'Unknown'

        target_os = "Unknown"

        # If there are OS matches
        if len(self.nmap_scanner[target]['osmatch']):
            # Get the first one, which is the most accurate.
            target_os = self.nmap_scanner[target]['osmatch'][0]['name']
            # Print every OS match with the corresponding accuracy
            for os_match in self.nmap_scanner[target]['osmatch']:
                print("[{0}] OS: {1: <25}\n{3:<{4}}Accuracy: {2}%".format(target, os_match['name'],
                                                                          os_match['accuracy'], ' ', len(target) + 3))
        else:
            print('[{0}] OS: Unknown.'.format(target))

        # Returns 'Unknown' if there was no OS match although the target was scanned, and the most accurate OS
        # in any other case.
        return target_os

    def __compare_scans(self, starting_time, current_scan_results):
        """Creates a log file containing all the differences from a previous scan, based on the current
        scan and a previous .csv file.

        If the given file is not a CSV file, the function stops. If the file is a .csv file, it then
        creates a log file where the differences are going to be stored and a ScanComparator object is built from
        both current and previous scan information. Thanks to that comparator, several factors are analyzed
        and written in case of an anomaly. Anomalies are classified in:

        - IPs not existing in both scans. A description for the missing IP will be writen, depending
        on the scan that it is missing.
        - Ports difference betweeen both scans. If the port is closed in one scan, but it does not appear
        in the other one, it is not considered an anomaly, as one scan could have used the --closed-ports
        argument, which means that it is normal if it doesnt show in the other one (that could have executed without
        that option). If the same port exists on both scans and the state of the ports has changed, it is also
        exported to the log file.

            :param starting_time: Time on which the current scan has started.
            :param current_scan_results: List of lists containing all the information for the current scan
            :type starting_time: float
            :type current_scan_results: list

        see_also::
            lib.scanner.Scanner.ScanComparator
        """

        # If file is not CSV, print and error message and exit function.
        if '.csv' not in self.diff_file:
            print_fail("Could not perform scan differentiation, the given file is not a CSV."
                       "Please specify a previous CSV scan file.")
            return

        # Build the file name, stored on selected output directory, with the name
        # diff_<starting_time>.log
        log_file_name = self.output_directory + '/' + 'diff_' + str(starting_time) + '.log'
        # Open the file selected to calculate de differences.
        with open(self.diff_file, 'r') as previous_scan:
            # Store CSV file parsing
            previous_scan_results = csv.reader(previous_scan)
            # Open the output log file
            with open(log_file_name, 'w') as log_file:
                # Add informative comments
                log_file.write("# An empty log file means two identical scans #\r\n")
                log_file.write("# Targets differences #\r\n")

                # Instantiate the ScanComparator object with both parameters
                # The first is a list containing all CSV rows, and the second is a list containing
                # all the current scan CSV rows.
                comparator = ScanComparator([x for x in previous_scan_results], current_scan_results)
                # For each IP that was not found on the previous scan, write a line on log file.
                for previously_non_scanned_ip in comparator.get_previously_non_scanned_ips():
                    log_file.write("{} was not scanned previously.\r\n".format(previously_non_scanned_ip))
                # For each IP that was not found on the current scan, write a line on log file.
                for currently_non_scanned_ip in comparator.get_currently_non_scanned_ips():
                    log_file.write("{} was not scanned in the latest scan.\r\n".format(currently_non_scanned_ip))

                # Add blank line and informative comment
                log_file.write("\r\n")
                log_file.write("# Ports differences #\r\n")

                # For each IP found on both scans
                for single_ip in comparator.get_common_ips():
                    # Get their profiles
                    previous_profile, current_profile = comparator.get_both_ip_profiles(single_ip)
                    # For each scanned port with its state on the previous scan
                    for port_proto, state in previous_profile.items():
                        # If that port is not on current scan and his state is not 'closed'. State has changed.
                        if port_proto not in current_profile and state != "closed":
                            # Output to log
                            log_file.write("{}: Port {} was not scanned in the latest scan and had a \'{}\' state.\r\n"
                                           .format(single_ip, port_proto, state))
                        # If that port was scanned both times but has different state
                        elif port_proto in current_profile and state != current_profile[port_proto]:
                            # Output to log
                            log_file.write("{}: Port {} changed his state from {} to {}\r\n"
                                           .format(single_ip, port_proto, state, current_profile[port_proto]))

                    # For each scanned port with its state on current scan
                    for port_proto, state in current_profile.items():
                        # if that port is not on the previous scan and his state is not 'closed'. State has changed.
                        if port_proto not in previous_profile and state != "closed":
                            log_file.write("{}: Port {} was not previously scanned and has a {} state.\r\n"
                                           .format(single_ip, port_proto, state))

        print_success("Finished creating diff log file at {}".format(log_file_name))

    def __service_scan(self, target):
        """ Scan the selected ports from the selected targets, either from a string or an input file. First of all,
        depending on the scan parameters, it performs a specific nmap scan. After that, an OS scan is done if not
        skipped by the user. Every result will be writen to an output .CSV file and also stored in a variable.

        The resulting .CSV file will have the following structure, optional output between parenthesis, depending
        on targets being specified by a CSV input file or not:

        ID,IP,Port,Service,Status,Version,OS(,MAC,hostname,processor,RAM,disk)

            :param target: Target to scan
            :type target: str
            :return: Nothing if scan could not be performed
            :return: List of CSV rows to write
            :rtype: None, list
        """

        # Arguments sentence formation: scan type + ports + max. speed + do not resolve hostname
        scan_sentence = self.__scan_arguments + ' -p' + self.__ports + ' -T4 -n'
        # Every single port scan list
        current_target_scan = []

        # OS Scan
        target_os = 'Unknown'
        if not self.__skip_os:
            target_os = self.__os_scan(target)

        # Attempt service scan
        try:
            self.nmap_scanner.scan(target, arguments=scan_sentence)
        except nmap.PortScannerError as nmap_error:
            print_fail("Could not scan target host. Unknown error: %s." % nmap_error)
            return

        # If no key is found, the service scan was not successful
        try:
            self.nmap_scanner[target]
        except KeyError:
            print_warning("Could not scan services from host %s. Host might be down "
                          "or blocking the scan. Jumping to the next target" % target)
            return

        # If not length on protocols, scan did not find anything
        if not len(self.nmap_scanner[target].all_protocols()):
            # CSV row for target is the current ID, the target, and 4 Unknown for the port, state, service and
            # version. Add OS and information from input CSV if there is one.
            row = [str(self.__id),
                   target,
                   'Unknown',
                   'Unknown',
                   'Unknown',
                   'Unknown',
                   target_os]
            # If information to be added
            if self.__add_previous_info:
                try:
                    # Extend the row list to add CSV input additional info
                    row.extend(self.__previous_info[target])
                except KeyError:
                    # If no information for that target was stored, pass and write the row
                    pass
                # Append row to the list containing all results
                current_target_scan.append(row)
                self.__id += 1

        # in any other case, iterate through all ports for each protocol.
        else:
            # For each protocol scanned for a given host
            for proto in self.nmap_scanner[target].all_protocols():
                # Store port list in ascending order
                port_list = sorted(self.nmap_scanner[target][proto])
                # For each port scanned for that target
                for port in port_list:
                    # Get port state
                    state = self.nmap_scanner[target][proto][port]['state']
                    # Get service running on that port
                    service = self.nmap_scanner[target][proto][port]['name']
                    # Get Service information, which is the product + the version + the extrainfo,
                    # Delete side black spaces and change commas for spaces to avoid CSV misinterpretation.
                    version_info = ' '.join([self.nmap_scanner[target][proto][port]['product'].replace(',', ' '),
                                             self.nmap_scanner[target][proto][port]['version'].replace(',', ' '),
                                             self.nmap_scanner[target][proto][port]['extrainfo'].replace(',', ' ')
                                             ]).strip()
                    print("[{0}] Port: {1: <8}State: {2: <11}Service: {3}\n{5:<{6}}Version info: {4}"
                          .format(target, port, state, service, version_info, ' ', len(target) + 3))
                    # Build the CSV file line.
                    row = [str(self.__id), target, str(port) + '/' + proto,
                           state, service, version_info, target_os]

                    # If __add_previous_info flag is set, add previous CSV info to current output
                    if self.__add_previous_info:
                        try:
                            # Extend the row list to add CSV input additional info
                            row.extend(self.__previous_info[target])
                        except KeyError:
                            # If KeyError, no previous information. Do nothing
                            pass

                    # Append row to the list containing all results
                    current_target_scan.append(row)

                    # Increment ID
                    self.__id += 1

                # Append closed ports if specified
                if self.__closed_ports:
                    # Get closed ports, which are ports that where not specified
                    closed_port_current_proto = Scanner.append_closed_ports(port_list)
                    # For each closed port
                    for closed_port in closed_port_current_proto:
                        # Append closed port with Unknown state, service and service info
                        row = [str(self.__id), target, str(closed_port) + '/' + proto,
                               'closed', 'Unknown', 'Unknown', target_os]

                        # If __add_previous_info flag is set, add previous CSV info to current output
                        if self.__add_previous_info:
                            try:
                                # Extends row with previous information
                                row.extend(self.__previous_info[target])
                            except KeyError:
                                # If KeyError, no previous information. Do nothing
                                pass

                        # Append row to the list containing all results
                        current_target_scan.append(row)

                        # Increment ID
                        self.__id += 1

        return current_target_scan

    def __perform_scan(self, targets):
        """ Executes the main Scanner routine for a number of given targets previously parsed from a manual input,
         a .txt file or a .csv file by calling the rest of the class methods and exporting all the information
        to the convenient files.

            :param targets: List of targets to scan
            :type targets: list
        """
        # Print scanner information and warnings.
        print_success("Starting scanner at {} for {} hosts"
                      .format(datetime.now().strftime("%Y-%m-%d_%H:%M:%S"), len(targets)))
        if '-Pn' in self.scan_arguments:
            print_warning("\'No ping\' option was selected. "
                          "Scanning with this option might take a lot longer than normal.")

        # List containing every single port scan
        all_scan_results = []
        # Starting time
        starting_time = time.time()

        # Open the output file
        full_file_name = self.__build_file_name()
        print_warning("Creating output file \'{}\'".format(full_file_name))
        file_creating = None
        try:
            file_creating = open(full_file_name, 'w')
        except (IOError, EnvironmentError) as e:
            halt_fail('Could not create output file: {}'.format(e))
        finally:
            file_creating.close()

        # Loop through targets
        for target in targets:

            # Store scan results
            target_results = self.__service_scan(target)
            # Add those results to all_scan_results
            if target_results is not None:
                all_scan_results.extend(target_results)

            # Open the file and write the changes. Close file when done for that target.
            # Use 'a' file mode, file is already created, information just needs to be added gradually.
            if target_results is not None:
                with open(full_file_name, 'a') as output_csv:
                    # Instantiate CSV writer
                    output_writer = csv.writer(output_csv, delimiter=',')

                    # Write every result
                    output_writer.writerows(target_results)

        # Compare file for existing port list if --diff option was used
        if self.__diff_file is not None:
            self.__compare_scans(starting_time, all_scan_results)

        # Loop and replace lines in output file in case of --persistent.
        if self.__persistent:

            # IP Sorting lambda function
            def ip_sorting():
                return lambda line: int(''.join(["%02X" % int(octet) for octet in line[1].split('.')]), 16)

            # Sleep 4 seconds and notificate user.
            print_warning('Reached persistent mode. Next iteration will start in 4 seconds')
            time.sleep(4)

            while True:
                # Close all the persistent code in a try-except to capture the KeyboardInterrupt (Ctrl + C)
                try:
                    # For every target, again
                    for target in targets:

                        # Store target results
                        target_results = self.__service_scan(target)

                        print_warning('Updating information from {}'.format(target))

                        # Build a list with all indexes where the current target appears.
                        indexes = [index for index in range(len(all_scan_results))
                                   if all_scan_results[index][1] == target]

                        # Delete every entry from all_scan_results that are related to the last target.
                        # Reverse de list of indexes to avoid KeyError for out of range.
                        indexes.sort(reverse=True)
                        for i in indexes:
                            del all_scan_results[i]

                        # If there is a scan result, append it to all results.
                        if target_results is not None:
                            all_scan_results.extend(target_results)

                        # Sort scan results by IP address to re-structure the file
                        all_scan_results.sort(key=ip_sorting())

                        # Open file in W mode, and re-write the content
                        # Notice that the csv module is not used in this case, it is easier
                        # to build the information manually than using the csv module
                        with open(full_file_name, 'w') as output_file:
                            current_id = 1
                            # Re write the file and build each line index to match the line number.
                            for l in all_scan_results:
                                output_file.write(str(current_id) + ',' + ','.join(l[1:]) + '\r\n')
                                current_id += 1

                    # Compare file for existing port list if --diff option was used
                    # Create a diff line for every complete iteration
                    if self.diff_file is not None:
                        self.__compare_scans(starting_time, all_scan_results)

                except KeyboardInterrupt:
                    print_fail('User stopped persistent execution.')
                    # Break infinite loop
                    break

        # If --output-pdf was specified
        if self.__output_pdf:
            print_warning('Generating PDF file...')
            if self.closed_ports:
                print_warning('WARNING: Appending closed ports will make this process much slower.')
            # Instantiate the PDFWriter, telling to write the document in spanish and use the attribute
            # self.output_directory as the exportation directory for the PDF file
            writer = PDFWriter(lang='esp', output_directory=self.output_directory)
            # Get all targets scanned, without duplicates
            targets_list = list(set([row[1] for row in all_scan_results]))
            # For each unique target
            for target in targets_list:
                # Get rows related to that target
                target_rows = [row for row in all_scan_results if row[1] == target]
                # For each single host, there is a table (dynamic info) with some previous data (static info)
                # in the exported PDF.
                # Set target IP and OS as static information, with the title to be shown in the document
                # Set a list of lists as list of rows for the table, that will have the ID, port, state,
                # service and version
                # Pass the table headers
                # Pass the column widths, values are converted to centimetres
                writer.append_info(
                    {'Direccion IP': target_rows[0][1], 'Sistema Operativo': target_rows[0][6]},
                    [[x[0], x[2], x[3], x[4], x[5]] for x in target_rows],
                    ['ID', 'Puerto', 'Estado', 'Servicio', 'Version'],
                    [2, 2.5, 1.8, 3, 4]
                )
            # Write the document
            writer.write_document()

        # Execution time
        exec_time = time.time() - starting_time
        print_success("Scan completed successfully. Time: {}".format(timedelta(seconds=int(exec_time))))
        print_success("Output exported to {}".format(full_file_name))
