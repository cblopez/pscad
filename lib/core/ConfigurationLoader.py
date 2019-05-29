# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019

import argparse
import pip
import subprocess

from lib.helpers.colors import *
from distutils import spawn

# Warning: Using a protected method.
from pip._internal.utils.misc import get_installed_distributions as get_pip_installations


class Singleton:
    """ This is a Singleton definer class meant to be used as a decorator.

    The decorated class will be able to define an __init__ function taking
    self as a unique parameter. Please note that the decorated class cannot be inherited.

    Getting a singleton instance can only be done by calling the get_instance()
    method. Using the __call__ method will raise a TypeError, which is one of the
    Singleton pattern restrictions.

    The decorated class attributes are defined in this class, as the
    decorated class will be filled with this decorator class information;

    - PIP_UTILS is the list that contains de non-vanilla python modules needed.
    - OS_UTILS is the list that contains the system applications needed.
    """

    # List of expected utils to be in the system
    PIP_UTILS = ['python-nmap', 'scapy', 'reportlab', 'netifaces', 'configparser']
    OS_UTILS = ['nmap']

    def __init__(self, decorated):
        self.__decorated = decorated

    def get_instance(self):
        """ Returns a decorated class instance: ConfigurationLoader

            :returns: ConfigurationLoader instance
            :rtype: ConfigurationLoader
        """
        try:
            return self.__instance
        # If no instance attribute found, return a new instance and save it.
        except AttributeError:
            self.__instance = self.__decorated()
            return self.__instance

    def __call__(self):
        raise TypeError('The ConfigurationLoader instance must be accessed by the get_instance() method.')


@Singleton
class ConfigurationLoader:
    """This class contains the application parameter's options and behaviour.

    It implements a Singleton. Only one instance of this class will ever be needed
    when the application is running. Used by pscad.py to manage all the
    important application arguments and workflow.
    """

    def __init__(self):
        # No __init__ from this class is used. From Singleton instead.
        pass

    def parse_arguments(self):
        """This method uses the argparser to define, identify and assign values depending on the
        script launching parameters. Arguments are defined in a specific order: 
            1) Top level parser.
            2) Subparsers creation.
            3) Mutual exclusive arguments.
            4) Required arguments.
            5) Optional arguments

            :returns: argparse Object that contains the parameters values
            :rtype: argparse.Namespace
        """

        # Top level parser
        reader = argparse.ArgumentParser(description="PSCAD.")

        subparsers = reader.add_subparsers(title='Main commands',
                                           description='These are the valid commands.',
                                           help='Please specify one of these commands',
                                           dest='command')

        # scan parser
        scan_parser = subparsers.add_parser('scan',
                                            help='Perform a network scan. Check \'python pscad.py scan '
                                                 '--help\' for more details',
                                            formatter_class=argparse.RawTextHelpFormatter)
        # scan parser mutual exclusive arguments
        descripted_group = scan_parser.add_argument_group('required arguments (choose one)')
        scan_group = descripted_group.add_mutually_exclusive_group(required=True)
        # scan parser mandatory arguments
        scan_group.add_argument("-i",
                                dest="scan_input_file",
                                required=False,
                                help="Read the IP addresses from the given file. Each IP on a separate line. It also"
                                     " accepts a CSV file produced by first ISAT module.")
        scan_group.add_argument("-t",
                                dest="scan_targets",
                                required=False,
                                help="Specify the target(s) IP addresses or range. Can be separated by commas. "
                                     "Ex: 192.168.1.1 or 192.168.1.0/24 or 192.168.1.1-102.168.1.5 or 127.0.0.1,"
                                     "192.168.1.1")

        # scan parser arguments
        scan_parser.add_argument("-p",
                                 dest="ports",
                                 required=False,
                                 help="Specify the port(s) range to scan separated with commas and ranging with '-'."
                                      "Ex: 80,443 or 100-200 or 80,443,100-200. Default: 1-1024",
                                 default="1-1024")
        scan_parser.add_argument("-o",
                                 dest="output_directory",
                                 required=False,
                                 help="Specify the output directory for file storing. Ex: /home/tmp/ Default: ./",
                                 default="./")
        scan_parser.add_argument("-n",
                                 dest="output_filename",
                                 required=False,
                                 help="Specify the output file base name. Default: services",
                                 default='services')
        scan_parser.add_argument("--type",
                                 dest="scan_type",
                                 required=False,
                                 choices={'TCP_CONNECT', 'TCP_SYN', 'UDP', 'FULL_UDP_TCP',
                                          'FAST_UDP_TCP', 'SERVICES', 'NO_PING_SERVICES'},
                                 help="Select a scan type:\n"
                                      "  TCP_CONNECT = Use TCP 3-way handshake\n"
                                      "  TCP_SYN = Use SYN packets\n"
                                      "  UDP = Scan only UDP protocol\n"
                                      "  FULL_UDP_TCP = Use TCP 3-way hardshake and scan UDP protocol\n"
                                      "  FAST_UDP_TCP = Use SYN packets and scan UDP protocol\n"
                                      "  SERVICES = Scan with service detection\n"
                                      "  NO_PING_SERVICES = Scan with service detection, but force to always scan.\n",
                                 default='SERVICES',
                                 metavar='OPTION')
        scan_parser.add_argument('--closed-ports',
                                 dest="closed_ports",
                                 action="store_true",
                                 required=False,
                                 help="Output closed ports information. Includes ports from 1 to 65535.")
        scan_parser.add_argument('--skip-os',
                                 dest="skip_os",
                                 action="store_true",
                                 required=False,
                                 help="Skip OS scan and set it's value to \'Unknown\'")
        scan_parser.add_argument('--diff',
                                 dest="diff_file",
                                 required=False,
                                 help="Create a log file containing all the scan differences with"
                                      " a previous .CSV scan file.")
        scan_parser.add_argument('--persistent',
                                 dest='persistent',
                                 action='store_true',
                                 required=False,
                                 help='Scan until user interrupts, updating the output file each time new information'
                                      ' is received.')
        scan_parser.add_argument("--output-pdf",
                                 dest="output_pdf",
                                 action="store_true",
                                 required=False,
                                 help="Output a PDF with all the information gathered from the scan.")

        # sniff parser
        sniff_parser = subparsers.add_parser('sniff',
                                             help='Perform a sniffing. '
                                                  'Check \'python pscad.py sniff --help\' for more details',
                                             formatter_class=argparse.RawTextHelpFormatter)
        # sniff parser mandatory arguments
        sniff_parser.add_argument("interface",
                                  help="Specify the interface for capturing packets.")
        sniff_parser.add_argument("gateway",
                                  help="Specify the network gateway.")
        # mRequire one of the three types of sniffing
        descripted_group = sniff_parser.add_argument_group('required arguments (choose one)')
        sniff_group = descripted_group.add_mutually_exclusive_group(required=True)
        sniff_group.add_argument('-t', '--target',
                                 dest='targets',
                                 default=None,
                                 help="Specify IP addresses to sniff."
                                      "Ex: 192.168.1.2,192.168.1.3 or 192.168.1.0/24 or 192.168.1.2-102.168.1.5")
        sniff_group.add_argument('-l', '--localnet',
                                 dest='localnet',
                                 default=None,
                                 action='store_true',
                                 help='Poison the hole network.')
        sniff_group.add_argument('-r', '--randomize',
                                 dest='randomize',
                                 type=int,
                                 default=None,
                                 help='Selected a number of random hosts to sniff. If the host limit is not'
                                      'reached after a few ping sweeps, all of them will be selected.')
        # sniff parser optional arguments
        sniff_parser.add_argument("-o",
                                  dest="output_directory",
                                  required=False,
                                  help="Specify the output directory for file storing. Ex: /home/tmp/",
                                  default="./")
        sniff_parser.add_argument("-n",
                                  dest="output_filename",
                                  required=False,
                                  help="Specify the file output name.",
                                  default='sniffing')
        sniff_parser.add_argument("-i",
                                  dest="sniff_input_file",
                                  required=False,
                                  default=None,
                                  help="Specify the .csv file created by the scan to configure the network profile.")
        sniff_parser.add_argument("-f", "--filter",
                                  dest="filter",
                                  required=False,
                                  default=None,
                                  help="Apply BPF filter. Default: No filter")
        sniff_parser.add_argument("--timeout",
                                  dest="timeout",
                                  required=False,
                                  type=int,
                                  default=None,
                                  help="Apply a timeout to stop sniffing.")
        sniff_parser.add_argument("--packet-count",
                                  dest="packet_count",
                                  type=int,
                                  default=0,
                                  required=False,
                                  help="Number of packets to capture. Default: 0 (Infinite)")
        sniff_parser.add_argument('--type',
                                  dest='arp_type',
                                  required=False,
                                  choices={'1', '2', '3', 'who-is', 'is-at', 'both'},
                                  default='both',
                                  help='Specify by number or text the type of ARP packets for poisoning:\r\n'
                                       '  1 or who-is\r\n'
                                       '  2 or is-at\r\n'
                                       '  3 or both',
                                  metavar='TYPE')
        sniff_parser.add_argument("-v", "--verbose",
                                  dest="verbose",
                                  type=int,
                                  choices={0, 1, 2, 3},
                                  default=0,
                                  required=False,
                                  help="Level of verbosity from 0 (mute) to 3 (verbose). "
                                       "Default and recommended: 0",
                                  metavar='LEVEL')

        # Perform arguments check
        arguments = reader.parse_args()

        return arguments

    def check_os_utils(self):
        """ For every ConfigurationLoader.OS_UTILS, checks if there's anyone missing on the system.
        If so, it shuts down the application telling which one is missing.

        note::
            The difference between this method and check_pip_utils() is that the packages tested in this method
            are system level packages, not pip level.
        """
        for util in ConfigurationLoader.OS_UTILS:
            if spawn.find_executable(util) is None:
                halt_fail("{} is not installed on your system. Please install it and re-launch the application."
                          .format(util))
            else:
                print_success("Found {} installed.".format(util))

    def check_pip_utils(self):
        """ Retrieves a list of modules installed by pip and sorts them by their name.
        For every utils in ConfigurationLoader.PIP_UTILS, checks if there's anyone missing. If so, it
        calls  __install_package() to install that particular module in the system.
        """

        # Warning: Calling protected method
        # Get all pip packages installed and sort them by key.
        installed = get_pip_installations()
        installed_list = sorted(["%s" % i.key for i in installed])

        if ConfigurationLoader.PIP_UTILS is None or len(ConfigurationLoader.PIP_UTILS) == 0:
            print_fail("No utils have been specified. Please check if there's an utils list. "
                       "The application might fail.")
            # Cut the method execution
            return

        # For every package needed
        for util in ConfigurationLoader.PIP_UTILS:
            # If package not installed
            if util not in installed_list:
                answer = ""
                # Ask user if he wants to install
                while answer.lower() not in ['y', 'n']:
                    print_warning("{} was not found. The application cannot be launched. Would you like to install it? "
                                  "(y/n)".format(util))
                    answer = raw_input('Answer: ')
                # If answer is yes, install it.
                if answer.lower() == 'y':
                    self.__install_package(util)
                # If answer is no, do not install it and halt with a message error.
                else:
                    halt_fail("{} needs to be installed, execute \'pip install {}\' and launch the script. Exiting..."
                              .format(util, util))
            else:
                print_success("Found {} package".format(util))

    def __install_package(self, util):
        """Installs the selected package within the script. It attempts two types of installation. If the pip
        module has a 'main' attribute, it uses it to install it, if not, install it directly from the terminal.

            :param util: Package to install
            :type util: str
        """
        try:
            if hasattr(pip, 'main'):
                pip.main(['install', util])
            else:
                # Build the console command and redirect errors
                util_install = subprocess.Popen(['pip', 'install', util], stderr=subprocess.PIPE)
                _, errors = util_install.communicate()
                if len(errors):
                    halt_fail('Message popped during {} installation: {}\n'.format(util, errors))
        except Exception as e:
            halt_fail("Unexpected error when installing {}, please install it manually: {}".format(util, e))

        # Success message and exit from the application
        print_success("{} successfully installed. Please restart the application." .format(util))
        exit()
