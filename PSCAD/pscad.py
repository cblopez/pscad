# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, April 2019

from .lib.core.ConfigurationLoader import *
from .lib.scanner.Scanner import *
from .lib.sniffer.Sniffer import *
from .lib.helpers.colors import *


def call_subroutine(command):
    """ Return the callback function depending on the command specified.

        :param command: Command requested
        :type command: str
        :returns: Callback function
        :rtype: function
    """
    switch = {
        'scan': scanner_subroutine,
        'sniff': sniffer_subroutine
    }

    return switch[command]


def show_banner():
    """Prints the script banner on init.
    """
    print("")
    print("  _____   _____  _____          _____  ")
    print(" |  __ \\ / ____|/ ____|   /\\   |  __ \\ ")
    print(" | |__) | (___ | |       /  \\  | |  | |")
    print(" |  ___/ \\___ \\| |      / /\\ \\ | |  | |")
    print(" | |     ____) | |____ / ____ \\| |__| |")
    print(" |_|    |_____/ \\_____/_/    \\_\\_____/ ")
    print("                                       ")
    print("*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*")
    print("")
    print("Python Services Checker and Anomaly Detector*")
    print("by Christian Barral Lopez.")
    print("")


def is_root():
    """ Checks if the user executing the script has root permissions

        :returns: True if the user is root. False if not.
        :rtype: bool
    """

    try:
        has_privileges = os.getuid() == 0
    except AttributeError:
        has_privileges = ctypes.windll.shell32.IsUserAnAdmin() != 0

    return has_privileges


def scanner_subroutine(arguments):
    """ Starts the scanning subroutine depeding on application arguments.

    Creates a Scanner instance and depending on the user selecting a manual input or a an input file,
    it initiates the scanner from different methods.

        :param arguments: Application arguments
        :type arguments: argparse.Namespace
    """
    print_success("Starting scanner subroutine.")
    scanner = Scanner(arguments.scan_type,
                      arguments.ports,
                      arguments.output_directory,
                      arguments.output_filename,
                      arguments.closed_ports,
                      arguments.skip_os,
                      arguments.diff_file,
                      arguments.persistent,
                      arguments.output_pdf)

    if arguments.scan_input_file is not None:
        scanner.init_from_file(arguments.scan_input_file)

    else:
        scanner.init_from_targets(arguments.scan_targets)


def sniffer_subroutine(arguments):
    """ Starts the sniffing subroutine instantiating a Sniffer object, with its attributes defined by the
    application arguments. User must have root permissions.

        :param arguments: Application arguments
        :type arguments: argparse.Namespace
    """
    print_success("Starting sniffer subroutine.")

    # If user has no root permissions, exit and show an error
    if not is_root():
        halt_fail("You must run the script with root privileges. Exiting...")

    sniffer = Sniffer(arguments.interface,
                      arguments.gateway,
                      arguments.targets,
                      arguments.localnet,
                      arguments.randomize,
                      arguments.arp_type,
                      arguments.output_directory,
                      arguments.output_filename,
                      arguments.sniff_input_file,
                      arguments.filter,
                      arguments.timeout,
                      arguments.packet_count,
                      arguments.verbose)

    sniffer.start_sniffing()


def main():
    """Main script function.

    Helped by the the rest of the application classes and functions, it contains all the main routine
    to execute.
    """

    print_success("Starting PSCAD application.")

    print_warning("Parsing parameters.")
    # Get Singleton instance
    config_loader = ConfigurationLoader.get_instance()
    # Parse application arguments
    arguments = config_loader.parse_arguments()
    print_success("All parameters were loaded successfully")

    print_warning("Checking utils on the system")
    # Check for needed applications installed on the system
    config_loader.check_os_utils()
    print_success("All utils required are installed on the system")

    print_warning("Checking pip utils")
    # Check if all python modules are installed
    config_loader.check_pip_utils()
    print_success("All python utils required are installed on the system.")

    print_success("Application loaded successfully. Initiating...")
    # 2 seconds sleep to allow the user to see all the info printed till this moment.
    time.sleep(2)
    # print application banner
    show_banner()

    # Execute te proper callback function depending on the command.
    call_subroutine(arguments.command)(arguments)


# If this file is executed, start the application
if __name__ == "__main__":
    main()
