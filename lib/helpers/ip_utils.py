# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019

import re
import struct
import socket

from lib.helpers.colors import *


def _is_ip_address(ip_address):
    """Checks if a given IP address is correctly formed.

        :param ip_address: IP address to check
        :type ip_address: str
        :return: True if it is a valid IP Address, False if not
        :rtype: bool
    """
    # IP address regex
    ip_address_regex = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|'
                                  '2[0-4][0-9]|25[0-5])\.){3}([0-9]|'
                                  '[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

    # Return True if matches, False if not.
    if ip_address_regex.match(ip_address):
        return True
    return False


def _ip_range(starting_ip, ending_ip):
    """ Calculates a list of IPs between two given.

        :param starting_ip: Range starting IP address
        :param ending_ip: Range ending IP address
        :type starting_ip: str
        :type ending_ip: str
        :return: list
    """

    # Create a list containing the 4 octets from both IP address in decimal format.
    split_starting_ip = list(map(int, starting_ip.split('.')))
    split_ending_ip = list(map(int, ending_ip.split('.')))
    # Create list of IPs to return, starting with the first one.
    ip_range = [starting_ip]

    # Execute algorithm. While you can add one to the most on the right octet, keep going
    # and add. If the 4 octets are named from 3 to 0 from left to right: when octet N is 255,
    # set octet N to 0 and add one to octet N+1
    while split_starting_ip != split_ending_ip:
        split_starting_ip[3] += 1
        for i in [3, 2, 1]:
            if split_starting_ip[i] == 256:
                split_starting_ip[i] = 0
                split_starting_ip[i - 1] += 1
        # Reformat to IP address-like string.
        current_ip = '.'.join(map(str, split_starting_ip))
        ip_range.append(current_ip)

    return ip_range


def _dispatch_network(network):
    """ Creates a list of all the IP address inside a network with it's netmask in CIDR format.

        :param network: Netowrk IP address and /netmask to dispatch
        :type network: str
        :return: List of every IP on a network range
        :rtype: list
        :raises: MalformedIPAddressError
    """

    # List to return
    ip_addresses = []

    # Delete blank spaces and split IP Address and netmask in CIDR format.
    ip_address_netmask = network.replace(' ', '').split('/')
    # If not split in two parts, raise Exception.
    if len(ip_address_netmask) != 2:
        halt_fail('Invalid network to dispatch: {}.'
                  ' Need an IP address and CIDR Mask like 192.168.1.0/24'
                  .format(network))

    # IP Address is the first part
    ip_address = ip_address_netmask[0]
    cidr = None

    # CIDR is the second part
    try:
        cidr = int(ip_address_netmask[1])
    # If cannot convert to integer, raise Exception
    except ValueError:
        halt_fail('Invalid CIDR format: {}'.format(ip_address_netmask[1]))

    # If netmask not between 0 and 32, included, raise Exception
    if not 0 <= cidr <= 32:
        halt_fail('Out of range CIDR: {}'.format(cidr))

    # If invalid IP address, raise Exception
    if not _is_ip_address(ip_address):
        halt_fail('Invalid network IP: {}.'.format(ip_address))

    # Combination from struct and socket for binary formatting and bit level operations.
    # Getting every IP address inside a network range (established by netmask).
    host_bits = 32 - cidr
    aux = struct.unpack('>I', socket.inet_aton(ip_address))[0]
    start = (aux >> host_bits) << host_bits
    end = start | ((1 << host_bits) - 1)

    for ip in range(start, end):
        ip_addresses.append(socket.inet_ntoa(struct.pack('>I', ip)))

    # Return every IP address but not Network Address
    # Broadcast IP address is not included
    return ip_addresses[1:]


def parse_targets(targets):
    """ Returns a list containing all targets specified for the scan.

        :param targets: String that specifies the targets to scan
        :type targets: str
        :return: List containing the targets to scan as Strings.
        :rtype: list
        :raises: MalformedIPAddressError

    Example:
        targets                             return
        '192.168.1.1, 192.168.1.2'          ['192.168.1.1', '192.168.1.2']
        '192.168.1.1-192.168.1.3'           ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        '192.168.1.0/30'                    ['192.168.1.1', '192.168.1.2']

    note:
        If network/cidr mask is specified, both Network address and broadcast address will be omitted.
    """

    # List to return
    target_list = []
    # Delete blank spaces
    targets_string = targets.replace(' ', '')

    # For each block split by a comma.
    for split_target in targets_string.split(','):
        # If range indicator
        if '-' in split_target:
            # Split range
            ip_range = split_target.split('-')
            # Get starting IP address from range
            starting_ip = ip_range[0]
            # If not a valid IP address, raise Error
            if not _is_ip_address(starting_ip):
                halt_fail('Invalid starting IP range: {}'.format(starting_ip))
            # Get Ending IP address from range
            ending_ip = ip_range[1]
            # If not valid IP address, raise Error
            if not _is_ip_address(ending_ip):
                halt_fail('Invalid ending IP range: {}'.format(ending_ip))
            # For every IP in range, add to list if valid IP. If not, raise Exception.
            for single_target_in_range in _ip_range(starting_ip, ending_ip):
                if _is_ip_address(single_target_in_range):
                    target_list.append(single_target_in_range)
                else:
                    halt_fail('Invalid IP Address: {}'.format(single_target_in_range))
        # If a slash is found, guess a network mask
        elif '/' in split_target:
            # Extend the list for dispatching the network
            target_list.extend(_dispatch_network(split_target))
        # If it reaches here, guess single IP. Add to list or raise Error if malformed.
        else:
            if _is_ip_address(split_target):
                target_list.append(split_target)
            else:
                halt_fail('Invalid IP Address: {}'.format(split_target))

    # Return the sorted list. List is sorted by IP address. Ex: 192.168.1.12 > 192.168.1.9
    # The key for sorting is comparing the hex value for all IP Addresses. Split the IP by the dot (.),
    # convert to upper cased Hex value each part, join them all and convert then to integer, base 16.
    return sorted(list(set(target_list)),
                  key=lambda ip: int(''.join(["%02X" % int(i) for i in ip.split('.')]), 16))


def get_ip_with_netmask(ip, netmask):
    """ Returns the network IP/netmask for a given IP and its network mask in decimal format.

        :param ip: IP to return
        :param netmask: Network masking
        :return: IP/mask forma
        :rtype: str
    """

    split_net_addr = [int(x) for x in ip.split('.')]
    split_netmask = [int(x) for x in netmask.split('.')]
    split_network_ip = [str(x & y) for x, y in zip(split_net_addr, split_netmask)]
    network_ip = '.'.join(split_network_ip)

    cidr_netmask = sum(bin(int(x)).count('1') for x in netmask.split('.'))
    return network_ip + '/' + str(cidr_netmask)


def __is_valid_port(port):
    """ Tells if a given port is valid.

        :param port: Port to check
        type: port: str, int
    """

    int_port = None
    try:
        int_port = int(port)
    except ValueError:
        halt_fail('Invalid port format: {}'.format(port))

    return 0 < int_port < 65536


def parse_ports_from_str(ports):
    """ Checks if a given port string is correctly formed.

        :param ports: String that specifies the ports to scan
        :type ports: str
    """
    # Delete blank spaces
    ports_string = ports.replace(' ', '')

    # For every comma separated block
    for split_ports in ports_string.split(','):
        # If there is a range indicator.
        if '-' in split_ports:
            # Split the range
            port_range = split_ports.split('-')
            # Cast to integer the starting port range number.
            first_port_range = None
            try:
                first_port_range = int(port_range[0])
            # If ValueError, non valid port with error message
            except ValueError:
                first_port = port_range[0] if len(port_range[0]) else 'None'
                halt_fail('Invalid starting port range: {}'.format(first_port))
            # Cast ending port range
            last_port_range = None
            try:
                last_port_range = int(port_range[1]) + 1
            # If IndexError, no ending port range was specified.
            except IndexError:
                halt_fail('End of port range in {}- not specified'.format(port_range[0]))
            # If ValueError, invalid ending for port range.
            except ValueError:
                halt_fail('Invalid ending port range: {} '.format(port_range[1]))
            # For every port in the range calculated
            for single_port in range(first_port_range, last_port_range):
                # If valid port, halt
                if not __is_valid_port(single_port):
                    halt_fail('Invalid port: {}'.format(single_port))
        # If no range indicators, guess individual port
        else:
            # If split port has length
            if len(split_ports):
                # Cast to integer value
                integer_parsed_port = None
                try:
                    integer_parsed_port = int(split_ports)
                # If ValueError, malformed
                except ValueError:
                    halt_fail('Invalid port: {}'.format(split_ports))
                # If it is not a valid port, error message
                if not __is_valid_port(integer_parsed_port):
                    halt_fail('Invalid port: {}.'.format(integer_parsed_port))
