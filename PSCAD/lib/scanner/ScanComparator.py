# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019


class ScanComparator:
    """ This class presents the utilities for gathering specific information about two different network
    scans performed by the PSCAD application.

    Each scan is formed by a list of lists, in which each individual list contains different information
    about different ports from every target. The purpose of this class is to add an abstraction level
    to the lib.scanner.Scanner.__compare_scans() private method, by returning useful information about two given
    network scans: a previous scan and a current scan.

        :param previous_network_scan: List of lists with the previous scan information
        :param current_network_scan: List of lists with the current scan information
        :type previous_network_scan: list
        :type current_network_scan: list
    """

    def __init__(self,
                 previous_network_scan,
                 current_network_scan):
        self.__previous_network_scan = previous_network_scan
        self.__current_network_scan = current_network_scan

    def __get_all_previous_ips(self):
        """ Returns a list of all unique IP addresses found on the previous network scan.

            :returns: List of all the unique IPs scanned in the previous scan
            :rtype: list
        """
        return list(set([x[1] for x in self.__previous_network_scan]))

    def __get_all_current_ips(self):
        """ Returns a list of all unique IP address found on the current network scan.

            :returns: List of all the unique IPs scanned in the previous scan
            :rtype: list
        """
        return list(set([x[1] for x in self.__current_network_scan]))

    def __get_previous_ip_profile(self, ip):
        """ For a specific IP Address, returns a dictionary containing all it's scanned
        ports/proto as keys and that specific port state as value for that entry, all from the
        previous scan.

            :param ip: IP to build the profile for.
            :type ip: str
            :return: None if no records were found
            :return: Dictionary containing all the ports info for that IP
            :rtype: None, dict
        """
        previous_profile = {}
        # All entries from previous scan which have the specified IP on second column.
        previous_records = [x for x in self.__previous_network_scan if x[1] == ip]

        # If no previous records where found, return None
        if not len(previous_records):
            return None

        # Each record is information from a specific port.
        for single_record in previous_records:
            # Get port/proto, from the third column
            port_proto = single_record[2]
            # Get state, from fourth column.
            state = single_record[3]
            # Assign to dictionary
            previous_profile[port_proto] = state

        return previous_profile

    def __get_current_ip_profile(self, ip):
        """ For a specific IP Address, returns a dictionary containing all it's scanned
        ports/proto as keys and that specific port state as value for that entry, all from the
        current scan.

            :param ip: IP to build the profile for.
            :type ip: str
            :return: None if no records were found
            :return: Dictionary containing all the ports info for that IP
            :rtype: None, dict
        """
        current_profile = {}
        # All entries from current scan which have the specified IP on second column.
        current_records = [x for x in self.__current_network_scan if x[1] == ip]

        # If no previous records where found, return None
        if not len(current_records):
            return None

        # Each record is information from a specific port.
        for single_record in current_records:
            # Get port/proto, from the third column
            port_proto = single_record[2]
            # Get state, from fourth column.
            state = single_record[3]
            # Assign to dictionary
            current_profile[port_proto] = state

        return current_profile

    def get_common_ips(self):
        """ Returns a list of common IPs scanned both in the current scan and in the previous scan.

            :returns: List of common IPs
            :rtype: list
        """
        previous_ips = self.__get_all_previous_ips()
        current_ips = self.__get_all_current_ips()

        return list(set(previous_ips).intersection(current_ips))

    def get_previously_non_scanned_ips(self):
        """ Compares the previous scan to the current one and returns a list of the IP addresses
        that do not appear in the previous one.

            :returns: List of previously non scanned IP addresses
            :rtype: list
        """

        return list(set(self.__get_all_current_ips()).difference(set(self.__get_all_previous_ips())))

    def get_currently_non_scanned_ips(self):
        """ Compares the current scan to the previous one and returns a list of the IP addresses
        that do not appear in the current one.

            :returns: List of currently non scanned IP addresses
            :rtype: list
        """

        return list(set(self.__get_all_previous_ips()).difference(set(self.__get_all_current_ips())))

    def get_both_ip_profiles(self, ip):
        """ Returns both previous and current profiles for a given IP Address

            :returns: Previous IP profile and current IP profile
            :rtype: tuple
                WHERE
                dict previous_profile is the previous profile for the given IP
                dict current_profile is the current profile for the given IP
        """
        return self.__get_previous_ip_profile(ip), self.__get_current_ip_profile(ip)
