from scapy.all import IP, IPv6, ARP, UDP, TCP, Ether, rdpcap, wrpcap, \
    srp, sendp, conf, get_if_addr, get_if_hwaddr, getmacbyip, sniff, send

import os
import logging
import threading
import random
import time
import socket
from collections import defaultdict

class PacketHandler:
    """
    NAT-based packet handler that routes client traffic to the internet
    and forwards responses back to the client.
    """
    def __init__(self, write_pcap=False, pcap_filename=None, logger_name="PacketHandler"):
        self.write_pcap = write_pcap
        self.pcap_filename = pcap_filename
        self.logger = logging.getLogger(logger_name)
        if self.write_pcap and pcap_filename is not None:
            os.makedirs(os.path.dirname(pcap_filename), exist_ok=True)
        
        # NAT tables: Maps (client_ip, client_port) -> (nat_port, dst_ip, dst_port)
        self.nat_table = {}
        # Reverse NAT table: Maps nat_port -> (client_socket, client_ip, client_port)
        self.reverse_nat_table = {}
        # Used ports set
        self.used_ports = set()
        # Client connections: Maps client_ip -> client_socket
        self.client_connections = {}
        
        # Start sniffer thread
        self.sniffer_thread = threading.Thread(target=self.packet_sniffer)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        
        # Enable IP forwarding on the system
        self._enable_ip_forwarding()

    def _enable_ip_forwarding(self):
        """Enable IP forwarding in the operating system"""
        try:
            # For Linux
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            self.logger.info("IP forwarding enabled")
        except Exception as e:
            self.logger.warning(f"Failed to enable IP forwarding: {e}")
            self.logger.warning("Internet connectivity for clients may not work properly")
            self.logger.warning("Run 'echo 1 > /proc/sys/net/ipv4/ip_forward' as root")

    def get_free_nat_port(self):
        """Get a free port for NAT between 10000 and 60000"""
        while True:
            port = random.randint(10000, 60000)
            if port not in self.used_ports:
                self.used_ports.add(port)
                return port

    def release_nat_port(self, port):
        """Release a previously allocated NAT port"""
        if port in self.used_ports:
            self.used_ports.remove(port)

    def register_client_connection(self, client_socket, client_ip):
        """Register a client connection for return traffic"""
        self.client_connections[client_ip] = client_socket
        self.logger.info(f"Registered client connection for {client_ip}")

    def forward_tcp_packet(self, packet, client_socket, client_ip):
        """Forward a TCP packet to its destination with NAT"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Create connection tuple
            conn_tuple = (src_ip, sport)
            
            # Check if connection already exists in NAT table
            if conn_tuple in self.nat_table:
                nat_port = self.nat_table[conn_tuple][0]
            else:
                # Get a unique NAT port for this connection
                nat_port = self.get_free_nat_port()
                self.nat_table[conn_tuple] = (nat_port, dst_ip, dport)
                self.reverse_nat_table[nat_port] = (client_socket, src_ip, sport)
                self.logger.debug(f"New TCP connection: {src_ip}:{sport} -> {dst_ip}:{dport} (NAT port: {nat_port})")
            
            # Modify packet for NAT
            packet[IP].src = get_if_addr(conf.iface)  # Replace source IP with our IP
            packet[TCP].sport = nat_port              # Replace source port with NAT port
            
            # Recalculate checksums
            del packet[IP].chksum
            del packet[TCP].chksum
            
            # Send the packet out
            send(packet, verbose=False)
            return True
        except Exception as e:
            self.logger.error(f"Error forwarding TCP packet: {e}")
            return False

    def forward_udp_packet(self, packet, client_socket, client_ip):
        """Forward a UDP packet to its destination with NAT"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            # Create connection tuple
            conn_tuple = (src_ip, sport)
            
            # Check if connection already exists in NAT table
            if conn_tuple in self.nat_table:
                nat_port = self.nat_table[conn_tuple][0]
            else:
                # Get a unique NAT port for this connection
                nat_port = self.get_free_nat_port()
                self.nat_table[conn_tuple] = (nat_port, dst_ip, dport)
                self.reverse_nat_table[nat_port] = (client_socket, src_ip, sport)
                self.logger.debug(f"New UDP connection: {src_ip}:{sport} -> {dst_ip}:{dport} (NAT port: {nat_port})")
            
            # Modify packet for NAT
            packet[IP].src = get_if_addr(conf.iface)  # Replace source IP with our IP
            packet[UDP].sport = nat_port              # Replace source port with NAT port
            
            # Recalculate checksums
            del packet[IP].chksum
            del packet[UDP].chksum
            
            # Send the packet out
            send(packet, verbose=False)
            return True
        except Exception as e:
            self.logger.error(f"Error forwarding UDP packet: {e}")
            return False

    def packet_sniffer(self):
        """Sniff for incoming packets that need to be forwarded back to clients"""
        def packet_callback(packet):
            try:
                # Only process IP packets
                if IP not in packet:
                    return
                
                # Only process TCP or UDP packets
                if TCP in packet:
                    dport = packet[TCP].dport
                    if dport in self.reverse_nat_table:
                        client_socket, client_ip, client_port = self.reverse_nat_table[dport]
                        
                        # Restore original destination IP and port
                        packet[IP].dst = client_ip
                        packet[TCP].dport = client_port
                        
                        # Recalculate checksums
                        del packet[IP].chksum
                        del packet[TCP].chksum
                        
                        # Convert packet to bytes
                        packet_bytes = bytes(packet[IP])
                        
                        # Forward to client
                        self.logger.debug(f"Forwarding TCP response to client: {client_ip}:{client_port}")
                        client_socket.sendall(packet_bytes)
                        
                elif UDP in packet:
                    dport = packet[UDP].dport
                    if dport in self.reverse_nat_table:
                        client_socket, client_ip, client_port = self.reverse_nat_table[dport]
                        
                        # Restore original destination IP and port
                        packet[IP].dst = client_ip
                        packet[UDP].dport = client_port
                        
                        # Recalculate checksums
                        del packet[IP].chksum
                        del packet[UDP].chksum
                        
                        # Convert packet to bytes
                        packet_bytes = bytes(packet[IP])
                        
                        # Forward to client
                        self.logger.debug(f"Forwarding UDP response to client: {client_ip}:{client_port}")
                        client_socket.sendall(packet_bytes)
            except Exception as e:
                self.logger.error(f"Error processing packet in sniffer: {e}")

        self.logger.info('Starting packet sniffer')
        try:
            # Filter for traffic coming back to our NAT ports
            nat_ports = [str(port) for port in self.reverse_nat_table.keys()]
            if nat_ports:
                filter_expr = f"dst host {get_if_addr(conf.iface)} and (dst port {' or dst port '.join(nat_ports)})"
            else:
                filter_expr = f"dst host {get_if_addr(conf.iface)}"
                
            sniff(iface=conf.iface, prn=packet_callback, filter=filter_expr, store=False)
        except Exception as e:
            self.logger.error(f"Error in packet sniffer: {e}")

    def handle_client_packet(self, packet_data, client_socket=None, client_ip=None):
        """Process packets from VPN clients and forward them to their destinations"""
        try:
            packet = IP(packet_data)
            
            if client_socket and client_ip:
                # Register the client connection if not already registered
                if client_ip not in self.client_connections:
                    self.register_client_connection(client_socket, client_ip)
            
            # Log the packet
            self.logger.debug(f"Processing client packet: {packet.summary()}")
            
            # Save to pcap if enabled
            self.append_to_pcap(packet)
            
            # Forward the packet based on protocol
            if TCP in packet:
                return self.forward_tcp_packet(packet, client_socket, client_ip)
            elif UDP in packet:
                return self.forward_udp_packet(packet, client_socket, client_ip)
            else:
                # For other IP protocols, just forward with source IP changed
                packet[IP].src = get_if_addr(conf.iface)
                del packet[IP].chksum
                send(packet, verbose=False)
                return True
                
        except Exception as e:
            self.logger.error(f"Error handling client packet: {e}")
            return False

    def append_to_pcap(self, packet):
        try:
            if self.write_pcap and self.pcap_filename is not None:
                # Add fake layer 2 data to the packet, if missing
                if not packet.haslayer(Ether):
                    src_mac = get_if_hwaddr(conf.iface)
                    fake_ether = Ether(src=src_mac, dst=None)
                    packet = fake_ether / packet
                wrpcap(self.pcap_filename, packet, append=True)
        except Exception as e:
            logging.error(f'Error appending to PCAP: {e}')