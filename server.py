import socket
import sys
import constants as const
from routing_table import RoutingTable
from utils import generate_address
from packet import Packet, LocationRequestPacket, LocationResponsePacket 
import time
import netifaces
from ipaddress import IPv4Network

class Router():
    def __init__(self, byte_length, ip_address, port):
        # Generate byte address
        self.byte_addr = generate_address(byte_length)
        # Create routing table
        self.routing_table = RoutingTable()
        self.routing_table.start_cleanup()
        # Create a datagram socket
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        # Bind to address and ip
        self.socket.bind((ip_address, port))
        self.hasPacket = 0
        print(f"Created router with address {self.byte_addr}")

    def enable_broadcast(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def get_broadcast_addresses(self):
        broadcast_addresses = []
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            ipv4_info = addrs.get(netifaces.AF_INET)
            if ipv4_info:
                ipv4_info = ipv4_info[0]
                ip_address = ipv4_info['addr']
                netmask = ipv4_info['netmask']
                network = IPv4Network(f"{ip_address}/{netmask}", strict=False)
                broadcast_addresses.append(str(network.broadcast_address))
        return broadcast_addresses

    def broadcast_location_request(self, packet_bytes):
        self.enable_broadcast()
        broadcast_addresses = self.get_broadcast_addresses()
        for broadcast_addr in broadcast_addresses:
            if broadcast_addr.startswith(('172', '192')):
                self.socket.sendto(packet_bytes, (broadcast_addr, const.BROADCAST_PORT))
                print(f"Broadcasted location request to {broadcast_addr}:{const.BROADCAST_PORT}")

    def broadcast_termination(self, packet, received_from):
        self.enable_broadcast()
        new_term_packet = Packet(self.byte_addr, packet.destination_address, "TERMINATE", packet.count)
        packet_bytes = new_term_packet.to_bytes()
        broadcast_addresses = self.get_broadcast_addresses()
        ip_from = received_from[0]

        for broadcast_addr in broadcast_addresses:
            if broadcast_addr.startswith(('172')) and broadcast_addr[:8] != ip_from[:8]:
                print(f"Broadcast addr {broadcast_addr[:8]}, received from {received_from[:8]}")
                self.socket.sendto(packet_bytes, (broadcast_addr, const.BROADCAST_PORT))
                print(f"Broadcasted termination packet to {broadcast_addr}:{const.BROADCAST_PORT}")

    def forward_packet(self, packet, destination_addr, rec_from):
        if isinstance(packet, Packet):
            if packet.data == "TERMINATE":
                if packet.source_address == self.byte_addr:
                    return
                print(f"Received TERMINATE packet from {packet.source_address}")
                if (self.knows_route(packet.destination_address)):
                    self.routing_table.remove_route(packet.destination_address)
                    print(f"Removed route to {packet.destination_address}")
                self.broadcast_termination(packet, rec_from)
                return
            elif self.knows_route(destination_addr):
                print(f"Router knows the route to {destination_addr}")
                serialised_packet = packet.to_bytes()
                self.socket.sendto(
                    serialised_packet,
                    (self.routing_table.table[destination_addr]["next_hop"]),
                )
                addr_of_next_hop = self.routing_table.table[destination_addr]["next_hop_address"]
                print(f"Forwarded packet to {destination_addr} via {addr_of_next_hop}")
                self.hasPacket = 0
                return
            
            print(f"Router does not know the route to {destination_addr}")
            print(f"Sending location request packet to all connected nodes, Count: {packet.count}")

            location_request_packet = LocationRequestPacket(
                self.byte_addr, packet.destination_address, packet.count
            )
            req_bytes = location_request_packet.to_bytes()
            # Send location request packet to all connected nodes
            self.broadcast_location_request(req_bytes)

            timeout = 5
            timer = time.time()

            while True:
                try:
                    # If time elapsed is greater than timeout, break the loop
                    if time.time() - timer > timeout:
                        print(f"Timeout: No response")
                        break

                    # Try to receive the response
                    self.socket.settimeout(timeout)
                    response, src = self.socket.recvfrom(4026)

                    # If response is received, process it (add your processing code here)
                    response_packet = Packet.from_bytes(response)
                    
                    # Check if the deserialized packet is a LocationResponsePacket
                    if isinstance(response_packet, LocationResponsePacket):
                    # Check if the packet is not from this router itself
                        if response_packet.source_address != self.byte_addr:
                            print(f"Response received from {response_packet.source_address}, Count: {response_packet.count}")
                            self.update_routing_table(
                            packet.destination_address, src, response_packet.source_address
                            )
                            print(f"Added route to {packet.destination_address} via {response_packet.source_address}")
                            if self.hasPacket == 1:
                                self.forward_packet(packet, destination_addr, rec_from)
                            break
                    else:
                        # If the packet is not a LocationResponsePacket, ignore it
                        print(f"Ignored packet from {response_packet.source_address} that is not a LocationResponsePacket.")
                        continue  # This will skip to the next iteration of the loop
                except socket.timeout:
                    print(
                        f"No response received within the given time frame."
                    )
                    break

    def listen(self):
        while True:
            self.socket.settimeout(None)
            self.socket.setblocking(True)
            message, addr = self.socket.recvfrom(4096)
            received_packet = Packet.from_bytes(message)
            if isinstance(received_packet, LocationRequestPacket):
                print(f"Received location request packet from {received_packet.source_address} for {received_packet.destination_address}, Count: {received_packet.count}")
                if self.knows_route(received_packet.destination_address):
                    response_packet = LocationResponsePacket(
                        self.byte_addr,
                        addr,
                        self.byte_addr,
                    )
                    print(f"Sending location response packet to {received_packet.source_address}, count: {received_packet.count}")
                    self.socket.sendto(response_packet.to_bytes(), addr)
                else:
                    self.forward_packet(received_packet, received_packet.destination_address, addr)
                    if self.knows_route(received_packet.destination_address):
                        response_packet = LocationResponsePacket(
                            self.byte_addr,
                            addr,
                            self.byte_addr,
                            received_packet.count,
                        )
                        print(f"Sending location response packet to {received_packet.source_address}, count: {received_packet.count}")
                        self.socket.sendto(response_packet.to_bytes(), addr)
            elif isinstance(received_packet, Packet):
                self.hasPacket = 1
                print(f"Received packet at router {self.byte_addr}: {received_packet.data}, count: {received_packet.count}")
                self.forward_packet(received_packet, received_packet.destination_address, addr)



    def update_routing_table(self, addr, node, byte_addr):
        # Adds new route with the corresponding byte address, network element and expiry time
        ip, port = node
        self.routing_table.add_route(addr, ip, port, 30, byte_addr)

    def knows_route(self, addr):
        # Checks if the router knows the route to the given address
        return addr in self.routing_table.table


def main(argv):
    localIP     = "0.0.0.0"

    router = Router(4, localIP, const.SERVER_PORT)

    router.socket.settimeout(500)

    print("Server up and listening", flush=True)

    router.listen()

if __name__ == "__main__":
    main(sys.argv[1:])