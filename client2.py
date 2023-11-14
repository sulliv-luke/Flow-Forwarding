import sys
import socket
import constants as const
from utils import generate_address
from packet import Packet, LocationRequestPacket, LocationResponsePacket

class Endpoint():
    def __init__(self, byte_length):
        self.byte_addr = generate_address(byte_length)
         # Create a UDP socket at client side
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', const.SERVER_PORT))  # Replace 0 with your specific port if needed
        print(f"Created endpoint with address {self.byte_addr}")

    def listen(self):
        print(f"Router {self.byte_addr} listening for packets at {self.socket.getsockname()}")
        while True:
            packetbytes, src = self.socket.recvfrom(4096)
            packet = Packet.from_bytes(packetbytes)
            if isinstance(packet, LocationRequestPacket):
                print(f"Received location request from {packet.source_address}, count: {packet.count}")
                if self.byte_addr == packet.destination_address:
                    # Send a LocationResponsePacket back to the source
                    response_packet = LocationResponsePacket(
                        self.byte_addr, packet.destination_address, self.socket.getsockname(), packet.count
                    )
                    response_bytes = response_packet.to_bytes()
                    self.socket.sendto(response_bytes, src)
            elif isinstance(packet, Packet) and not isinstance(
                packet, LocationResponsePacket
            ) and packet.data != "TERMINATE":
                print(f"Received packet at {self.byte_addr}: {packet.data}, count: {packet.count}")
                self.send_ack(packet, src)

    def send_ack(self, received_packet, addr):
        if isinstance(received_packet, Packet):
            print(f"Sending ACK packet to {received_packet.source_address}, count: {received_packet.count}")
            ackpack = Packet(self.byte_addr, received_packet.source_address, f"Received packet at {self.byte_addr}: {received_packet.data}", received_packet.count).to_bytes()
            # Send to server using created UDP socket
            self.socket.sendto(ackpack, addr)
            print(f"Sending packet to router from {self.byte_addr}, count: {received_packet.count}")



def main(argv):
    # Get 4-byte address of node to send packet to from the user
    client = Endpoint(4)
    client.listen()

if __name__ == "__main__":
    main(sys.argv[1:])
