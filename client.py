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
        self.socket.bind(('0.0.0.0', const.SERVER_PORT))
        print(f"Created endpoint with address {self.byte_addr}")

    def listen(self):
        # Set a timeout for the socket
        self.socket.settimeout(2.5)  # 5 seconds timeout
        while True:
            try:
                packetbytes, src = self.socket.recvfrom(4096)
            except socket.timeout:
                print("Did not receive response in time")
                break
            packet = Packet.from_bytes(packetbytes)
            if isinstance(packet, LocationRequestPacket):
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
                print(f"Received packet at {self.byte_addr}: {packet.data}")
                break    

def get_4_byte_code():
    while True:
        code = input("Enter a 4-byte code: ")
        if len(code) == 4:
            return code
        else:
            print("Invalid input. Please enter exactly 4 characters.")

def main(argv):
    # Get 4-byte address of node to send packet to from the user
    client = Endpoint(4)
    count = 0
    while True:
        destination_byte_addr = get_4_byte_code()
        # Encode the 4-byte code along with the message
        packet_data = Packet(client.byte_addr, destination_byte_addr, "Hello World!", count)
        packet = packet_data.to_bytes()
        bufferSize = 65535

        # Use the first argument as the name of the server to contact
        # omitted all checks and safety here
        addr = (argv[0], const.SERVER_PORT)

        # Create a UDP socket at client side
        comms = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

        # Send to server using created UDP socket
        comms.sendto(packet, addr)
        print(f"Sending packet to router from {client.byte_addr}")

        # Listen for incoming datagrams
        client.listen()

        # If you want to keep sending messages, you can loop here
        # If you want to stop, you can break from the loop
        continue_input = input("Send another message? (y/n): ").lower()
        if continue_input != 'y':
            # Send termination packet
            termination_packet_data = Packet(client.byte_addr, client.byte_addr, "TERMINATE", count)
            termination_packet = termination_packet_data.to_bytes()
            comms.sendto(termination_packet, addr)
            print(f"Sending termination packet to router from {client.byte_addr}")
            break
        count += 1

if __name__ == "__main__":
    main(sys.argv[1:])
