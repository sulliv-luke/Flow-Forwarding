import pickle


class Packet:
    def __init__(self, source_address, destination_address, data):
        self.source_address = source_address
        self.destination_address = destination_address
        self.data = data

    def to_bytes(self):
        return pickle.dumps(self)

    @staticmethod
    def from_bytes(packet_bytes):
        return pickle.loads(packet_bytes)


class LocationRequestPacket(Packet):
    def __init__(self, source_address, destination_address):
        # A location request packet doesn't need to carry any data,
        # so we can just pass an empty byte array to the superclass constructor
        super().__init__(source_address, destination_address, b"")


class LocationResponsePacket(Packet):
    def __init__(self, source_address, destination_address, next_hop):
        # The data for a location response packet is the next hop for the destination address
        super().__init__(source_address, destination_address, next_hop)
