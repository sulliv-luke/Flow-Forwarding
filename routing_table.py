import time


class RoutingTable:
    # RoutingTable will map destination addresses to the next hop addresses
    def __init__(self):
        self.table = {}

    def add_route(self, destination, ip_address, port, lifetime, byte_addr):
        self.table[destination] = {
            "next_hop": (ip_address, port),
            "next_hop_address": byte_addr,
            "expiry_time": time.time() + lifetime,
        }

    def remove_expired_routes(self):
        current_time = time.time()
        self.table = {
            destination: info
            for destination, info in self.table.items()
            if info["expiry_time"] > current_time
        }
