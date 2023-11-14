import time
import threading


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

    def remove_route(self, destination):
        del self.table[destination]

    def remove_expired_routes(self):
        current_time = time.time()
        expired_routes = [destination for destination, route in self.table.items() if route["expiry_time"] < current_time]
        for destination in expired_routes:
            del self.table[destination]
            print(f"Removed route to {destination} as it has expired")

    def start_cleanup(self, interval=5):
        def cleanup():
            while True:
                self.remove_expired_routes()
                time.sleep(interval)

        threading.Thread(target=cleanup, daemon=True).start()
