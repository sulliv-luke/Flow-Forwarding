import random
import string


def generate_address(byte_length):
    # Define the characters that can be used in the address
    characters = string.ascii_uppercase + string.digits

    # Generate the address
    address = "".join(random.choice(characters) for _ in range(byte_length))

    return address
