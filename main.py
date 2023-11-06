import socket
import struct
import random


def create_dns_query(domain):
    transaction_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # Standard query with recursion desired
    qdcount = 1  # One question
    ancount = 0  # No answers
    nscount = 0  # No authority records
    arcount = 0  # No additional records

    # DNS Header
    dns_header = struct.pack('>HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)

    # Pseudo-graphical representation of the DNS header with actual values
    print("\n[DNS Header Structure]")
    print("┌─────────────────────────────────────────────┐")
    print(f"│ Transaction ID:           {transaction_id:>#6X} │")
    print("├─────┬───┬───┬───┬───────┬───────────────────┤")
    print(f"│ QR  │ Opcode │ AA│ TC│ RD│ RA│ Z │ RCODE      │")
    print(f"│ 0   │ 0000   │ 0 │ 0 │ 1 │ 0 │ 0 │ 0000       │")
    print("├─────┴───┴───┴───┴───────┴───────────────────┤")
    print(f"│ QDCOUNT:                  {qdcount:>#6} │")
    print(f"│ ANCOUNT:                  {ancount:>#6} │")
    print(f"│ NSCOUNT:                  {nscount:>#6} │")
    print(f"│ ARCOUNT:                  {arcount:>#6} │")
    print("└─────────────────────────────────────────────┘")

    # DNS Question
    query_parts = domain.split('.')
    query_body = b''.join(struct.pack('>B', len(part)) + part.encode('utf-8') for part in query_parts)
    query_type = struct.pack('>H', 1)  # Type A query
    query_class = struct.pack('>H', 1)  # Class IN

    dns_question = query_body + b'\x00' + query_type + query_class

    # Pseudo-graphical representation of the DNS question with actual values
    print("\n[DNS Question Structure]")
    print("┌─────────────────────────────────────────────┐")
    for part in query_parts:
        print(f"│ Length: {len(part):<2} Label: {part:<{len(part)}}", end=" " * (29 - len(part)))
        print("│")
    print("├─────────────────────────────────────────────┤")
    print(f"│ Type: A (0x{struct.unpack('>H', query_type)[0]:04X})              │")
    print(f"│ Class: IN (0x{struct.unpack('>H', query_class)[0]:04X})            │")
    print("└─────────────────────────────────────────────┘\n")

    return dns_header + dns_question


def send_dns_query(query, server='8.8.8.8', port=53):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        print("\nSending DNS query to server...")
        sock.sendto(query, (server, port))
        response, _ = sock.recvfrom(512)  # DNS responses typically fit within 512 bytes
        print("DNS response received.")
    return response


def parse_dns_response(response):
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', response[:12])

    print("\n[DNS Response Header Structure]")
    print("┌─────────────────────────────────────────────┐")
    print(f"│ Transaction ID:           {transaction_id:>#6X} │")
    print("├─────┬───┬───┬───┬───────┬───────────────────┤")
    print(f"│ QR  │ Opcode │ AA│ TC│ RD│ RA│ Z │ RCODE      │")
    print(
        f"│ {flags >> 15}   │ {(flags >> 11) & 0xF}    │ {(flags >> 10) & 1} │ {(flags >> 9) & 1} │ {(flags >> 8) & 1} │ {(flags >> 7) & 1} │ 0 │ {flags & 0xF}        │")
    print("├─────┴───┴───┴───┴───────┴───────────────────┤")
    print(f"│ QDCOUNT:                  {qdcount:>#6} │")
    print(f"│ ANCOUNT:                  {ancount:>#6} │")
    print(f"│ NSCOUNT:                  {nscount:>#6} │")
    print(f"│ ARCOUNT:                  {arcount:>#6} │")
    print("└─────────────────────────────────────────────┘")
    # Skip the question section in the response
    current_position = 12
    for _ in range(qdcount):
        while response[current_position] != 0:
            current_position += 1
        current_position += 5  # move past the null byte at the end and Type and Class fields

    # Parse the answer section in the response
    for _ in range(ancount):
        # Move past the name field
        if response[current_position] == 0xc0:
            current_position += 2  # Compressed name (pointer to a name)
        else:
            while response[current_position] != 0:
                current_position += 1
            current_position += 1  # move past the null byte at the end of the name

        type, class_, ttl, data_length = struct.unpack('>HHIH', response[current_position:current_position + 10])
        current_position += 10  # Move past the type, class, ttl, and data length fields

        if type == 1 and class_ == 1 and data_length == 4:  # if it's an A record
            ip_address = struct.unpack('>BBBB', response[current_position:current_position + 4])
            print(f"IP Address: {'.'.join(map(str, ip_address))}")
        current_position += data_length


def main():
    domain = input("Enter the domain name: ")
    query = create_dns_query(domain)
    response = send_dns_query(query)
    parse_dns_response(response)


if __name__ == '__main__':
    main()
