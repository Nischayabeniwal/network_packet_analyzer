def format_packet_data(packet):
    """Format packet data for display."""
    try:
        src_ip = packet[1].src
        dst_ip = packet[1].dst
        protocol = packet[1].proto
        payload = bytes(packet[1]).hex()  # Convert payload to hex format

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "payload": payload
        }
    except IndexError:
        return None

def is_valid_packet(packet):
    """Check if the packet contains valid IP layer."""
    return packet.haslayer('IP')