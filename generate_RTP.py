from scapy.all import *
from scapy.fields import *
from scapy.packet import *

# Define a custom RTP layer
class RTP(Packet):
    name = "RTP"
    fields_desc = [
        BitField("version", 2, 2),           # RTP version (2 bits)
        BitField("padding", 0, 1),          # Padding (1 bit)
        BitField("extension", 0, 1),        # Extension (1 bit)
        BitField("cc", 0, 4),               # CSRC count (4 bits)
        BitField("marker", 0, 1),           # Marker (1 bit)
        BitField("pt", 0, 7),               # Payload type (7 bits)
        ShortField("sequence", 0),          # Sequence number
        IntField("timestamp", 0),           # Timestamp
        IntField("ssrc", 0),                # Synchronization source
    ]

    def guess_payload_class(self, payload):
        return Raw

# Function to create and send RTP packets
def generate_rtp_packets(target_ip, target_port, num_packets=10, payload_type=96):
    for seq in range(num_packets):
        # Define the RTP header fields
        rtp_packet = RTP(
            version=2,
            padding=0,
            extension=0,
            cc=0,
            marker=0,
            pt=payload_type,
            sequence=seq,
            timestamp=seq * 160,  # Example timestamp increment
            ssrc=0x12345678,      # Example SSRC
        )

        # Add UDP and IP layers
        udp_layer = UDP(sport=2000, dport=target_port)
        ip_layer = IP(src="127.0.0.1", dst=target_ip)

        # Combine the layers and payload
        packet = ip_layer / udp_layer / rtp_packet / Raw(load="RTP payload data")

        # Send the packet
        send(packet, verbose=0)
        print(f"Sent RTP packet {seq + 1}/{num_packets}")

# Example usage
if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with your target IP
    target_port = 3000           # Replace with your target UDP port
    generate_rtp_packets(target_ip, target_port, num_packets=1000, payload_type=96)