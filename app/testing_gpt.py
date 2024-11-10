import pyshark
from openai import OpenAI

client = OpenAI(
    api_key="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",
)

class Packet:
    def __init__(self, number, src_ip, dst_ip, protocol, raw_data):
        self.number = number
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.raw_data = raw_data

    def __str__(self):
        return f"Packet {self.number}: Source IP {self.src_ip}, Destination IP {self.dst_ip}, Protocol {self.protocol}"


# Function to process packets from a .pcap file and return list of Packet objects
def process_packet(file_path):
    capture = pyshark.FileCapture(file_path)
    packets = []
    for packet in capture:
        if 'IP' in packet:
            number = packet.number
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.highest_layer
            raw_data = str(packet)[:512]  # Truncate raw data to avoid exceeding context length
            packets.append(Packet(number, src_ip, dst_ip, protocol, raw_data))
    capture.close()
    return packets


# Summarize packets for easier OpenAI processing
def get_packet_summaries(packets):
    summaries = []
    for packet in packets:
        summary = f"Packet {packet.number}: Source IP {packet.src_ip}, Destination IP {packet.dst_ip}, Protocol {packet.protocol}"
        summaries.append(summary)
    return "\n".join(summaries)


# Main function to interact with OpenAI's API
def network_specialist_interface(file_path, question):
    # Process .pcap file to get packet summaries
    packets = process_packet(file_path)
    packet_summaries = get_packet_summaries(packets)

    # Construct enhanced question for OpenAI model
    enhanced_question = f"Analyze the following network data and answer the question: {question}\n\nPacket Summaries:\n{packet_summaries}"

    # Send the packet summaries and question to OpenAI's GPT-4 model
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert analyzing network packet data."},
            {"role": "user", "content": enhanced_question}
        ]
    )

    # Extract response text
    answer = response
    print("Response:", answer)
    return answer


# Main interactive loop
if __name__ == "__main__":
    file_path = '../data/redline.pcap'  # Update with the actual path to your .pcap file
    question = input("Enter your question about the network (e.g., 'What anomalies are present?'): ")
    answer = network_specialist_interface(file_path, question)
    print(f"Answer: {answer}")