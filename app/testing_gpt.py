import os
import pyshark
from langchain_community.chat_models import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage
import tiktoken
from app.adapter.log import log_info, log_error
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
openai_api_key = os.getenv('OPENAI_API_KEY')
file_path = os.getenv('FILE_PATH')
model = os.getenv('MODEL')
max_tokens = int(os.getenv('MAX_TOKENS'))


class Packet:
    def __init__(self, number, src_ip, dst_ip, protocol, src_port=None, dst_port=None, length=None, timestamp=None,
                 flags=None):
        self.number = number
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.timestamp = timestamp
        self.flags = flags

    def __str__(self):
        return (f"Packet {self.number}: Source IP {self.src_ip}:{self.src_port}, "
                f"Destination IP {self.dst_ip}:{self.dst_port}, Protocol {self.protocol}, "
                f"Length {self.length}, Timestamp {self.timestamp}, Flags {self.flags}")

def process_packet(file_path):
    log_info(f"Processing file: {file_path}")
    capture = pyshark.FileCapture(file_path, display_filter="ip or tcp or udp")
    packets = []
    for packet in capture:
        try:
            if 'IP' in packet:
                number = packet.number
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.highest_layer
                src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else None
                dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else None
                length = packet.length
                timestamp = packet.sniff_time
                flags = packet.tcp.flags if 'TCP' in protocol else None

                packets.append(Packet(number, src_ip, dst_ip, protocol, src_port, dst_port, length, timestamp, flags))
        except AttributeError:
            log_error(f"AttributeError processing packet: {packet}")
            continue
    capture.close()
    log_info(f"Processed {len(packets)} packets")
    return packets

def get_packet_summaries(packets):
    log_info("Generating packet summaries")
    summaries = []
    for packet in packets:
        summary = (f"Packet {packet.number}: Source IP {packet.src_ip}:{packet.src_port}, "
                   f"Destination IP {packet.dst_ip}:{packet.dst_port}, Protocol {packet.protocol}, "
                   f"Length {packet.length}, Timestamp {packet.timestamp}")
        if packet.flags:
            summary += f", Flags {packet.flags}"
        summaries.append(summary)
    return "\n".join(summaries)

def chunk_summaries(packet_summaries, model=model):
    chunks = []
    current_chunk = []

    for summary in packet_summaries:
        current_chunk.append(summary)
        if count_tokens("\n".join(current_chunk), model=model) > max_tokens:
            chunks.append("\n".join(current_chunk))
            current_chunk = []

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    return chunks

def count_tokens(text, model=model):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(text))

def filter_relevant_packets(packets):
    filtered = [
        packet for packet in packets
        if packet.protocol in ["TCP", "UDP"] and (
                packet.src_ip.startswith("192.168") or packet.dst_ip.startswith("192.168"))
    ]
    return filtered

def network_specialist_interface(file_path, question, model=model):
    packets = process_packet(file_path)
    packet_summaries = get_packet_summaries(packets).split("\n")

    total_tokens = count_tokens("\n".join(packet_summaries), model=model)
    print(f"Total Tokens: {total_tokens}")

    if total_tokens > 4000:
        print("Data exceeds token limit. Chunking summaries...")
        chunks = chunk_summaries(packet_summaries, model=model)
    else:
        chunks = ["\n".join(packet_summaries)]

    llm = ChatOpenAI(
        temperature=0.0,
        model=model,
        openai_api_key=openai_api_key,
    )

    final_response = ""
    for i, chunk in enumerate(chunks):
        print(f"Processing chunk {i + 1}/{len(chunks)}...")
        enhanced_question = (f"Analyze the following network data and answer the question: {question}\n\n"
                             f"Packet Summaries:\n{chunk}")

        messages = [
            SystemMessage(content="You are a network/cybersecurity expert analyzing network packet data."),
            HumanMessage(content=enhanced_question)
        ]

        response = llm(messages)
        final_response += f"Chunk {i + 1} Response:\n{response.content}\n\n"

    return final_response

if __name__ == "__main__":
    print(os.listdir('./data'))
    question = input("Type your question for the network specialist: ")
    answer = network_specialist_interface(file_path, question)
    print(f"Answer from LangChain:\n{answer}")