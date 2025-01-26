import os
import pyshark
from langchain_community.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import SystemMessage, HumanMessage
from app.adapter.log import log_info, log_error


class Packet:
    def __init__(self, number, src_ip, dst_ip, protocol, src_port=None, dst_port=None, length=None, timestamp=None, flags=None):
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

def network_specialist_interface(file_path, question):
    log_info("Starting network specialist interface")
    packets = process_packet(file_path)
    packet_summaries = get_packet_summaries(packets)

    enhanced_question = (f"Analyze the following network data and answer the question: {question}\n\n"
                         f"Packet Summaries:\n{packet_summaries}")

    llm = ChatOpenAI(
        temperature=0.0,
        model="gpt-3.5-turbo",
        openai_api_key="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",
    )

    messages = [
        SystemMessage(content="You are a network/cybersecurity expert analyzing network packet data."),
        HumanMessage(content=enhanced_question)
    ]

    response = llm(messages)
    log_info("Received response from LangChain")
    return response.content


if __name__ == "__main__":
    file_path = '../data/redline.pcap'
    question = input("Type your question for the network specialist: ")
    answer = network_specialist_interface(file_path, question)
    print(f"Answer from LangChain:\n{answer}")