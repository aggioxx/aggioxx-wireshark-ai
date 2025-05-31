import os
import pyshark
from langchain_community.chat_models import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage
from langchain.chains import ConversationChain
from langchain.memory import ConversationBufferMemory
import tiktoken
from app.adapter.log import log_info, log_error
from dotenv import load_dotenv

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
    return summaries


def count_tokens(text, model=model):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(text))


def chunk_summaries_with_context(packet_summaries, model=model, max_context=max_tokens):
    """
    Chunk packet summaries to ensure no chunk exceeds the max context length, including past messages.
    """
    chunks = []
    current_chunk = []
    context_token_buffer = 1000

    for summary in packet_summaries:
        current_chunk.append(summary)
        if count_tokens("\n".join(current_chunk), model=model) + context_token_buffer > max_context:
            chunks.append("\n".join(current_chunk[:-1]))
            current_chunk = [summary]

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    return chunks


def network_specialist_chat():
    chat_model = ChatOpenAI(
        temperature=0.0,
        model=model,
        openai_api_key=openai_api_key,
    )
    memory = ConversationBufferMemory()
    conversation = ConversationChain(
        llm=chat_model,
        memory=memory
    )

    print("Chat is now live! Type your questions. Type 'exit' to quit.\n")
    while True:
        user_input = input("You: ")
        if user_input.lower() == 'exit':
            print("Exiting chat. Goodbye!")
            break

        try:
            packets = process_packet(file_path)
            packet_summaries = get_packet_summaries(packets)

            chunks = chunk_summaries_with_context(packet_summaries)

            final_response = ""
            for i, chunk in enumerate(chunks):
                memory_size = count_tokens(memory.load_memory_variables({})["history"], model=model)
                if memory_size + count_tokens(chunk, model=model) > max_tokens:
                    memory.clear()

                enhanced_input = (f"Analyze the following network packet data:\n\n{chunk}\n\n"
                                  f"User Question: {user_input}")
                response = conversation.predict(input=enhanced_input)
                final_response += f"Chunk {i + 1} Response:\n{response}\n\n"

            print(f"Bot: {final_response.strip()}\n")
        except Exception as e:
            log_error(f"Error during chat: {e}")
            print("An error occurred during the chat. Check the logs for details.")


if __name__ == "__main__":
    network_specialist_chat()
