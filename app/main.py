import pyshark
import torch
from transformers import AutoTokenizer, BertForQuestionAnswering, pipeline
import numpy as np
import os

os.environ["LOKY_MAX_CPU_COUNT"] = "4"
os.environ["CUDA_LAUNCH_BLOCKING"] = "1"
os.environ['TORCH_USE_CUDA_DSA'] = '1'


#device = "cuda" if torch.cuda.is_available() else "cpu"
device = "cpu"
print(f"Using device: {device}")

# Load models and tokenizers on the GPU
secbert_tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecBERT")
secbert_model = BertForQuestionAnswering.from_pretrained("jackaduma/SecBERT", output_hidden_states=True).to(device)
qa_model = BertForQuestionAnswering.from_pretrained("jackaduma/SecBERT").to(device)


#Analyze packets with SecBERT and get embeddings
# def analyze_packet_with_secbert(packet):
#     packet_data = str(packet)
#     inputs = secbert_tokenizer(packet_data, return_tensors="pt", truncation=True, padding=True, max_length=512).to(device)
#     inputs.pop('token_type_ids', None)
#     inputs = {key: val.to(device) for key, val in inputs.items()}
#
#     with torch.no_grad():
#         outputs = secbert_model(**inputs)
#
#     # Calculate embedding and move to CPU for compatibility with scikit-learn
#     embedding = outputs.last_hidden_state.mean(dim=1).squeeze().cpu().numpy()
#
#     # Expanded packet summary
#     summary = f"Packet {packet.number}: Source IP {packet.ip.src}, Destination IP {packet.ip.dst}, "
#     summary += f"Protocol {packet.highest_layer}, "
#     if 'TCP' in packet:
#         summary += f"Source Port {packet.tcp.srcport}, Dest Port {packet.tcp.dstport}, TCP Flags {packet.tcp.flags} | "
#     elif 'UDP' in packet:
#         summary += f"Source Port {packet.udp.srcport}, Dest Port {packet.udp.dstport} | "
#
#     return embedding, summary

#Analyze packets with SecBERT and get embeddings
def analyze_packet_with_secbert(packet):
    packet_data = str(packet)

    # Tokenize and send tensors to the GPU
    inputs = secbert_tokenizer(packet_data, return_tensors="pt", truncation=True, padding='max_length', max_length=512)
    if 'token_type_ids' not in inputs:
        inputs['token_type_ids'] = torch.zeros_like(inputs['input_ids']).to(device)
    inputs = {key: val.to(device) for key, val in inputs.items()}

    with torch.no_grad():
        outputs = secbert_model(**inputs)

    # Move embedding to CPU for KMeans
    last_hidden_state = outputs.hidden_states[-1]
    embedding = last_hidden_state.mean(dim=1).squeeze().cpu().numpy()

    # Generate packet summary
    summary = f"Packet {packet.number}: Source IP {packet.ip.src}, Destination IP {packet.ip.dst}, "
    summary += f"Protocol {packet.highest_layer}, "
    if 'TCP' in packet:
        summary += f"Source Port {packet.tcp.srcport}, Dest Port {packet.tcp.dstport}, TCP Flags {packet.tcp.flags} | "
    elif 'UDP' in packet:
        summary += f"Source Port {packet.udp.srcport}, Dest Port {packet.udp.dstport} | "

    return embedding, summary


# Summarize packets and detect anomalies
def get_secbert_summaries():
    file_path = '../data/redline.pcap'
    capture = pyshark.FileCapture(file_path)

    embeddings = []
    summaries = []

    # Extract embeddings and summaries for each packet
    for packet in capture:
        if 'IP' in packet:
            embedding, summary = analyze_packet_with_secbert(packet)
            embeddings.append(embedding)
            summaries.append(summary)

    capture.close()
    return " ".join(summaries)


# Q&A pipeline for enhanced answers, set to GPU
qa_pipeline = pipeline("question-answering", model=qa_model, tokenizer=secbert_tokenizer, device=0 if device == "cuda" else -1)
hidden_size = qa_pipeline.model.config.hidden_size
qa_pipeline.model.bert.embeddings.token_type_embeddings = torch.nn.Embedding(2, hidden_size)

# Interactive chat function to answer questions
def network_specialist_interface(question):
    # Get summaries and highlight key info
    secbert_summaries = get_secbert_summaries()
    enhanced_question = f"As a network security specialist, provide detailed insights on anomalies and suspicious behavior in the following network packets: {question}"
    if len(secbert_summaries) > 500:
        secbert_summaries = secbert_summaries[:500]

    response = qa_pipeline(question=enhanced_question, context=secbert_summaries)
    print("Response:", response)

    return response["answer"]


# Main interface
if __name__ == "__main__":
    while True:
        question = input("Enter your question (or 'exit' to quit): ")
        if question.lower() == 'exit':
            break
        answer = network_specialist_interface(question)
        print(f"Answer: {answer}")
