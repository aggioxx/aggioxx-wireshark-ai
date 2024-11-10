# import pyshark
#
# class Packet:
#     def __init__(self, number, src_ip, dst_ip, protocol, raw_data):
#         self.number = number
#         self.src_ip = src_ip
#         self.dst_ip = dst_ip
#         self.protocol = protocol
#         self.raw_data = raw_data
#
#     def __str__(self):
#         return f"Packet {self.number}: Source IP {self.src_ip}, Destination IP {self.dst_ip}, Protocol {self.protocol}"
#
# def process_packet(file_path):
#     capture = pyshark.FileCapture(file_path)
#     packets = []
#     for packet in capture:
#         if 'IP' in packet:
#             number = packet.number
#             src_ip = packet.ip.src
#             dst_ip = packet.ip.dst
#             protocol = packet.highest_layer
#             raw_data = str(packet)
#             packets.append(Packet(number, src_ip, dst_ip, protocol, raw_data))
#     capture.close()
#     return packets
#
# file_path = '../data/redline.pcap'
# packets = process_packet(file_path)
# for packet in packets:
#     print(packet)

import torch
print("GPU available:", torch.cuda.is_available())
print("GPU name:", torch.cuda.get_device_name(0) if torch.cuda.is_available() else "No GPU")
