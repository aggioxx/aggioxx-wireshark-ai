import pyshark


def process_packet(file_path):
    capture = pyshark.FileCapture(file_path)
    return capture


if __name__ == "__main__":
    file_path = '../data/slow.pcapng'
    file = process_packet(file_path)
    print(file)