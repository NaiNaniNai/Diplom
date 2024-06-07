import subprocess
import threading
import os
from datetime import datetime

from scapy.layers.inet import IP, TCP, UDP

from project_root.settings import CURRENT_PORT, SUDO_PASSWORD
from scapy.all import rdpcap


def run_tcpdump(port, output_file, password):
    command = f"tcpdump -i any port {port} -w {output_file}"

    def tcpdump_process():
        try:
            process = subprocess.Popen(
                ["sudo", "-S"] + command.split(),
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=True,
            )
            process.communicate(password + "\n")
        except Exception as e:
            print(f"Произошла ошибка при запуске tcpdump: {e}")

    thread = threading.Thread(target=tcpdump_process)
    thread.daemon = True
    thread.start()


def run_analyzer(output_file):
    port = CURRENT_PORT
    password = SUDO_PASSWORD
    run_tcpdump(port, output_file, password)


def reader_file(absolute_url_save_directory, save_directory):
    for file in os.listdir(absolute_url_save_directory):
        file_path = os.path.join(absolute_url_save_directory, file)
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            print("Файл пуст!")
        else:
            packets = rdpcap(file_path)

            num_packets = len(packets)
            num_bytes = sum(len(packet) for packet in packets)
            start_time = packets[0].time
            end_time = packets[-1].time
            duration = end_time - start_time
            packet_rate = num_packets / duration
            inter_arrival_times = sum(
                [packets[i + 1].time - packets[i].time for i in range(num_packets - 1)]
            )

            data = []

            for packet in packets:
                packet_info = {
                    "packet_size": len(packet),
                    "duration": packet.time - start_time,
                    "src_port": None,
                    "dst_port": None,
                    "protocol": None,
                    "src_ip": None,
                    "dst_ip": None,
                }

                if IP in packet:
                    packet_info["src_ip"] = packet[IP].src
                    packet_info["dst_ip"] = packet[IP].dst
                    if TCP in packet:
                        packet_info["protocol"] = "TCP"
                        packet_info["src_port"] = packet[TCP].sport
                        packet_info["dst_port"] = packet[TCP].dport
                    elif UDP in packet:
                        packet_info["protocol"] = "UDP"
                        packet_info["src_port"] = packet[UDP].sport
                        packet_info["dst_port"] = packet[UDP].dport

                data.append(packet_info)
                return {
                    "packet_rate": packet_rate,
                    "inter_arrival_times": inter_arrival_times,
                    "num_packets": num_packets,
                    "num_bytes": num_bytes,
                    "duration": duration,
                    "packet_data": data,
                }


def main():
    current_directory = os.path.dirname(os.path.abspath(__file__))
    pcap_files_directory = "pcap_files/"
    date = datetime.date(datetime.now())
    daily_save_directory = pcap_files_directory + f"{date}/"
    time = datetime.time(datetime.now()).replace(microsecond=0)
    save_directory = daily_save_directory
    absolute_url_save_directory = current_directory + "/" + save_directory

    file = "/" + save_directory + f"{time}_http_traffic.pcap"
    output_file = current_directory + file

    if not os.path.exists(absolute_url_save_directory):
        os.makedirs(absolute_url_save_directory)

    run_analyzer(output_file)
    a = reader_file(absolute_url_save_directory, save_directory)
    print(a)


if __name__ == "__main__":
    main()
