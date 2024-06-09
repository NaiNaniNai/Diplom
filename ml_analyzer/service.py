import os
import subprocess
import threading
from datetime import datetime

import numpy as np
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from tensorflow.python import keras
from tensorflow.python.keras.engine import data_adapter

from project_root.settings import CURRENT_PORT, SUDO_PASSWORD


# from ml_analyzer.models import AnalyzedTraffic


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


def normalize_data(data):
    normal_data = []
    numeric_features = [
        float(data["packet_rate"]),
        float(data["inter_arrival_times"]),
        float(data["packet_data"][0]["packet_size"]),
        float(data["duration"]),
        float(data["packet_data"][0]["src_port"]),
        float(data["packet_data"][0]["dst_port"]),
        float(data["num_packets"]),
        float(data["num_bytes"]),
    ]

    categorical_features = [
        hash(data["packet_data"][0]["protocol"]),
        hash(data["packet_data"][0]["src_ip"]),
        hash(data["packet_data"][0]["dst_ip"]),
    ]

    features = numeric_features + categorical_features
    normal_data.append(features)
    normal_data = np.array(normal_data)

    normal_data_mean = np.load("ml_analyzer/ml_model/normal_data_mean.npy")
    normal_data_std = np.load("ml_analyzer/ml_model/normal_data_std.npy")
    normal_data_std[normal_data_std == 0] = 1

    normal_data = (normal_data - normal_data_mean) / normal_data_std
    return normal_data


def _is_distributed_dataset(ds):
    return isinstance(ds, data_adapter.input_lib.DistributedDatasetSpec)


def writing_in_db(data, label):
    data = [
        float(data["packet_rate"]),
        float(data["inter_arrival_times"]),
        float(data["packet_data"][0]["packet_size"]),
        float(data["duration"]),
        data["packet_data"][0]["src_port"],
        data["packet_data"][0]["dst_port"],
        float(data["num_packets"]),
        float(data["num_bytes"]),
        data["packet_data"][0]["protocol"],
        data["packet_data"][0]["src_ip"],
        data["packet_data"][0]["dst_ip"],
        label
    ]
    attrs = ["packet_rate", "inter_arrival_times", "packet_size", "duration", "src_port", "dst_port", "num_packets",
             "num_bytes", "protocol", "src_ip", "dst_ip", "label"]
    data_dict = dict(zip(attrs, data))
    # AnalyzedTraffic.objects.create(**data_dict)
    print(data_dict)


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
    data = reader_file(absolute_url_save_directory, save_directory)
    normal_data = normalize_data(data)
    data_adapter._is_distributed_dataset = _is_distributed_dataset
    model_loaded = keras.models.load_model(
        "ml_analyzer/ml_model/tf_python_keras_model2.h5"
    )

    a = model_loaded.predict(normal_data)

    print(f"Результат: {a}")
    if a[0][0] > a[0][1]:
        label = "Атака"
    else:
        label = "Нормальная активность"

    writing_in_db(data, label)


if __name__ == "__main__":
    main()
