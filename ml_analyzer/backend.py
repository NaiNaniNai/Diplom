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


def _is_distributed_dataset(ds):
    return isinstance(ds, data_adapter.input_lib.DistributedDatasetSpec)


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
    # data = reader_file(absolute_url_save_directory, save_directory)
    # normal_data = normalize_data(data)
    data_adapter._is_distributed_dataset = _is_distributed_dataset
    # model_loaded = keras.models.load_model(
    #     "ml_analyzer/ml_model/tf_python_keras_model2.h5"
    # )
    #
    # a = model_loaded.predict(normal_data)
    #
    # print(f"Результат: {a}")
    # if a[0][0] > a[0][1]:
    #     label = "Атака"
    # else:
    #     label = "Нормальная активность"
    #
    # writing_in_db(data, label)
    # print("s")


if __name__ == "__main__":
    main()
