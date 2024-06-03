import subprocess
import threading
import os
from datetime import datetime

from project_root.settings import CURRENT_HOST, CURRENT_PORT, SUDO_PASSWORD
from scapy.all import rdpcap


def run_tcpdump(port, output_file, password):
    command = f"tcpdump -i any port {port} -w {output_file}"

    def tcpdump_process():
        try:
            process = subprocess.Popen(
                ['sudo', '-S'] + command.split(),
                stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True
            )
            process.communicate(password + '\n')
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
            print(packets)
    # packets = rdpcap(absolute_url_save_directory+"16:32:08_http_traffic.pcap")


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

    # run_analyzer(output_file)
    reader_file(absolute_url_save_directory, save_directory)


if __name__ == '__main__':
    main()
