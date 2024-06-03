import subprocess
import threading
import os

from project_root.settings import CURRENT_HOST, CURRENT_PORT, SUDO_PASSWORD


def run_tcpdump(port, output_file, password):
    command = f"tcpdump port {port} -w {output_file}"

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


def run_analyzer():
    port = CURRENT_PORT
    current_directory = os.path.dirname(os.path.abspath(__file__))
    output_file = current_directory + "/http_traffic.pcap"
    password = SUDO_PASSWORD
    run_tcpdump(port, output_file, password)



def main():
    run_analyzer()


if __name__ == '__main__':
    main()
