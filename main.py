import socket
import subprocess
import re

def get_local_ip():
    try:
        # Cria um socket UDP para conectar a um servidor externo e, em seguida, captura o endereço IP local
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))
        local_ip = temp_socket.getsockname()[0]
        temp_socket.close()
        return local_ip
    except Exception as e:
        print(f"Erro ao obter o endereço IP local: {e}")
        return None

def scan_network(ip_range):
    try:
        result = subprocess.run(["nmap", "-sn", ip_range], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar o Nmap: {e}")
        return ""

def parse_nmap_output(nmap_output):
    parsed_result = []
    lines = nmap_output.strip().split("\n")
    for line in lines:
        if "Nmap scan report" in line:
            ip = line.split()[-1]
        elif "MAC Address: " in line:
            match = re.search(r"MAC Address: ((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}).*? \((.*?)\)", line)
            if match:
                mac_address = match.group(1)
                device_name = match.group(2)
                parsed_result.append((ip, mac_address, device_name))
    return parsed_result

def main():
    local_ip = get_local_ip()
    if local_ip:
        print(f"Seu endereço IP local é: {local_ip}")

        network_prefix = ".".join(local_ip.split(".")[:-1]) + ".0/24"
        print(f"Escaneando a rede {network_prefix}...\n")
        scan_result = scan_network(network_prefix)
        if scan_result:
            print("Dispositivos encontrados na rede:")
            parsed_result = parse_nmap_output(scan_result)
            for ip, mac_address, device_name in parsed_result:
                print(f"{ip} | {mac_address} | {device_name}")

            # Salvando o resultado no arquivo log.txt
            with open("log.txt", "w") as log_file:
                for ip, mac_address, device_name in parsed_result:
                    log_file.write(f"{ip} | {mac_address} | {device_name}\n")
    else:
        print("Não foi possível obter o endereço IP local.")

if __name__ == "__main__":
    main()
