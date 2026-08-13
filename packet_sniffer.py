import socket
import struct
from datetime import datetime

LOG_FILE = "network_log.txt"


def get_protocol_name(protocol):
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(protocol, str(protocol))


def sniff_packets():
    try:
        raw_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_IP
        )

        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        raw_socket.bind((local_ip, 0))
        raw_socket.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_HDRINCL,
            1
        )

        raw_socket.ioctl(
            socket.SIO_RCVALL,
            socket.RCVALL_ON
        )

        print("=== Network Packet Sniffer ===")
        print("Listening for packets...")
        print("Press Ctrl+C to stop.\n")

        packet_count = 0

        with open(LOG_FILE, "a") as log:
            log.write("\n--- Packet Sniffer Session ---\n")
            log.write(f"Started: {datetime.now()}\n")

            while True:
                packet, address = raw_socket.recvfrom(65535)

                ip_header = packet[0:20]

                iph = struct.unpack(
                    "!BBHHHBBH4s4s",
                    ip_header
                )

                protocol = iph[6]
                source_ip = socket.inet_ntoa(iph[8])
                destination_ip = socket.inet_ntoa(iph[9])

                protocol_name = get_protocol_name(protocol)

                packet_count += 1

                line = (
                    f"Packet {packet_count}: "
                    f"{source_ip} -> {destination_ip} | "
                    f"Protocol: {protocol_name}"
                )

                if protocol == 6 or protocol == 17:
                    transport_header = packet[20:40]

                    if len(transport_header) >= 4:
                        source_port, destination_port = struct.unpack(
                            "!HH",
                            transport_header[:4]
                        )

                        line += (
                            f" | Source Port: {source_port}"
                            f" | Destination Port: {destination_port}"
                        )

                print(line)
                log.write(line + "\n")

    except PermissionError:
        print("Error: Administrator privileges are required.")

    except KeyboardInterrupt:
        print("\nSniffing stopped.")

    except Exception as error:
        print(f"Error: {error}")

    finally:
        try:
            raw_socket.ioctl(
                socket.SIO_RCVALL,
                socket.RCVALL_OFF
            )
            raw_socket.close()
        except:
            pass


if __name__ == "__main__":
    sniff_packets()