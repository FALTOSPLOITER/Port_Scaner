import socket

# Function to scan a single port
def scan_port(host, port):
    try:
        # Creating a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        # Attempting to connect to the port
        result = sock.connect_ex((host, port))
        
        # Checking if the connection is successful
        if result == 0:
            print(f"Port {port} is OPEN")
        else:
            print(f"Port {port} is CLOSED")
        
        sock.close()
    except socket.error:
        print(f"Unable to connect to port {port}")
        
# Main function to initiate the scan
def scan_ports(host, start_port, end_port):
    for port in range(start_port, end_port+1):
        scan_port(host, port)

# Example usage
target_host = "192.168.1.1"
scan_ports(target_host, 20, 1024)
