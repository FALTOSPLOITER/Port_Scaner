import pyshark
import scapy.all as scapy
import pandas as pd
import json
import os
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from datetime import datetime

# Function to analyze Wireshark capture file (.pcap)
def analyze_pcap(file_path):
    cap = pyshark.FileCapture(file_path)
    packets = []

    for packet in cap:
        packet_info = {
            'timestamp': packet.sniff_time,
            'src_ip': packet.ip.src if 'IP' in packet else None,
            'dst_ip': packet.ip.dst if 'IP' in packet else None,
            'protocol': packet.highest_layer,
            'length': packet.length
        }
        packets.append(packet_info)
    
    # Convert packets data to DataFrame
    df = pd.DataFrame(packets)
    print(df.head())  # Preview
    return df

# Function to detect network scanning activity (ICMP and SYN packets)
def detect_network_scanning(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        if packet.haslayer(scapy.ICMP):  # Detect ICMP ping requests (ping flood)
            print(f"Ping flood detected from {ip_src} to {ip_dst}")
        elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':  # SYN packet (scan)
            print(f"TCP SYN scan detected from {ip_src} to {ip_dst}")

# Function to monitor live network activity
def monitor_live_network(ip_or_domain):
    print(f"Monitoring network for IP/Domain: {ip_or_domain}")
    
    def packet_callback(packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            if ip_or_domain in [ip_src, ip_dst]:
                print(f"Packet Detected: {packet.summary()}")
                detect_network_scanning(packet)
    
    scapy.sniff(prn=packet_callback, store=0, timeout=60)

# Function to check for DDoS by analyzing high packet rates from a source IP
def detect_ddos(packets, threshold=100):
    ip_counts = {}
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            if ip_src not in ip_counts:
                ip_counts[ip_src] = 0
            ip_counts[ip_src] += 1
    
    for ip, count in ip_counts.items():
        if count > threshold:
            print(f"Potential DDoS detected from IP: {ip} with {count} packets.")

# Function to train a machine learning model on network data
def train_model(df):
    # Preprocessing the data (Encode labels if necessary)
    df = df.dropna()
    label_encoder = LabelEncoder()
    df['protocol'] = label_encoder.fit_transform(df['protocol'])

    X = df.drop(columns=['timestamp', 'src_ip', 'dst_ip'])
    y = df['protocol']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train RandomForest model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred)
    print("Model Performance Report:")
    print(report)
    return report

# Function to save report in various formats
def save_report(report, file_name):
    # TXT Report
    with open(f"{file_name}.txt", "w") as txt_file:
        txt_file.write(report)
    
    # JSON Report
    report_json = {
        'date': str(datetime.now()),
        'report': report
    }
    with open(f"{file_name}.json", "w") as json_file:
        json.dump(report_json, json_file)
    
    # HTML Report
    with open(f"{file_name}.html", "w") as html_file:
        html_file.write(f"<html><body><pre>{report}</pre></body></html>")

    # Excel Report using Pandas DataFrame
    df_report = pd.DataFrame([{'Report': report}])
    df_report.to_excel(f"{file_name}.xlsx", index=False)

    print(f"Report saved as {file_name} in multiple formats.")

# Main function to handle file uploads and real-time monitoring
def main():
    print("Select an option:")
    print("1. Analyze Wireshark capture file (.pcap)")
    print("2. Monitor live network activity")
    print("3. Train model on network data")
    choice = input("Enter your choice (1/2/3): ")

    if choice == '1':
        file_path = input("Enter path to the .pcap file: ")
        if os.path.exists(file_path):
            df = analyze_pcap(file_path)
            report = train_model(df)
            save_report(report, "network_analysis_report")
        else:
            print("File not found.")
    
    elif choice == '2':
        ip_or_domain = input("Enter the IP address or Domain name to monitor: ")
        monitor_live_network(ip_or_domain)
    
    elif choice == '3':
        # You can either train a model with a pre-collected dataset or with the data from a pcap file
        file_path = input("Enter path to the .pcap file for model training: ")
        if os.path.exists(file_path):
            df = analyze_pcap(file_path)
            report = train_model(df)
            save_report(report, "network_model_report")
        else:
            print("File not found.")
    
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
