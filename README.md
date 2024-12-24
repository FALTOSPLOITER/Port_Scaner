# Python-Script-for-Port-Scanning

This Python script is designed for network analysis, monitoring, and intrusion detection. It includes functionalities to analyze packet capture files, detect scanning and DDoS attacks, and train a machine learning model for network activity classification.

Key Functionalities:
Analyze Packet Capture Files (analyze_pcap):

Reads .pcap files using PyShark.
Extracts packet details (timestamp, source/destination IP, protocol, length).
Converts the data into a pandas DataFrame for analysis.
Detect Network Scanning (detect_network_scanning):

Identifies ICMP ping requests or SYN packets that indicate network scans.
Monitor Live Network Activity (monitor_live_network):

Monitors packets in real-time using Scapy.
Filters packets involving a specific IP or domain and checks for scanning activity.
Detect DDoS Attacks (detect_ddos):

Counts the number of packets from each IP.
Flags IPs exceeding a defined packet rate threshold.
Train a Machine Learning Model (train_model):

Uses a Random Forest Classifier from scikit-learn.
Processes packet data, encodes protocol labels, and trains a model to classify network activity.
Evaluates performance with a classification report.
Save Reports in Various Formats (save_report):

Outputs analysis results as text, JSON, HTML, and Excel files.
Main Functionality:

Provides a user menu to:
Analyze .pcap files.
Monitor live traffic.
Train models using .pcap data.
Libraries Used:
PyShark and Scapy: For packet capture analysis and real-time monitoring.
Pandas: Data handling and manipulation.
Scikit-learn: Machine learning model training and evaluation.
OS and Time: File and process management.
JSON and Datetime: Handling structured data and timestamps.
Applications:
Network Security: Detect anomalies like scans or potential DDoS attacks.
Traffic Analysis: Gain insights into network traffic patterns.
Machine Learning: Classify network activities based on patterns.
