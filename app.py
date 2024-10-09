import sys
import subprocess
import socket
import os
from threading import Thread
from scapy.all import sniff, Ether, IP, ARP
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QListWidget, 
                             QTextEdit, QMessageBox, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter)
from PyQt5.QtGui import QColor, QFont, QPalette
from PyQt5.QtCore import Qt
from datetime import datetime
import netifaces

def is_npcap_installed():
    try:
        result = subprocess.run([r"C:\Program Files\Npcap\CheckStatus.bat"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        try:
            hostname = socket.gethostbyname(ip)
            return hostname
        except socket.gaierror:
            return ip

def ping_ip(ip):
    param = '-n' if os.name == 'nt' else '-c'
    command = ['ping', param, '1', ip]
    return subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def get_local_ip():
    try:
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
    except Exception as e:
        print(f"Error getting local IP: {str(e)}")
    return None

class MyApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.sniffing = False
        self.packets = []
        self.local_ip = get_local_ip()

    def init_ui(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                font-size: 14px;
            }
            QPushButton {
                background-color: #4a4a4a;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #5a5a5a;
            }
            QTableWidget {
                gridline-color: #3a3a3a;
                border: 1px solid #3a3a3a;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                padding: 5px;
                border: 1px solid #2b2b2b;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #3a3a3a;
                font-family: Consolas, monospace;
            }
        """)

        main_layout = QVBoxLayout()

       # ASCII Art Title
        ascii_art = r"""
         ____            _        _     ____       _  __  __           
        |  _ \ __ _  ___| | _____| |_  / ___|  ___(_)/ _|/ _| ___ _ __ 
        | |_) / _` |/ __| |/ / _ \ __| \___ \ / _ \ | |_| |_ / _ \ '__|
        |  __/ (_| | (__|   <  __/ |_   ___) |  __/ |  _|  _|  __/ |   
        |_|   \__,_|\___|_|\_\___|\__| |____/ \___|_|_| |_|  \___|_|   
                                                By Marmik Mewada from India
        """
        title_label = QLabel(ascii_art)
        title_label.setFont(QFont("Courier", 10))
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        self.status_label = QLabel('Checking Npcap installation...')
        main_layout.addWidget(self.status_label)

        if is_npcap_installed():
            self.status_label.setText("Npcap is installed. Ready to start sniffing.")
            
            button_layout = QHBoxLayout()
            self.start_button = QPushButton('Start Sniffing')
            self.start_button.setToolTip("Click to start capturing network packets.")
            self.start_button.clicked.connect(self.start_sniffing)
            button_layout.addWidget(self.start_button)

            self.stop_button = QPushButton('Stop Sniffing')
            self.stop_button.setToolTip("Click to stop capturing packets.")
            self.stop_button.clicked.connect(self.stop_sniffing)
            button_layout.addWidget(self.stop_button)

            main_layout.addLayout(button_layout)

            self.filter_combo = QComboBox()
            self.filter_combo.addItems(["All Packets", "Incoming Packets", "Outgoing Packets"])
            self.filter_combo.setToolTip("Select packet type to display.")
            main_layout.addWidget(self.filter_combo)

            # Use QSplitter for resizable sections
            splitter = QSplitter(Qt.Vertical)

            self.packet_table = QTableWidget(0, 5)
            self.packet_table.setHorizontalHeaderLabels(["Type", "Source", "Destination", "Protocol", "Time"])
            self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            self.packet_table.verticalHeader().setVisible(False)
            self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
            self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.packet_table.itemSelectionChanged.connect(self.show_packet_details)
            splitter.addWidget(self.packet_table)

            self.display_area = QTextEdit()
            self.display_area.setReadOnly(True)
            splitter.addWidget(self.display_area)

            main_layout.addWidget(splitter)

            self.export_button = QPushButton('Export Selected Transactions')
            self.export_button.clicked.connect(self.export_transactions)
            main_layout.addWidget(self.export_button)

            self.stats_label = QLabel("Total Packets: 0")
            main_layout.addWidget(self.stats_label)

        else:
            self.status_label.setText("Npcap is not installed. Please install it manually.")

        self.setLayout(main_layout)
        self.setWindowTitle('Packet Sniffer by Marmik Mewada')
        self.setGeometry(100, 100, 800, 600)
        self.show()

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.status_label.setText("Sniffing started...")
            self.packets.clear()
            self.packet_table.setRowCount(0)
            self.stats_label.setText("Total Packets: 0")
            Thread(target=self.sniff_packets).start()

    def sniff_packets(self):
        def packet_callback(packet):
            if self.sniffing and Ether in packet:
                self.process_packet(packet)

        sniff(prn=packet_callback, store=0)

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.status_label.setText("Sniffing stopped.")

    def show_packet_details(self):
        selected_items = self.packet_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            selected_packet = self.packets[row]
            
            self.display_area.clear()
            self.display_area.append(f"Source: {selected_packet['src']} ({selected_packet['src_mac']})")
            self.display_area.append(f"Destination: {selected_packet['dest']} ({selected_packet['dest_mac']})")
            self.display_area.append(f"Protocol: {selected_packet['protocol']}")
            self.display_area.append(f"Time: {selected_packet['time']}")
            self.display_area.append(f"Raw Packet Data: {selected_packet['raw'].hex()}")

    def export_transactions(self):
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"packet_export_{current_time}.txt"

        selected_items = self.packet_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            selected_packet = self.packets[row]
            src, dest = selected_packet['src'], selected_packet['dest']

            filtered_packets = [p for p in self.packets if p['src'] == src or p['dest'] == dest]

            with open(filename, 'w') as f:
                for packet in filtered_packets:
                    f.write(f"Time: {packet['time']}, "
                            f"Source: {packet['src']} ({packet['src_mac']}), "
                            f"Destination: {packet['dest']} ({packet['dest_mac']}), "
                            f"Protocol: {packet['protocol']}, "
                            f"Raw Data: {packet['raw'].hex()}\n")

            QMessageBox.information(self, "Export Successful", f"Transactions exported to {filename}")
        else:
            QMessageBox.warning(self, "No Selection", "Please select a packet to export transactions.")

    def process_packet(self, packet):
        dest_mac = packet[Ether].dst if Ether in packet else "N/A"
        src_mac = packet[Ether].src if Ether in packet else "N/A"
        protocol = ""

        if IP in packet:
            protocol = "IPv4"
            dest_ip = packet[IP].dst
            src_ip = packet[IP].src
        elif ARP in packet:
            protocol = "ARP"
            dest_ip = packet[ARP].pdst
            src_ip = packet[ARP].psrc
        else:
            dest_ip = src_ip = "N/A"

        dest_hostname = resolve_hostname(dest_ip) if ping_ip(dest_ip) else dest_ip
        src_hostname = resolve_hostname(src_ip) if ping_ip(src_ip) else src_ip

        packet_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        packet_data = {
            'dest': dest_hostname,
            'src': src_hostname,
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'protocol': protocol,
            'raw': bytes(packet),
            'time': packet_time
        }

        self.packets.append(packet_data)

        self.stats_label.setText(f"Total Packets: {len(self.packets)}")

        packet_type = "Outgoing" if src_ip == self.local_ip else "Incoming"
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        
        self.packet_table.setItem(row_position, 0, QTableWidgetItem(packet_type))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(f"{src_hostname} ({src_mac})"))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(f"{dest_hostname} ({dest_mac})"))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(protocol))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(packet_time))

        for col in range(5):
            self.packet_table.item(row_position, col).setBackground(
                QColor(255, 200, 200) if packet_type == "Outgoing" else QColor(200, 255, 200)
            )

    def closeEvent(self, event):
        self.stop_sniffing()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    my_app = MyApp()
    sys.exit(app.exec_())