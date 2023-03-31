from scapy.all import *
from threading import Thread
import pandas
import time
import os
import sys
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QPushButton

# initialize the networks dataframe that will contain all access points nearby
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
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
        # Set the width of the BSSID column
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 150)

        layout = QVBoxLayout(central_widget)
        layout.addWidget(QLabel("Available Networks:"))
        layout.addWidget(self.table)


        # add start and stop buttons
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)

        # start the channel changer
        self.channel_changer = Thread(target=self.change_channel)
        self.channel_changer.daemon = True

        self.stop_sniff = False

    def start_sniffing(self):
        # start sniffing
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.sniffer = Thread(target=self.sniff_networks)
        self.sniffer.daemon = True
        self.sniffer.start()
        self.channel_changer.start()

    def stop_sniffing(self):
        # stop sniffing
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
                # extract the MAC address of the network
                bssid = packet[Dot11].addr2
                # get the name of it
                ssid = packet[Dot11Elt].info.decode()
                try:
                    dbm_signal = packet.dBm_AntSignal
                except:
                    dbm_signal = "N/A"
                # extract network stats
                stats = packet[Dot11Beacon].network_stats()
                # get the channel of the AP
                channel = stats.get("channel")
                # get the crypto
                crypto = stats.get("crypto")
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
                # update the table
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
            # switch channel from 1 to 14 each 0.5s
            ch = ch % 14 + 1
            time.sleep(0.5)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())