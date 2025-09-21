import sys
import datetime
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QComboBox,
                               QPushButton, QLabel, QTextEdit)
from PySide6.QtCore import QThread, Signal
from scapy.all import get_if_list, AsyncSniffer, PcapWriter, Raw
import pymongo

def packet_to_dict(pkt):
    if pkt is None:
        return None
    d = {'_class': type(pkt).__name__}
    for k, v in pkt.fields.items():
        if isinstance(v, (int, float, str, bool)):
            if isinstance(v, int) and (v > 2**63 - 1 or v < -2**63):
                d[k] = str(v)
            else:
                d[k] = v
        elif isinstance(v, bytes):
            d[k] = v.hex()
        elif hasattr(v, 'fields'):
            d[k] = packet_to_dict(v)
        else:
            d[k] = str(v)
    if pkt.payload:
        d['payload'] = packet_to_dict(pkt.payload)
    if Raw in pkt:
        load = pkt[Raw].load
        try:
            d['data'] = load.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            d['data'] = load.hex()
    return d

class SnifferThread(QThread):
    packet_received = Signal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.sniffer = None
        self.packets = []
        self.pkt_count = 0
        self.writer = None

    def create_new_pcap(self):
        if self.writer:
            self.writer.close()
        start_time = datetime.datetime.now()
        self.filename = start_time.strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"
        self.writer = PcapWriter(self.filename, append=False, sync=True)

    def save_packets(self):
        if not self.packets:
            return
        client = pymongo.MongoClient()
        db = client['network_sniffing']
        collection = db['packets']
        data = []
        for pkt in self.packets:
            pkt_dict = packet_to_dict(pkt)
            pkt_dict['timestamp'] = float(pkt.time)
            pkt_dict['length'] = len(pkt)
            pkt_dict['summary'] = pkt.summary()
            data.append(pkt_dict)
        if data:
            collection.insert_many(data)
        client.close()
        self.packets = []

    def run(self):
        def packet_callback(packet):
            if self.writer is None:
                self.create_new_pcap()
            self.writer.write(packet)
            self.packets.append(packet)
            self.pkt_count += 1
            summary = str(packet.summary())
            self.packet_received.emit(summary)
            if len(self.packets) == 1000:
                self.save_packets()
                self.create_new_pcap()

        self.sniffer = AsyncSniffer(iface=self.interface, prn=packet_callback, store=0)
        self.sniffer.start()

        while not self.isInterruptionRequested():
            if not self.sniffer.running:
                break
            self.msleep(100)

        self.sniffer.stop()
        self.save_packets()
        if self.writer:
            self.writer.close()

class SniffApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Sniffer")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        self.label = QLabel("Select Network Interface:")
        layout.addWidget(self.label)

        self.interface_combo = QComboBox()
        interfaces = get_if_list()
        self.interface_combo.addItems(interfaces)
        layout.addWidget(self.interface_combo)

        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)

        self.packets_text = QTextEdit()
        self.packets_text.setReadOnly(True)
        layout.addWidget(self.packets_text)

        self.setLayout(layout)

        self.sniffer_thread = None
        self.filename = None

    def start_sniffing(self):
        interface = self.interface_combo.currentText()
        if interface:
            self.sniffer_thread = SnifferThread(interface)
            self.sniffer_thread.packet_received.connect(self.display_packet)
            self.sniffer_thread.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.packets_text.clear()

    def stop_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.requestInterruption()
            self.sniffer_thread.wait(5000)  # Wait up to 5 seconds
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def display_packet(self, packet_summary):
        self.packets_text.append(packet_summary)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SniffApp()
    window.show()
    sys.exit(app.exec())
