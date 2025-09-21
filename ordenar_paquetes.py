#!/usr/bin/env python3
"""
Script para leer paquetes de red desde MongoDB y ordenarlos
Requiere: pip install pymongo scapy pyside6
"""

from pymongo import MongoClient
from scapy.all import *
import json
from datetime import datetime
from collections import defaultdict
import socket
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QComboBox, QVBoxLayout, QHBoxLayout, QWidget, QTextEdit, QPushButton, QMessageBox
from PySide6.QtCore import Qt

class PacketSorter:
    def __init__(self, mongo_uri="mongodb://localhost:27017", db_name="network_sniffing"):
        """
        Inicializar conexión a MongoDB
        
        Args:
            mongo_uri: URI de conexión a MongoDB
            db_name: Nombre de la base de datos
        """
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.packets = []
        self.ip_cache = {}
        
    def load_packets(self, collection_name="packets", limit=None):
        """
        Cargar paquetes desde MongoDB
        
        Args:
            collection_name: Nombre de la colección
            limit: Límite de paquetes a cargar (None = todos)
        """
        collection = self.db[collection_name]
        
        query = collection.find()
        if limit:
            query = query.limit(limit)
            
        self.packets = list(query)
        print(f"Cargados {len(self.packets)} paquetes desde MongoDB")
        
    def sort_by_timestamp(self):
        """Ordenar paquetes por timestamp de captura"""
        self.packets.sort(key=lambda p: p.get('timestamp', 0))
        print("Paquetes ordenados por timestamp")
        
    def sort_by_tcp_sequence(self):
        """Ordenar paquetes TCP por número de secuencia"""
        tcp_packets = [p for p in self.packets if self._is_tcp_packet(p)]
        non_tcp_packets = [p for p in self.packets if not self._is_tcp_packet(p)]

        # Agrupar por flujos TCP (src_ip:src_port -> dst_ip:dst_port)
        flows = defaultdict(list)

        for packet in tcp_packets:
            flow_key = self._get_flow_key(packet)
            flows[flow_key].append(packet)

        # Ordenar cada flujo por número de secuencia
        sorted_tcp = []
        for flow_key, flow_packets in flows.items():
            def get_seq_num(p):
                seq_val = p['payload']['payload'].get('seq', 0)
                if isinstance(seq_val, dict) and '$numberLong' in seq_val:
                    return int(seq_val['$numberLong'])
                elif isinstance(seq_val, int):
                    return seq_val
                else:
                    return 0
            flow_packets.sort(key=get_seq_num)
            sorted_tcp.extend(flow_packets)
            print(f"Flujo {flow_key}: {len(flow_packets)} paquetes ordenados por secuencia TCP")

        self.packets = sorted_tcp + non_tcp_packets
        print(f"Ordenados {len(sorted_tcp)} paquetes TCP por secuencia")
        
    def sort_by_conversation(self):
        """Ordenar por conversación (agrupando ida y vuelta)"""
        tcp_packets = [p for p in self.packets if self._is_tcp_packet(p)]
        non_tcp_packets = [p for p in self.packets if not self._is_tcp_packet(p)]

        conversations = defaultdict(list)

        for packet in tcp_packets:
            conv_key = self._get_conversation_key(packet)
            conversations[conv_key].append(packet)

        # Ordenar cada conversación por timestamp
        sorted_tcp = []
        for conv_key, conv_packets in conversations.items():
            conv_packets.sort(key=lambda p: p.get('timestamp', 0))
            sorted_tcp.extend(conv_packets)
            print(f"Conversación {conv_key}: {len(conv_packets)} paquetes")

        self.packets = sorted_tcp + non_tcp_packets
        print(f"Ordenados por conversación: {len(conversations)} conversaciones")
    
    def _is_tcp_packet(self, packet):
        """Verificar si el paquete es TCP"""
        return (packet.get('payload', {}).get('_class') == 'IP' and 
                packet.get('payload', {}).get('payload', {}).get('_class') == 'TCP')
    
    def _get_flow_key(self, packet):
        """Obtener clave del flujo TCP (unidireccional)"""
        if not self._is_tcp_packet(packet):
            return None
        
        ip_layer = packet['payload']
        tcp_layer = packet['payload']['payload']
        
        return f"{ip_layer['src']}:{tcp_layer['sport']} -> {ip_layer['dst']}:{tcp_layer['dport']}"
    
    def _get_conversation_key(self, packet):
        """Obtener clave de conversación (bidireccional)"""
        if not self._is_tcp_packet(packet):
            return None
        
        ip_layer = packet['payload']
        tcp_layer = packet['payload']['payload']
        
        # Crear clave simétrica para conversación bidireccional
        endpoints = sorted([
            f"{ip_layer['src']}:{tcp_layer['sport']}",
            f"{ip_layer['dst']}:{tcp_layer['dport']}"
        ])
        return f"{endpoints[0]} <-> {endpoints[1]}"
    
    def print_packet_summary(self, max_packets=10):
        """Mostrar resumen de paquetes"""
        print(f"\n--- Resumen de los primeros {min(max_packets, len(self.packets))} paquetes ---")
        
        for i, packet in enumerate(self.packets[:max_packets]):
            timestamp = packet.get('timestamp', 0)
            dt = datetime.fromtimestamp(timestamp)
            
            summary = packet.get('summary', 'N/A')
            
            # Extraer información adicional si es TCP
            extra_info = ""
            if self._is_tcp_packet(packet):
                tcp_layer = packet['payload']['payload']
                seq = tcp_layer.get('seq', {})
                if isinstance(seq, dict) and '$numberLong' in seq:
                    seq_num = int(seq['$numberLong'])
                    extra_info = f" [SEQ: {seq_num}]"
                else:
                    extra_info = f" [SEQ: {seq}]"
            
            print(f"{i+1:3d}. {dt.strftime('%H:%M:%S.%f')[:-3]} - {summary}{extra_info}")
    
    def export_ordered_packets(self, filename="ordered_packets.json"):
        """Exportar paquetes ordenados a archivo JSON"""
        with open(filename, 'w') as f:
            json.dump(self.packets, f, indent=2, default=str)
        print(f"Paquetes exportados a {filename}")
    
    def get_statistics(self):
        """Obtener estadísticas de los paquetes"""
        total = len(self.packets)
        tcp_count = sum(1 for p in self.packets if self._is_tcp_packet(p))
        
        protocols = defaultdict(int)
        for packet in self.packets:
            if packet.get('payload', {}).get('_class') == 'IP':
                proto = packet['payload'].get('proto', 'Unknown')
                protocols[proto] += 1
        
        print(f"\n--- Estadísticas ---")
        print(f"Total de paquetes: {total}")
        print(f"Paquetes TCP: {tcp_count}")
        print(f"Protocolos encontrados:")
        for proto, count in protocols.items():
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Proto-{proto}")
            print(f"  {proto_name}: {count}")

    def resolve_ip(self, ip):
        """Resolver IP a dominio usando DNS reverso, con caché"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        try:
            domain = socket.gethostbyaddr(ip)[0]
            self.ip_cache[ip] = domain
            return domain
        except:
            self.ip_cache[ip] = ip  # Si no se puede resolver, mantener IP
            return ip

    def get_resolved_conversation_key(self, conv_key):
        """Obtener clave de conversación con dominios resueltos"""
        parts = conv_key.split(" <-> ")
        resolved_parts = []
        for part in parts:
            ip_port = part.split(":")
            ip = ip_port[0]
            resolved_ip = self.resolve_ip(ip)
            port = ip_port[1] if len(ip_port) > 1 else ""
            resolved_parts.append(f"{resolved_ip}:{port}")
        return " <-> ".join(resolved_parts)


class PacketAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Analyzer")
        self.setGeometry(100, 100, 800, 600)
        self.sorter = PacketSorter()
        self.initUI()

    def initUI(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Load button
        load_btn = QPushButton("Load Packets from MongoDB")
        load_btn.clicked.connect(self.load_packets)
        layout.addWidget(load_btn)

        # IP selection layout
        ip_layout = QHBoxLayout()
        layout.addLayout(ip_layout)

        ip_layout.addWidget(QLabel("Select Source IP:"))
        self.src_ip_combo = QComboBox()
        self.src_ip_combo.addItem("All")
        ip_layout.addWidget(self.src_ip_combo)

        ip_layout.addWidget(QLabel("Select Destination IP:"))
        self.dst_ip_combo = QComboBox()
        self.dst_ip_combo.addItem("All")
        ip_layout.addWidget(self.dst_ip_combo)

        # Filter and display button
        filter_btn = QPushButton("Filter and Display Conversations")
        filter_btn.clicked.connect(self.display_conversations)
        layout.addWidget(filter_btn)

        # Display area
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)

    def load_packets(self):
        try:
            self.sorter.load_packets(collection_name="packets", limit=None)
            self.update_ip_combos()
            QMessageBox.information(self, "Success", f"Loaded {len(self.sorter.packets)} packets successfully")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load packets: {str(e)}\n\nMake sure MongoDB is running.")

    def update_ip_combos(self):
        src_ips = set()
        dst_ips = set()
        for packet in self.sorter.packets:
            if self.sorter._is_tcp_packet(packet):
                ip_layer = packet['payload']
                src_ips.add(ip_layer['src'])
                dst_ips.add(ip_layer['dst'])

        self.src_ip_combo.clear()
        self.src_ip_combo.addItem("All")
        self.src_ip_combo.addItems(sorted(src_ips, key=socket.inet_aton))

        self.dst_ip_combo.clear()
        self.dst_ip_combo.addItem("All")
        self.dst_ip_combo.addItems(sorted(dst_ips, key=socket.inet_aton))

    def display_conversations(self):
        src_ip = self.src_ip_combo.currentText()
        dst_ip = self.dst_ip_combo.currentText()

        # Filter packets
        filtered_packets = []
        for p in self.sorter.packets:
            if self.sorter._is_tcp_packet(p):
                ip_layer = p['payload']
                src_ok = (src_ip == "All") or (ip_layer['src'] == src_ip)
                dst_ok = (dst_ip == "All") or (ip_layer['dst'] == dst_ip)
                if src_ok and dst_ok:
                    filtered_packets.append(p)
            elif (src_ip == "All") and (dst_ip == "All"):
                filtered_packets.append(p)  # Include non-TCP only if no IP filter

        if not filtered_packets:
            self.text_area.setText("No packets match the filter criteria.")
            return

        # Create temp sorter and sort by conversation
        temp_sorter = PacketSorter()  # Create new instance without MongoDB connection
        temp_sorter.packets = filtered_packets
        temp_sorter.sort_by_conversation()  # Groups into conversations sorted by timestamp within

        # Display conversations
        self.text_area.clear()
        conversations = defaultdict(list)
        for p in temp_sorter.packets:
            if temp_sorter._is_tcp_packet(p):
                conv_key = temp_sorter._get_conversation_key(p)
                conversations[conv_key].append(p)

        def get_seq_num(packet):
            if not temp_sorter._is_tcp_packet(packet):
                return 0
            tcp_layer = packet['payload']['payload']
            seq_val = tcp_layer.get('seq', 0)
            if isinstance(seq_val, dict) and '$numberLong' in seq_val:
                return int(seq_val['$numberLong'])
            elif isinstance(seq_val, int):
                return seq_val
            else:
                return 0

        # Sort conversations by earliest sequence number
        sorted_convs = sorted(conversations.items(), key=lambda x: min(get_seq_num(p) if temp_sorter._is_tcp_packet(p) else 0 for p in x[1]))

        for conv_key, convo_packets in sorted_convs:
            resolved_conv_key = self.sorter.get_resolved_conversation_key(conv_key)
            self.text_area.append(f"Conversation: {resolved_conv_key}\n")
            # Sort packets within conversation by sequence number
            convo_packets.sort(key=get_seq_num)
            for i, p in enumerate(convo_packets, 1):
                seq_num = get_seq_num(p) if self.sorter._is_tcp_packet(p) else 'N/A'
                dt = datetime.fromtimestamp(p.get('timestamp', 0))
                summary = p.get('summary', 'N/A')
                self.text_area.append(f"  {i}. SEQ:{seq_num} {dt.strftime('%H:%M:%S')} - {summary}")
            self.text_area.append("\n")


if __name__ == "__main__":
    app = QApplication([])
    window = PacketAnalyzer()
    window.show()
    app.exec()
