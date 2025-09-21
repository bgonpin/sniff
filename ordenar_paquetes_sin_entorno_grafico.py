#!/usr/bin/env python3
"""
Script para leer paquetes de red desde MongoDB y ordenarlos
Requiere: pip install pymongo scapy
"""

from pymongo import MongoClient
from scapy.all import *
import json
from datetime import datetime
from collections import defaultdict

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


def main():
    """Función principal con ejemplo de uso"""
    # Configuración de conexión
    sorter = PacketSorter(
        mongo_uri="mongodb://localhost:27017",
        db_name="network_sniffing"
    )
    
    try:
        # Cargar paquetes
        sorter.load_packets(collection_name="packets", limit=None)  # Ordenar todos los paquetes
        
        # Mostrar estadísticas
        sorter.get_statistics()
        
        print("\n" + "="*50)
        print("ORDENAMIENTO POR TIMESTAMP")
        print("="*50)
        sorter.sort_by_timestamp()
        sorter.print_packet_summary()
        
        print("\n" + "="*50)
        print("ORDENAMIENTO POR SECUENCIA TCP")
        print("="*50)
        sorter.sort_by_tcp_sequence()
        sorter.print_packet_summary()
        
        print("\n" + "="*50)
        print("ORDENAMIENTO POR CONVERSACIÓN")
        print("="*50)
        sorter.sort_by_conversation()
        sorter.print_packet_summary()
        
        # Exportar resultados
        sorter.export_ordered_packets("packets_ordered_by_conversation.json")
        
    except Exception as e:
        print(f"Error: {e}")
        print("Verifica que MongoDB esté ejecutándose y la conexión sea correcta")


if __name__ == "__main__":
    main()
