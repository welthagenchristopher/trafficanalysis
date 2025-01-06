import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, IFACES, Ether
from datetime import datetime
import threading
import logging
import ipaddress
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self, local_network_range: str):
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = []
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.local_network = ipaddress.IPv4Network(local_network_range, strict=False)

    def get_protocol_name(self, protocol_num: int) -> str:
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def is_local_ip(self, ip: str) -> str:
        """Determine if the IP is part of the local network."""
        try:
            return "Local" if ipaddress.IPv4Address(ip) in self.local_network else "External"
        except ipaddress.AddressValueError:
            return "Invalid"

    def process_packet(self, packet, interface: str) -> None:
        try:
            if IP in packet:
                with self.lock:
                    source_mac = packet[Ether].src if Ether in packet else "Unknown"
                    connection_type = self.is_local_ip(packet[IP].src)

                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds(),
                        'interface': interface,
                        'source_mac': source_mac,
                        'connection_type': connection_type,
                    }

                    if TCP in packet:
                        packet_info.update({
                            'src_port': int(packet[TCP].sport),
                            'dst_port': int(packet[TCP].dport),
                            'tcp_flags': str(packet[TCP].flags),
                        })

                    elif UDP in packet:
                        packet_info.update({
                            'src_port': int(packet[UDP].sport),
                            'dst_port': int(packet[UDP].dport),
                        })

                    self.packet_data.append(packet_info)

                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def get_dataframe(self) -> pd.DataFrame:
        with self.lock:
            if not self.packet_data:
                return pd.DataFrame(columns=[
                    'timestamp', 'source', 'destination', 'protocol', 'size',
                    'time_relative', 'interface', 'source_mac', 'connection_type'
                ])
            return pd.DataFrame(self.packet_data)


class PacketCaptureThread:
    def __init__(self, processor: PacketProcessor, interface: str):
        self.processor = processor
        self.interface = interface
        self.thread = None
        self.stop_event = threading.Event()

    def start(self):
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.thread.start()
        logger.info(f"Packet capture started on interface: {self.interface}")

    def stop(self):
        if self.thread and self.thread.is_alive():
            self.stop_event.set()
            self.thread.join(timeout=2)
            logger.info(f"Packet capture stopped on interface: {self.interface}")

    def _capture_packets(self):
        try:
            logger.info(f"Starting sniffing on interface: {self.interface}")
            sniff(
                iface=self.interface,
                prn=lambda pkt: self.processor.process_packet(pkt, self.interface),
                store=False,
                stop_filter=lambda pkt: self.stop_event.is_set(),
            )
        except PermissionError:
            logger.error("Permission denied. Run the script as root or with elevated privileges.")
        except Exception as e:
            logger.error(f"Error sniffing on interface {self.interface}: {e}")


def main():
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-Time Network Traffic Analysis")

    # Sidebar: Interface selection and refresh rate
    with st.sidebar:
        refresh_rate = st.slider("Refresh Rate (seconds)", 1, 10, 2)

        # Filter interfaces with valid IPs
        interface_options = {
            iface.name: iface
            for iface in IFACES.data.values()
            if getattr(iface, "ip", None) and not iface.ip.startswith("169.254") and "lo" not in iface.name.lower()
        }
        if not interface_options:
            st.error("No valid network interfaces found.")
            return

        default_interface = next((name for name in interface_options if 'wifi' in name.lower()), list(interface_options.keys())[0])
        interface_selection = st.selectbox("Select Network Interface", list(interface_options.keys()), index=list(interface_options.keys()).index(default_interface))

    selected_iface = interface_options[interface_selection]
    logger.info(f"Selected interface: {selected_iface.name} (IP: {selected_iface.ip})")

    if "capture_thread" not in st.session_state or st.session_state.current_interface != interface_selection:
        if "capture_thread" in st.session_state and st.session_state.capture_thread:
            st.session_state.capture_thread.stop()
        
        local_network_range = str(ipaddress.ip_network(f"{selected_iface.ip}/24", strict=False))
        st.session_state.processor = PacketProcessor(local_network_range)
        st.session_state.capture_thread = PacketCaptureThread(st.session_state.processor, selected_iface.name)
        st.session_state.capture_thread.start()
        st.session_state.current_interface = interface_selection

    # Placeholders for metrics, data, and protocol chart
    metrics_placeholder = st.empty()
    data_placeholder = st.empty()
    protocol_chart_placeholder = st.empty()

    def apply_style(row):
        if row['connection_type'] == 'Local':
            return ['background-color: green'] * len(row)
        else:
            return [""] * len(row)

    while True:
        # Fetch the latest data from the processor
        df = st.session_state.processor.get_dataframe()

        df = df.iloc[::-1]
        styleddf = df.style.apply(apply_style, axis=1) # apply green to local!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

        # Update metrics
        with metrics_placeholder.container():
            if df.empty:
                st.warning("No packets captured yet.")
            else:
                st.metric("Total Packets", len(df))
                st.metric("Capture Duration (s)", (datetime.now() - st.session_state.processor.start_time).total_seconds())

        # Update packet data
        with data_placeholder.container():
            if not df.empty:
                st.subheader("Packet Data")
                st.dataframe(styleddf, use_container_width=True)

        # Update protocol chart
        with protocol_chart_placeholder.container():
            if not df.empty:
                protocol_counts = df["protocol"].value_counts()
                st.plotly_chart(
                    px.pie(
                        names=protocol_counts.index,
                        values=protocol_counts.values,
                        title="Protocol Distribution",
                    )
                )

        # Pause for refresh rate without blocking the interface
        time.sleep(refresh_rate)


if __name__ == "__main__":
    main()
