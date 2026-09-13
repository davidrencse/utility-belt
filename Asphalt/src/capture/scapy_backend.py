import threading
import queue
import time
from typing import Dict, Any, Optional, List
# Try different import methods
try:
    # Try absolute import
    from capture.icapture_backend import ICaptureBackend, CaptureConfig
except ImportError:
    # Fallback to relative import
    from .icapture_backend import ICaptureBackend, CaptureConfig

try:
    from scapy.all import sniff, get_if_list, get_if_addr, conf, AsyncSniffer
    from scapy.interfaces import NetworkInterface
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class ScapyBackend(ICaptureBackend):
    """Scapy-based capture backend for Windows."""
    
    def __init__(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available. Install with: pip install scapy")
        
        self._sessions: Dict[str, Dict] = {}
        self._lock = threading.RLock()
    
    def list_interfaces(self) -> List[Dict]:
        """List Windows network interfaces using Scapy."""
        if not SCAPY_AVAILABLE:
            return []
        
        interfaces = []
        
        try:
            # Get raw interface GUIDs (what NpCap sees)
            iface_guids = get_if_list()
            
            # Get Windows interface details with human-readable names
            # Try to import Windows-specific function
            try:
                from scapy.arch.windows import get_windows_if_list
                win_ifaces = get_windows_if_list()
                
                # Create mapping from GUID to Windows interface info
                guid_to_wininfo = {}
                for win_iface in win_ifaces:
                    guid = win_iface.get('guid', '')
                    if guid:
                        guid_to_wininfo[guid] = win_iface
                
            except ImportError:
                win_ifaces = []
                guid_to_wininfo = {}
            
            # If Scapy returns no NPF interfaces, fall back to Windows list
            if not iface_guids and win_ifaces:
                for win_iface in win_ifaces:
                    guid = win_iface.get('guid', '')
                    if guid:
                        iface_guids.append(rf"\\Device\\NPF_{guid}")

            for iface_guid in iface_guids:
                try:
                    # Extract GUID from NpCap device name
                    # Format: \Device\NPF_{GUID} or \Device\NPF_Loopback
                    if iface_guid == r'\Device\NPF_Loopback':
                        guid = 'Loopback'
                        description = 'Loopback Interface'
                        is_up = True
                        ips = ['127.0.0.1', '::1']
                        mac = '00:00:00:00:00:00'
                    else:
                        # Extract GUID from \Device\NPF_{GUID}
                        guid_start = iface_guid.find('{')
                        guid_end = iface_guid.find('}')
                        if guid_start != -1 and guid_end != -1:
                            guid = iface_guid[guid_start:guid_end+1]  # Keep braces
                        else:
                            guid = iface_guid
                    
                    # Try to find Windows info for this GUID
                    win_info = guid_to_wininfo.get(guid, {})
                    
                    interface_info = {
                        'id': iface_guid,
                        'name': iface_guid,  # GUID name for capture
                        'display_name': win_info.get('name', iface_guid),  # Human-readable
                        'description': win_info.get('description', iface_guid),
                        'is_up': True,  # Assume up if NpCap can see it
                        'mac': win_info.get('mac', None),
                        'ips': win_info.get('ips', []),
                        'link_type': 'Ethernet',
                        'guid': guid,
                    }
                    
                    # Special handling for loopback
                    if 'Loopback' in iface_guid or '127.0.0.1' in interface_info['ips']:
                        interface_info['link_type'] = 'Loopback'
                        interface_info['display_name'] = 'Loopback'
                        interface_info['description'] = 'Loopback Interface'
                    
                    interfaces.append(interface_info)
                    
                except Exception as e:
                    # Fallback minimal info
                    interfaces.append({
                        'id': iface_guid,
                        'name': iface_guid,
                        'display_name': iface_guid,
                        'description': iface_guid,
                        'is_up': True,
                        'mac': None,
                        'ips': [],
                        'link_type': 'Unknown',
                        'guid': iface_guid,
                    })
        
        except Exception as e:
            print(f"Error listing interfaces: {e}")
            import traceback
            traceback.print_exc()
        
        return interfaces
    
    def start(self, config: CaptureConfig) -> str:
        with self._lock:
            # Generate session ID
            session_id = f"scapy_{int(time.time())}_{hash(config.interface)}"
            
            # DEBUG: Log what we're trying to capture on
            print(f"DEBUG: Starting capture with interface: '{config.interface}'")
            print(f"DEBUG: Filter: '{config.filter}'")
            print(f"DEBUG: Promisc: {config.promisc}")
            
            # Resolve interface name - handle both GUID and human-readable names
            actual_iface_name = config.interface
            # Normalize double-backslash inputs (PowerShell often passes them literally)
            if actual_iface_name.startswith('\\\\'):
                actual_iface_name = actual_iface_name.replace('\\\\', '\\')
            
            # Check if it's already a GUID (starts with \Device\NPF_)
            if not actual_iface_name.startswith(r'\Device\NPF_'):
                # Try to find matching interface by human-readable name
                all_interfaces = self.list_interfaces()
                found_match = False
                
                for iface in all_interfaces:
                    # Check against display name, description, or contains search
                    display_name = iface.get('display_name', '')
                    description = iface.get('description', '')
                    
                    if (config.interface.lower() == display_name.lower() or 
                        config.interface.lower() == description.lower() or
                        config.interface.lower() in description.lower()):
                        
                        actual_iface_name = iface['name']  # Use the GUID name
                        print(f"DEBUG: Mapped '{config.interface}' -> '{actual_iface_name}'")
                        print(f"DEBUG: Description: {description}")
                        found_match = True
                        break
                
                if not found_match:
                    print(f"WARNING: Could not find interface '{config.interface}'")
                    print(f"Available interfaces:")
                    for iface in all_interfaces:
                        if not iface['name'].startswith('dummy'):
                            desc = iface.get('description', iface['name'])
                            print(f"  '{iface['name']}' - {desc}")
            
            # Ensure scapy uses Npcap/pcap backend on Windows
            try:
                conf.use_pcap = True
            except Exception:
                pass
            try:
                conf.sniff_promisc = config.promisc
            except Exception:
                pass
            try:
                conf.iface = actual_iface_name
            except Exception:
                pass

            # Create packet queue
            packet_queue = queue.Queue(maxsize=config.buffer_size)
            stop_event = threading.Event()
            stats = {
                'packets_total': 0,
                'bytes_total': 0,
                'packets_per_sec': 0,
                'bytes_per_sec': 0,
                'drops_total': 0,
                'queue_depth': 0,
                'start_time': time.time(),
                'last_update': time.time(),
                'packets_since_update': 0,
                'bytes_since_update': 0,
                'interface_name': actual_iface_name,  # Store the actual name used
            }
            
            def packet_callback(packet):
                """Callback for each captured packet."""
                nonlocal stats
                
                try:
                    # Convert Scapy packet to our format
                    packet_data = {
                        'ts': packet.time,
                        'data': bytes(packet),
                        'wirelen': len(packet),
                        'scapy_packet': packet,  # Keep for debugging
                    }
                    
                    try:
                        packet_queue.put_nowait(packet_data)
                        stats['packets_since_update'] += 1
                        stats['bytes_since_update'] += len(packet)
                        
                        # DEBUG: First few packets
                        if stats['packets_total'] + stats['packets_since_update'] < 5:
                            print(f"DEBUG: Captured packet {stats['packets_total'] + stats['packets_since_update']}: {len(packet)} bytes")
                            
                    except queue.Full:
                        stats['drops_total'] += 1
                        if stats['drops_total'] % 100 == 0:  # Log every 100 drops
                            print(f"DEBUG: Queue full, drops: {stats['drops_total']}")
                    
                    # Update rate stats every second
                    current_time = time.time()
                    if current_time - stats['last_update'] >= 1.0:
                        stats['packets_per_sec'] = stats['packets_since_update']
                        stats['bytes_per_sec'] = stats['bytes_since_update']
                        stats['packets_total'] += stats['packets_since_update']
                        stats['bytes_total'] += stats['bytes_since_update']
                        stats['queue_depth'] = packet_queue.qsize()
                        stats['packets_since_update'] = 0
                        stats['bytes_since_update'] = 0
                        stats['last_update'] = current_time
                        
                except Exception as e:
                    print(f"Error in packet callback: {e}")
                    import traceback
                    traceback.print_exc()
            
            try:
                # DEBUG: Before starting sniffer
                print(f"DEBUG: Creating AsyncSniffer with interface='{actual_iface_name}'")
                
                # Start Scapy AsyncSniffer
                sniffer = AsyncSniffer(
                    iface=actual_iface_name,
                    prn=packet_callback,
                    filter=config.filter,
                    store=False,  # Don't store in Scapy's memory
                    promisc=config.promisc,
                    monitor=config.monitor,
                    timeout=config.timeout_ms,  # Use config timeout
                )
                
                print(f"DEBUG: Starting sniffer...")
                sniffer.start()
                print(f"DEBUG: Sniffer started successfully")
                
            except Exception as e:
                print(f"ERROR: Failed to start capture on '{actual_iface_name}': {e}")
                print(f"Error type: {type(e).__name__}")
                import traceback
                traceback.print_exc()
                
                # Suggest common fixes
                if "The system cannot find the file specified" in str(e):
                    print("\nTROUBLESHOOTING:")
                    print("1. Make sure NpCap is installed from https://npcap.com/")
                    print("2. Run as Administrator")
                    print("3. Try a different interface name")
                    print("   Use 'asphalt capture --interface list' to see available interfaces")
                
                raise RuntimeError(f"Failed to start capture: {e}")
            
            # Store session
            self._sessions[session_id] = {
                'sniffer': sniffer,
                'queue': packet_queue,
                'stop_event': stop_event,
                'config': config,
                'actual_interface': actual_iface_name,  # Store actual interface used
                'stats': stats,
                'stats_lock': threading.Lock(),
            }
        
        # Start stats updater thread
        def stats_updater():
            """Update stats periodically (backup in case packet_callback fails)."""
            while not stop_event.is_set():
                time.sleep(1)
                with self._lock:
                    if session_id in self._sessions:
                        session = self._sessions[session_id]
                        session_stats = session['stats']
                        session_queue = session['queue']
                        
                        # Update from callback stats (if any)
                        session_stats['queue_depth'] = session_queue.qsize()
                        
                        # If no packets in last 2 seconds, reset pps/bps
                        current_time = time.time()
                        if current_time - session_stats['last_update'] > 2.0:
                            session_stats['packets_per_sec'] = 0
                            session_stats['bytes_per_sec'] = 0
        
        stats_thread = threading.Thread(
            target=stats_updater,
            daemon=True
        )
        stats_thread.start()
        
        print(f"DEBUG: Capture session {session_id} started successfully")
        return session_id
    
    def _stats_updater(self, session_id: str, stop_event: threading.Event):
        """Update stats periodically."""
        while not stop_event.is_set():
            time.sleep(1)
            with self._lock:
                if session_id in self._sessions:
                    session = self._sessions[session_id]
                    stats = session['stats']
                    queue = session['queue']
                    
                    with session['stats_lock']:
                        # Final update of rates
                        stats['packets_per_sec'] = stats['packets_since_update']
                        stats['bytes_per_sec'] = stats['bytes_since_update']
                        stats['packets_total'] += stats['packets_since_update']
                        stats['bytes_total'] += stats['bytes_since_update']
                        stats['queue_depth'] = queue.qsize()
                        stats['packets_since_update'] = 0
                        stats['bytes_since_update'] = 0
                        stats['last_update'] = time.time()
    
    def stop(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session {session_id} not found")
            
            session = self._sessions[session_id]
            
            # Signal stop
            session['stop_event'].set()
            
            # Stop Scapy sniffer
            session['sniffer'].stop()
            
            # Wait for it to stop
            time.sleep(0.5)
            
            # Prepare metadata
            metadata = {
                'session_id': session_id,
                'backend': 'scapy',
                'interface': session['config'].interface,
                'start_ts': session['stats']['start_time'],
                'end_ts': time.time(),
                'config': {
                    'interface': session['config'].interface,
                    'snaplen': session['config'].snaplen,
                    'promisc': session['config'].promisc,
                    'filter': session['config'].filter,
                },
                'stats_summary': session['stats'].copy()
            }
            
            # Remove final queue items
            metadata['stats_summary']['final_queue_size'] = session['queue'].qsize()
            
            # Remove session
            del self._sessions[session_id]
            
            return metadata
    
    def get_stats(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session {session_id} not found")
            
            session = self._sessions[session_id]
            with session['stats_lock']:
                return session['stats'].copy()
    
    def get_packets(self, session_id: str, count: int = 100) -> List[Dict]:
        """Get captured packets from the queue."""
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session {session_id} not found")
            
            session = self._sessions[session_id]
            packets = []
            for _ in range(count):
                try:
                    packets.append(session['queue'].get_nowait())
                except queue.Empty:
                    break
            
            return packets
