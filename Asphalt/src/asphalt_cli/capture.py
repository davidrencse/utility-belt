"""
CLI commands for packet capture.
"""
import click
import time
import sys
from typing import Optional

@click.command()
@click.option('--interface', '-i', required=True, help='Interface to capture from')
@click.option('--duration', '-d', type=int, help='Duration in seconds (default: run until Ctrl+C)')
@click.option('--filter', '-f', help='BPF filter (e.g., "tcp port 80")')
def capture(interface: str, duration: Optional[int], filter: Optional[str]):
    """
    Start packet capture.
    
    Examples:
      asphalt capture -i "Ethernet" -d 60 -f "tcp port 80"
    """
    # Import from capture module (in same src directory)
    try:
        # These should work since src is in sys.path
        from capture.scapy_backend import ScapyBackend
        from capture.icapture_backend import CaptureConfig
    except ImportError as e:
        click.echo(f"Error importing capture modules: {e}", err=True)
        sys.exit(1)
    
    # Create capture backend
    try:
        capture_backend = ScapyBackend()
    except Exception as e:
        click.echo(f"Error initializing scapy backend: {e}", err=True)
        click.echo("\nFor packet capture on Windows:", err=True)
        click.echo("1. Install NpCap from https://npcap.com/", err=True)
        click.echo("2. Choose 'WinPcap API-compatible mode'", err=True)
        click.echo("3. Reboot if prompted", err=True)
        sys.exit(1)
    
    # List interfaces if requested
    if interface == 'list':
        click.echo("Available interfaces:")
        interfaces = capture_backend.list_interfaces()

        if interfaces:
            click.echo("\n=== Network Interfaces ===")
            for iface in interfaces:
                display_name = iface.get('display_name', iface['name'])
                desc = iface.get('description', '')

                # Truncate long GUIDs for display
                if len(display_name) > 30 and 'NPF_' in display_name:
                    display_name = desc if desc and desc != iface['name'] else f"...{display_name[-20:]}"

                status = "UP" if iface.get('is_up', True) else "DOWN"

                click.echo(f"  {status} {display_name:30}")
                if iface.get('ips'):
                    click.echo(f"      IPs: {', '.join(iface['ips'])}")
                click.echo(f"      Use: asphalt capture --interface \"{iface['name']}\"")

        if not interfaces:
            click.echo("\nNo real interfaces found.")
            click.echo("Note: Interface names are GUIDs like \\Device\\NPF_{...}")
            click.echo("      Use the exact name shown above for capture.")

        return

    # Create config
    config = CaptureConfig(
        interface=interface,
        filter=filter,
        buffer_size=10000
    )
    
    # Start capture
    try:
        session_id = capture_backend.start(config)
        click.echo(f"Capture started on '{interface}' (session: {session_id})")
        if filter:
            click.echo(f"Filter: {filter}")
        if duration:
            click.echo(f"Duration: {duration} seconds")
        click.echo("Press Ctrl+C to stop\n")
    except Exception as e:
        click.echo(f"Error starting capture: {e}", err=True)
        sys.exit(1)
    
    # Display header
    click.echo(f"{'Time':6} {'Pkts/s':8} {'Total':10} {'Drops':8}")
    click.echo("-" * 40)
    
    # Capture loop
    start_time = time.time()
    last_display = start_time
    
    try:
        while True:
            # Check duration
            if duration and (time.time() - start_time) >= duration:
                click.echo(f"\nDuration reached ({duration}s), stopping...")
                break
            
            # Update display every 0.5 seconds
            current_time = time.time()
            if current_time - last_display >= 0.5:
                stats = capture_backend.get_stats(session_id)
                elapsed = current_time - start_time
                
                click.echo(f"\r{elapsed:5.1f}s {stats['packets_per_sec']:8} "
                         f"{stats['packets_total']:10} {stats['drops_total']:8}", 
                         nl=False)
                last_display = current_time
            
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        click.echo("\n\nStopping capture...")
    except Exception as e:
        click.echo(f"\nError during capture: {e}", err=True)
    finally:
        # Stop capture
        metadata = capture_backend.stop(session_id)
        
        # Display summary
        click.echo("\n" + "=" * 50)
        click.echo("CAPTURE SUMMARY")
        click.echo("=" * 50)
        click.echo(f"Session ID:    {metadata['session_id']}")
        click.echo(f"Interface:     {metadata['interface']}")
        click.echo(f"Duration:      {metadata['end_ts'] - metadata['start_ts']:.2f}s")
        click.echo(f"Total Packets: {metadata['stats_summary']['packets_total']}")
        click.echo(f"Total Bytes:   {metadata['stats_summary']['bytes_total']:,}")
        click.echo(f"Packet Drops:  {metadata['stats_summary']['drops_total']}")
