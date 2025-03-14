import asyncio
import logging
import sys
from accumulate.api.client import AccumulateClient
from accumulate.models.service import FindServiceOptions

# Enable logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("MetricsServicesSnapshotsDemo")

ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
    
async def demo_metrics():
    """Demonstrates retrieving network metrics such as TPS (transactions per second)."""
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    try:
        logger.info(" Fetching network metrics...")
        metrics_data = await client.metrics()

        print("\n Network Metrics:")
        for key, value in metrics_data.items():
            print(f"  {key}: {value}")

    except Exception as e:
        logger.error(f" Error fetching metrics: {e}")

    finally:
        await client.close()


async def demo_find_services():
    """Demonstrates finding services available on the Accumulate network."""
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    try:
        logger.info(" Searching for available services...")

        # Define service options (excluding None fields)
        options_dict = {"network": "MainNet"}  # No timeout if not required

        # Request available services
        services = await client.find_service(FindServiceOptions(**options_dict))

        if services:
            print("\n Found Services:")
            for service in services:
                print(f"   Peer ID: {service.peer_id}")
                print(f"   Status: {service.status}")
                print(f"   Addresses: {', '.join(service.addresses) if service.addresses else 'No addresses'}")
                print("-" * 40)
        else:
            print("\n No services found.")

    except Exception as e:
        logger.error(f" Error finding services: {e}")

    finally:
        await client.close()


async def demo_list_snapshots():
    """Demonstrates retrieving a list of available blockchain snapshots."""
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    try:
        logger.info(" Fetching blockchain snapshots...")

        # Correct JSON-RPC method name
        snapshots = await client.list_snapshots()

        if snapshots:
            print("\n Available Snapshots:")
            for snapshot in snapshots:
                print(f"   Snapshot ID: {snapshot.get('id', 'Unknown')}")
                print(f"   Created At: {snapshot.get('created', 'Unknown')}")
                print(f"   Size: {snapshot.get('size', 'Unknown')} bytes")
                print("-" * 40)
        else:
            print("\n No snapshots available.")

    except Exception as e:
        logger.error(f" Error fetching snapshots: {e}")

    finally:
        await client.close()


async def main():
    """Runs the selected demo function based on user input."""
    if len(sys.argv) < 2:
        print("\n Missing argument! Usage:")
        print("   python examples/metrics_services_snapshots_demo.py [metrics|services|snapshots]\n")
        return

    demo_type = sys.argv[1].lower()

    if demo_type == "metrics":
        await demo_metrics()
    elif demo_type == "services":
        await demo_find_services()
    elif demo_type == "snapshots":
        await demo_list_snapshots()
    else:
        print("\n Invalid argument! Use one of:")
        print("   python examples/metrics_services_snapshots_demo.py metrics")
        print("   python examples/metrics_services_snapshots_demo.py services")
        print("   python examples/metrics_services_snapshots_demo.py snapshots\n")


if __name__ == "__main__":
    asyncio.run(main())
