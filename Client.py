"""
Main entry point for Secure TCP Client.

This file demonstrates usage of the refactored Secure TCP Client library.
"""

import sys
from Client import SecureTCPClient


def main():
    """Main client function."""
    if len(sys.argv) < 3:
        print("Usage: python Client.py <host> <port> [message]")
        print("Example: python Client.py localhost 8436 'Hello Server'")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    message = sys.argv[3] if len(sys.argv) > 3 else "Hello from client!"

    # Create client instance
    client = SecureTCPClient(
        host=host,
        port=port,
        use_display=True,  # Use Rich display for UI
    )

    try:
        # Connect to server
        client.connect()

        # Send message and receive response
        response = client.send_message(message.encode('utf-8'))
        print(f"\nServer response: {response.decode('utf-8')}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        # Disconnect
        client.disconnect()


if __name__ == "__main__":
    main()
