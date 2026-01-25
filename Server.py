"""
Main entry point for Secure TCP Server.

This file demonstrates usage of the refactored Secure TCP Server library.
"""

from Server import SecureTCPServer


if __name__ == "__main__":
    # Create server instance
    server = SecureTCPServer(
        host="0.0.0.0",
        port=8436,
        use_display=True,  # Use Rich display for UI
    )

    # Initialize (load/generate keys)
    server.initialize()

    # Start server
    server.start()
