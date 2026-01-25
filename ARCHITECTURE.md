# Secure TCP Communication Library - Architecture Documentation

## Overview

This library provides a production-ready implementation of secure TCP communication using hybrid cryptography:
- **RSA-2048** for secure key exchange
- **AES-GCM** (256-bit) for symmetric encryption of all subsequent communications

The architecture follows clean architecture principles with clear separation of concerns, making it maintainable, testable, and extensible.

---

## Architecture Components

### Server Architecture

The server implementation consists of five distinct layers:

#### 1. **Transport Layer** (`Server/transport.py`)
- **Responsibility**: Low-level socket operations and network I/O
- **Class**: `TCPServerTransport`
- **Key Features**:
  - Socket binding and listening
  - Connection acceptance and management
  - Graceful shutdown handling
  - Pure I/O operations with no business logic

#### 2. **Cryptographic Layer** (`Server/crypto.py`)
- **Responsibility**: All cryptographic operations
- **Classes**:
  - `KeyManager`: RSA key pair generation, loading, and persistence
  - `AESGCMHandler`: AES-GCM encryption and decryption operations
- **Key Features**:
  - Automatic key generation and file-based persistence
  - Symmetric encryption/decryption with authenticated encryption
  - Nonce management for AES-GCM
  - Comprehensive error handling with custom exceptions

#### 3. **Protocol Layer** (`Server/protocol.py`)
- **Responsibility**: Secure communication protocol implementation
- **Classes**:
  - `HandshakeHandler`: Manages RSA key exchange and AES key establishment
  - `MessageHandler`: Handles encrypted message exchange
- **Key Features**:
  - Complete handshake protocol implementation
  - Message encryption/decryption flow management
  - Callback support for custom message processing
  - Protocol-level error handling

#### 4. **Display Layer** (`Server/display.py`)
- **Responsibility**: User interface presentation (optional, reusable)
- **Class**: `ServerDisplay`
- **Key Features**:
  - Rich console utilities using the `rich` library
  - Reusable across different server implementations
  - Can be disabled for headless/logging-only deployments
  - Consistent UI formatting and styling

#### 5. **Main Server** (`Server/server.py`)
- **Responsibility**: High-level orchestration and coordination
- **Class**: `SecureTCPServer`
- **Key Features**:
  - Composes all architectural layers
  - Explicit state management
  - Comprehensive error handling and logging
  - Clean public API

### Client Architecture

The client implementation mirrors the server architecture with client-specific adaptations:

#### 1. **Transport Layer** (`Client/transport.py`)
- **Responsibility**: Client-side socket operations
- **Class**: `TCPClientTransport`
- **Key Features**:
  - Connection establishment
  - Send/receive operations
  - Connection state management
  - Graceful disconnection

#### 2. **Cryptographic Layer** (`Client/crypto.py`)
- **Responsibility**: Client-side cryptographic operations
- **Classes**:
  - `AESGCMHandler`: AES-GCM encryption/decryption (shared with server)
  - `KeyExchange`: Handles RSA public key loading and AES key encryption
- **Key Features**:
  - AES key generation
  - RSA public key loading and validation
  - RSA-encrypted AES key transmission
  - Symmetric encryption/decryption

#### 3. **Protocol Layer** (`Client/protocol.py`)
- **Responsibility**: Client-side protocol implementation
- **Classes**:
  - `HandshakeHandler`: Manages client-side handshake (receive public key, encrypt and send AES key)
  - `MessageHandler`: Handles encrypted message exchange
- **Key Features**:
  - Complete handshake protocol from client perspective
  - Message send/receive with automatic encryption/decryption
  - Callback support for custom message processing

#### 4. **Display Layer** (`Client/display.py`)
- **Responsibility**: Client UI presentation (optional, reusable)
- **Class**: `ClientDisplay`
- **Key Features**:
  - Rich console utilities
  - Client-specific UI formatting
  - Optional display mode

#### 5. **Main Client** (`Client/client.py`)
- **Responsibility**: High-level client orchestration
- **Class**: `SecureTCPClient`
- **Key Features**:
  - Simplified connection API
  - Automatic handshake on connect
  - Message send/receive abstraction
  - State management

---

## SOLID Principles Implementation

### Single Responsibility Principle (SRP)
Each class has a single, well-defined responsibility:
- `KeyManager` exclusively handles key lifecycle management
- `AESGCMHandler` exclusively handles symmetric encryption/decryption
- `HandshakeHandler` exclusively manages the handshake protocol
- `MessageHandler` exclusively manages message exchange
- `TCPServerTransport` / `TCPClientTransport` exclusively handle network I/O

### Open/Closed Principle (OCP)
The architecture supports extension without modification:
- Message callbacks allow custom message processing without modifying core classes
- Display layer can be swapped or extended
- Transport layer can be replaced with alternative implementations
- Protocol handlers can be extended with additional features

### Liskov Substitution Principle (LSP)
Interfaces are consistent and replaceable:
- Logger callbacks follow consistent function signatures
- Display components can be substituted with alternative implementations
- Transport abstractions allow for different network implementations

### Interface Segregation Principle (ISP)
Interfaces are small and focused:
- Optional dependencies (display, logger) reduce coupling
- Minimal public APIs expose only necessary functionality
- Internal implementation details are properly encapsulated

### Dependency Inversion Principle (DIP)
High-level modules depend on abstractions:
- Dependencies are injected via constructors
- No hard-coded dependencies on concrete implementations
- Logging and display are optional and injectable

---

## Key Design Decisions

### 1. No Side Effects in Constructors
- **Rationale**: Constructors should only initialize object state, not perform I/O or complex operations
- **Implementation**: `initialize()` method separates initialization from construction
- **Benefit**: Easier testing, clearer error handling, better resource management

### 2. Explicit State Management
- **Rationale**: Clear state transitions prevent invalid operations
- **Implementation**: 
  - Keys must be initialized before use
  - Connection state is explicitly tracked
  - Running state is managed explicitly
- **Benefit**: Prevents runtime errors from invalid state

### 3. Comprehensive Error Handling
- **Rationale**: Proper error handling improves debuggability and user experience
- **Implementation**:
  - Custom exception hierarchy with clear inheritance
  - Proper exception chaining with `from` clause
  - No print-based error reporting
- **Benefit**: Errors are catchable, loggable, and testable

### 4. Logging-Ready Design
- **Rationale**: Production systems require proper logging
- **Implementation**:
  - Standard Python `logging` module integration
  - Optional Rich display for development
  - Can run headless with logging only
- **Benefit**: Flexible deployment options, production-ready

### 5. Complete Type Hints
- **Rationale**: Type hints improve code quality and developer experience
- **Implementation**: Full type annotations throughout the codebase
- **Benefit**: Better IDE support, static analysis, self-documenting code

### 6. Private Implementation Details
- **Rationale**: Clear separation between public API and implementation
- **Implementation**: Internal methods prefixed with `_`
- **Benefit**: Clear public API, prevents misuse, easier refactoring

---

## Usage Examples

### Server Usage

```python
from Server import SecureTCPServer

# Create server instance
server = SecureTCPServer(
    host="0.0.0.0",
    port=8436,
    use_display=True,  # Optional Rich UI
)

# Initialize (load/generate keys)
server.initialize()

# Start server (blocks until shutdown)
server.start()
```

### Client Usage

```python
from Client import SecureTCPClient

# Create client instance
client = SecureTCPClient(
    host="localhost",
    port=8436,
    use_display=True,  # Optional Rich UI
)

# Connect to server (performs handshake automatically)
client.connect()

# Send message and receive response
response = client.send_message(b"Hello, Server!")
print(response.decode('utf-8'))

# Disconnect
client.disconnect()
```

### Advanced Usage with Custom Message Handler

```python
from Server import SecureTCPServer

def custom_message_handler(message: bytes) -> bytes:
    # Custom processing logic
    processed = message.upper()
    return processed

server = SecureTCPServer(
    host="0.0.0.0",
    port=8436,
    message_callback=custom_message_handler,
)
server.initialize()
server.start()
```

---

## Module Structure

```
Callcp/
├── Server/                    # Server package
│   ├── __init__.py           # Package exports
│   ├── exceptions.py         # Custom exception hierarchy
│   ├── crypto.py             # Cryptographic operations
│   ├── protocol.py           # Protocol handlers
│   ├── transport.py          # Transport layer
│   ├── display.py            # Reusable Rich display utilities
│   └── server.py             # Main server class
│
├── Client/                    # Client package
│   ├── __init__.py           # Package exports
│   ├── exceptions.py         # Custom exception hierarchy
│   ├── crypto.py             # Cryptographic operations
│   ├── protocol.py           # Protocol handlers
│   ├── transport.py          # Transport layer
│   ├── display.py            # Reusable Rich display utilities
│   └── client.py             # Main client class
│
├── Server.py                  # Server entry point
├── Client.py                  # Client entry point
└── ARCHITECTURE.md           # This document
```

---

## Security Considerations

1. **Key Management**: RSA keys are stored in PEM format without encryption. In production, consider additional key protection mechanisms.

2. **Key Exchange**: The handshake uses RSA-OAEP with SHA-256 for secure key exchange.

3. **Symmetric Encryption**: AES-256-GCM provides authenticated encryption, ensuring both confidentiality and integrity.

4. **Nonce Management**: Each encrypted message uses a unique random nonce, preventing replay attacks.

5. **Connection Security**: The protocol provides end-to-end encryption but does not include authentication of endpoints. Consider adding certificate-based authentication for production use.

---

## Dependencies

- `cryptography`: Cryptographic primitives (RSA, AES-GCM)
- `rich`: Optional console UI enhancements

---

## Version

Current version: **1.0.0**

---

## License

[Specify license here]

---

## Author

Created by @Adedev-W (github)
