# Crypto Game Security Demo

A demonstration of secure client-server communication in a game context, implementing various cryptographic security measures.

## Features

- Secure client-server communication using Ed25519 signatures
- Session management with key rotation
- Rate limiting and anti-replay protection
- HMAC-based message authentication
- AES encryption for key exchange
- Challenge-response authentication

## Security Measures

1. **Ed25519 Signatures**: Used for client authentication and challenge-response
2. **Session Keys**: Rotated periodically for enhanced security
3. **HMAC Signatures**: Verify message integrity
4. **AES Encryption**: Secure key exchange
5. **Rate Limiting**: Prevents abuse
6. **Timestamp Validation**: Prevents replay attacks
7. **Nonce-based Challenges**: Ensures request freshness

## Getting Started

### Prerequisites

- Node.js (v18 or higher)
- npm

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/crypto-game.git
cd crypto-game
```

2. Install dependencies:
```bash
npm install
```

### Running the Demo

1. Run the tests:
```bash
npm test
```

2. Run the demo:
```bash
npm start
```

## Project Structure

- `client.ts`: Client-side cryptographic operations
- `server.ts`: Server-side game logic and security
- `types.ts`: Shared type definitions
- `index.ts`: Demo implementation
- `crypto.test.ts`: Security test suite

## Security Considerations

- Private keys are stored only in memory
- Keys are rotated during score updates
- No persistent storage of sensitive data
- Rate limiting prevents abuse
- Challenge-response prevents replay attacks

## License

MIT License - see LICENSE file for details 