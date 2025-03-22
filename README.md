# Crypto Game

A secure crypto game implementation with React frontend and Express backend.

## Project Structure

```
crypto-game/
├── frontend/           # React frontend application
│   ├── src/           # Frontend source code
│   ├── package.json   # Frontend dependencies
│   └── tsconfig.json  # Frontend TypeScript config
├── backend/           # Express backend application
│   ├── src/          # Backend source code
│   ├── package.json  # Backend dependencies
│   └── tsconfig.json # Backend TypeScript config
└── package.json      # Root package.json for managing both apps
```

## Setup

1. Install dependencies:
```bash
npm run install:all
```

2. Start development servers:
```bash
npm run dev
```

This will start:
- Frontend at http://localhost:3000
- Backend at http://localhost:4000

## Development

- Frontend: React application with TypeScript
- Backend: Express API with TypeScript
- Both applications use TypeScript for type safety

## API Endpoints

### Backend API (http://localhost:4000)

- `POST /api/start-game`: Start a new game session
- `POST /api/update-score`: Update game score
- `GET /api/score/:sessionId`: Get current score for a session

## Security Features

- Cryptographic signatures for score updates
- Rate limiting
- Session management
- Timestamp validation
- Client proof verification

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