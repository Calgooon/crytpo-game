import express from 'express';
import cors from 'cors';
import CryptoJS from 'crypto-js';
import * as ed25519 from '@noble/ed25519';
import { ScoreUpdate, ServerResponse, GameSession, getServerTime } from './types.js';
import './utils/crypto.js';

// Cryptographic key management
class KeyManager {
  private static generatePrivateKey(): Uint8Array {
    const random = CryptoJS.lib.WordArray.random(32);
    const words = random.words;
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      const word = words[i];
      bytes[i * 4] = (word >>> 24) & 0xff;
      bytes[i * 4 + 1] = (word >>> 16) & 0xff;
      bytes[i * 4 + 2] = (word >>> 8) & 0xff;
      bytes[i * 4 + 3] = word & 0xff;
    }
    return bytes;
  }

  static async generateKeyPair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    const privateKey = this.generatePrivateKey();
    const publicKey = await ed25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
  }

  static async sign(message: Uint8Array, privateKey: Uint8Array): Promise<string> {
    const signature = await ed25519.sign(message, privateKey);
    const wordArray = CryptoJS.lib.WordArray.create(signature);
    return CryptoJS.enc.Hex.stringify(wordArray);
  }

  static toBase64(array: Uint8Array): string {
    const wordArray = CryptoJS.lib.WordArray.create(array);
    return CryptoJS.enc.Base64.stringify(wordArray);
  }
}

// Session cryptography operations
class SessionCrypto {
  private sessionKey: CryptoJS.lib.WordArray;
  private signingKey!: CryptoJS.lib.WordArray;

  constructor(clientPublicKey: Uint8Array, serverPublicKey: Uint8Array) {
    this.sessionKey = this.deriveSessionKey(clientPublicKey, serverPublicKey);
  }

  setSigningKey(signingKey: CryptoJS.lib.WordArray) {
    this.signingKey = signingKey;
  }

  private deriveSessionKey(clientPublicKey: Uint8Array, serverPublicKey: Uint8Array): CryptoJS.lib.WordArray {
    const keys = [
      KeyManager.toBase64(clientPublicKey),
      KeyManager.toBase64(serverPublicKey)
    ].sort();
    return CryptoJS.SHA256(keys[0] + keys[1]);
  }

  encryptKey(key: CryptoJS.lib.WordArray): string {
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(
      CryptoJS.enc.Base64.stringify(key),
      this.sessionKey,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
    
    // Combine IV and encrypted data
    const combined = iv.clone();
    combined.concat(encrypted.ciphertext);
    return CryptoJS.enc.Base64.stringify(combined);
  }

  decryptKey(encryptedKey: string): CryptoJS.lib.WordArray {
    const encryptedBuffer = CryptoJS.enc.Base64.parse(encryptedKey);
    const iv = encryptedBuffer.clone();
    iv.sigBytes = 16;
    iv.clamp();
    
    const encrypted = encryptedBuffer.clone();
    encrypted.words.splice(0, 4);
    encrypted.sigBytes -= 16;
    
    return CryptoJS.AES.decrypt(
      CryptoJS.enc.Base64.stringify(encrypted),
      this.sessionKey,
      {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );
  }

  signPayload(payload: any): string {
    const payloadString = JSON.stringify(payload);
    return CryptoJS.HmacSHA256(payloadString, this.signingKey).toString();
  }
}

class GameServer {
  private sessions: Map<string, GameSession> = new Map();
  private sessionData: Map<string, {
    signingKey: CryptoJS.lib.WordArray;
    challengeNonce: string;
    sessionKey: CryptoJS.lib.WordArray;
    sessionCrypto: SessionCrypto;
  }> = new Map();
  private serverKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array } | null = null;

  constructor() {
    this.initializeServerKeyPair();
  }

  private async initializeServerKeyPair() {
    this.serverKeyPair = await KeyManager.generateKeyPair();
  }

  private verifyJwt(token: string): { sessionId: string } {
    // In production, this would verify a real JWT
    return { sessionId: 'xyz' };
  }

  private generateChallengeNonce(): string {
    return CryptoJS.lib.WordArray.random(32).toString();
  }

  private async verifyClientProof(challengeNonce: string, clientProof: string, clientPublicKey: string): Promise<boolean> {
    if (!this.serverKeyPair) return false;
    
    const challengeBytes = new TextEncoder().encode(challengeNonce);
    const clientPublicKeyBytes = new Uint8Array(atob(clientPublicKey).split('').map(c => c.charCodeAt(0)));
    
    try {
      const proofBytes = new Uint8Array(clientProof.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
      const isValid = await ed25519.verify(
        proofBytes,
        challengeBytes,
        clientPublicKeyBytes
      );
      return isValid;
    } catch (err) {
      console.error('Error verifying client proof:', err);
      return false;
    }
  }

  // Handle game start
  async startGame(sessionToken: string, clientPublicKey: string): Promise<{ encryptedSigningKey: string; challengeNonce: string; sessionKey: string }> {
    const { sessionId } = this.verifyJwt(sessionToken);
    if (!this.serverKeyPair) throw new Error('Server key pair not initialized');

    // Generate signing key
    const signingKey = CryptoJS.lib.WordArray.random(32);
    
    // Set up session crypto
    const clientPublicKeyBytes = new Uint8Array(atob(clientPublicKey).split('').map(c => c.charCodeAt(0)));
    const crypto = new SessionCrypto(clientPublicKeyBytes, this.serverKeyPair.publicKey);
    crypto.setSigningKey(signingKey);
    
    // Encrypt signing key
    const encryptedSigningKey = crypto.encryptKey(signingKey);
    
    // Generate challenge nonce
    const challengeNonce = this.generateChallengeNonce();
    
    // Store session data
    this.sessionData.set(sessionId, {
      signingKey,
      challengeNonce,
      sessionKey: crypto['sessionKey'],
      sessionCrypto: crypto,
    });
    
    return {
      encryptedSigningKey,
      challengeNonce,
      sessionKey: KeyManager.toBase64(this.serverKeyPair.publicKey),
    };
  }

  // Handle score update
  async processUpdate(update: ScoreUpdate): Promise<ServerResponse> {
    const { sessionId } = this.verifyJwt(update.sessionToken);
    const sessionData = this.sessionData.get(sessionId);
    if (!sessionData) throw new Error('Invalid session');

    // Verify client proof
    const isValidProof = await this.verifyClientProof(
      update.serverChallenge || sessionData.challengeNonce,
      update.clientProof,
      update.newClientPublicKey || ''
    );
    if (!isValidProof) throw new Error('Invalid client proof');

    // Verify HMAC signature
    const payload = {
      score: update.score,
      timestamp: update.timestamp,
      sessionId: update.sessionId,
    };
    const expectedSignature = sessionData.sessionCrypto.signPayload(payload);
    if (update.signature !== expectedSignature) {
      throw new Error('Invalid signature');
    }

    // Generate new signing key
    const newSigningKey = CryptoJS.lib.WordArray.random(32);
    sessionData.sessionCrypto.setSigningKey(newSigningKey);
    
    // Encrypt new signing key
    const encryptedNewKey = sessionData.sessionCrypto.encryptKey(newSigningKey);
    
    // Generate new challenge nonce
    const newChallengeNonce = this.generateChallengeNonce();
    
    // Update session data
    this.sessionData.set(sessionId, {
      ...sessionData,
      signingKey: newSigningKey,
      challengeNonce: newChallengeNonce,
    });

    // Update score
    const existingSession = this.sessions.get(sessionId) || {
      signingKey: sessionData.signingKey,
      challengeNonce: sessionData.challengeNonce,
      publicKey: new Uint8Array(),
      status: 'active' as const,
      keyIssuedAt: Date.now(),
      sessionKey: sessionData.sessionKey,
      nonceCounter: 0
    };

    this.sessions.set(sessionId, {
      ...existingSession,
      score: update.score,
      lastUpdateTime: Date.parse(update.timestamp),
    });

    return {
      status: 'success',
      encryptedNewKey,
      newChallengeNonce,
    };
  }

  // Get current score
  getScore(sessionId: string): number {
    return this.sessions.get(sessionId)?.score || 0;
  }
}

const app = express();
const gameServer = new GameServer();

app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.json());

// Start game endpoint
app.post('/api/start-game', async (req, res) => {
  try {
    const { sessionToken, clientPublicKey } = req.body;
    const response = await gameServer.startGame(sessionToken, clientPublicKey);
    res.json(response);
  } catch (error) {
    console.error('Error starting game:', error);
    res.status(400).json({ error: error instanceof Error ? error.message : 'Failed to start game' });
  }
});

// Update score endpoint
app.post('/api/update-score', async (req, res) => {
  try {
    const update: ScoreUpdate = req.body;
    const response = await gameServer.processUpdate(update);
    res.json(response);
  } catch (error) {
    console.error('Error updating score:', error);
    res.status(400).json({ error: error instanceof Error ? error.message : 'Failed to update score' });
  }
});

// Get score endpoint
app.get('/api/score/:sessionId', (req, res) => {
  try {
    const score = gameServer.getScore(req.params.sessionId);
    res.json({ score });
  } catch (error) {
    console.error('Error getting score:', error);
    res.status(400).json({ error: error instanceof Error ? error.message : 'Failed to get score' });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 