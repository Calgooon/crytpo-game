import CryptoJS from 'crypto-js';
import * as ed25519 from '@noble/ed25519';
import { ScoreUpdate, ServerResponse, GameSession, getServerTime } from './types.js';

// Generate random private key using crypto-js
function generatePrivateKey(): Uint8Array {
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

// Helper function to convert base64 to Uint8Array
function base64ToUint8Array(base64: string): Uint8Array {
  const wordArray = CryptoJS.enc.Base64.parse(base64);
  const words = wordArray.words;
  const sigBytes = wordArray.sigBytes;
  const u8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    u8[i] = byte;
  }
  return u8;
}

export class GameServer {
  private sessionData: Map<string, GameSession>;
  private readonly keyExpirationMs = 3000; // 3 seconds
  private readonly maxScoreDelta = 100; // Maximum score increase per update
  private readonly maxUpdatesPerSecond = 30; // Rate limiting
  private readonly updateWindowMs = 1000; // 1 second window for rate limiting

  constructor() {
    this.sessionData = new Map();
  }

  // Verify JWT and extract session ID
  private verifyJwt(sessionToken: string): { sessionId: string } {
    // For demo purposes, we'll do a simple validation
    if (sessionToken !== 'dummy_jwt') {
      throw new Error('Invalid session token');
    }
    return { sessionId: 'xyz' };
  }

  // Generate a cryptographically secure nonce
  private generateNonce(sessionId: string): string {
    const session = this.sessionData.get(sessionId);
    if (!session) throw new Error('Session not found');
    
    const counter = session.nonceCounter++;
    const timestamp = Date.now();
    const random = CryptoJS.lib.WordArray.random(8);
    
    const nonceData = CryptoJS.enc.Utf8.parse(sessionId)
      .concat(CryptoJS.enc.Utf8.parse(counter.toString()))
      .concat(CryptoJS.enc.Utf8.parse(timestamp.toString()))
      .concat(random);
    
    return CryptoJS.SHA256(nonceData).toString();
  }

  // Encrypt a key using the session key
  private encryptKey(key: CryptoJS.lib.WordArray, sessionKey: CryptoJS.lib.WordArray): string {
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(key, sessionKey, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });
    
    return CryptoJS.enc.Base64.stringify(iv.concat(encrypted.ciphertext));
  }

  // Handle game start
  async startGame(sessionToken: string, clientPublicKey: string): Promise<{ encryptedSigningKey: string; challengeNonce: string; sessionKey: string }> {
    const { sessionId } = this.verifyJwt(sessionToken);
    const signingKey = CryptoJS.lib.WordArray.random(32);
    const serverPrivateKey = generatePrivateKey();
    const serverPublicKey = await ed25519.getPublicKey(serverPrivateKey);
    const serverPublicKeyBase64 = CryptoJS.enc.Base64.stringify(CryptoJS.lib.WordArray.create(serverPublicKey));
    
    // Generate session key using deterministic method
    // Sort the keys to ensure consistent order on both sides
    const keys = [clientPublicKey, serverPublicKeyBase64].sort();
    const sessionKey = CryptoJS.SHA256(keys[0] + keys[1]);
    
    const now = Date.now();
    // Create session first
    this.sessionData.set(sessionId, {
      signingKey,
      challengeNonce: '', // Temporary value
      publicKey: base64ToUint8Array(clientPublicKey),
      score: 0,
      status: 'active',
      keyIssuedAt: now,
      lastUpdateTime: now,
      sessionKey,
      nonceCounter: 0
    });

    // Now generate the nonce
    const challengeNonce = this.generateNonce(sessionId);
    
    // Update the session with the nonce
    const session = this.sessionData.get(sessionId);
    if (session) {
      session.challengeNonce = challengeNonce;
    }

    const encryptedSigningKey = this.encryptKey(signingKey, sessionKey);
    return { encryptedSigningKey, challengeNonce, sessionKey: serverPublicKeyBase64 };
  }

  // Process score update
  async processUpdate(update: ScoreUpdate): Promise<ServerResponse> {
    const { sessionId } = this.verifyJwt(update.sessionToken);
    const session = this.sessionData.get(sessionId);

    if (!session || session.status !== 'active') {
      throw new Error('Session invalid or completed');
    }

    // Rate limiting check - minimum 33ms between updates (about 30 fps)
    const now = Date.now();
    const timeSinceLastUpdate = now - session.lastUpdateTime;
    if (timeSinceLastUpdate < 33) { // Allow roughly 30 updates per second
      throw new Error('Rate limit exceeded - updates too frequent');
    }

    // Check key expiration (3 seconds)
    const timeSinceKeyIssued = now - session.keyIssuedAt;
    if (timeSinceKeyIssued > 3000) {
      throw new Error('Signing key expired');
    }

    // Verify timestamp (±1 second)
    const serverTime = new Date(getServerTime()).getTime();
    const clientTime = new Date(update.timestamp).getTime();
    if (Math.abs(serverTime - clientTime) > 1000) {
      throw new Error('Timestamp out of sync');
    }

    // Verify HMAC signature
    const payloadString = JSON.stringify({ score: update.score, timestamp: update.timestamp, sessionId });
    const expectedSignature = CryptoJS.HmacSHA256(payloadString, session.signingKey).toString();
    if (expectedSignature !== update.signature) {
      throw new Error('Invalid signature');
    }

    // Verify Client Proof
    const clientProofBytes = new Uint8Array(CryptoJS.enc.Hex.parse(update.clientProof).sigBytes);
    const words = CryptoJS.enc.Hex.parse(update.clientProof).words;
    for (let i = 0; i < clientProofBytes.length; i++) {
      clientProofBytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    const challengeBytes = new TextEncoder().encode(session.challengeNonce);
    const isProofValid = await ed25519.verify(
      clientProofBytes,
      challengeBytes,
      session.publicKey
    );
    if (!isProofValid) {
      throw new Error('Invalid client proof');
    }

    // Verify server challenge matches the current challenge nonce
    if (update.serverChallenge !== session.challengeNonce) {
      throw new Error('Invalid server challenge');
    }

    // Update score and state
    session.score = update.score;
    session.signingKey = CryptoJS.lib.WordArray.random(32);
    session.challengeNonce = this.generateNonce(sessionId);
    session.lastUpdateTime = now;
    session.keyIssuedAt = now;

    // Update Client Public Key if provided
    if (update.newClientPublicKey) {
      session.publicKey = base64ToUint8Array(update.newClientPublicKey);
    }

    const encryptedNewKey = this.encryptKey(session.signingKey, session.sessionKey);

    if (update.score === 1000) {
      session.status = 'completed';
    }

    return { status: 'score_updated', encryptedNewKey, newChallengeNonce: session.challengeNonce };
  }

  getScore(sessionId: string): number {
    return this.sessionData.get(sessionId)?.score || 0;
  }
} 