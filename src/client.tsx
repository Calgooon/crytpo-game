import CryptoJS from 'crypto-js';
import * as ed25519 from '@noble/ed25519';
import { ScoreUpdate, ServerResponse, getServerTime } from './types.js';
import { serverStartGame, serverProcessUpdate } from './server-functions.js';

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
  private _sessionKey: CryptoJS.lib.WordArray;
  private signingKey!: CryptoJS.lib.WordArray;

  constructor(clientPublicKey: Uint8Array, serverPublicKey: string) {
    this._sessionKey = this.deriveSessionKey(clientPublicKey, serverPublicKey);
  }

  setSigningKey(signingKey: CryptoJS.lib.WordArray) {
    this.signingKey = signingKey;
  }

  getSessionKey(): CryptoJS.lib.WordArray {
    return this._sessionKey;
  }

  private deriveSessionKey(clientPublicKey: Uint8Array, serverPublicKey: string): CryptoJS.lib.WordArray {
    const keys = [
      KeyManager.toBase64(clientPublicKey),
      serverPublicKey
    ].sort();
    return CryptoJS.SHA256(keys[0] + keys[1]);
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
      this._sessionKey,
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

// Game client that manages the game session
export class GameClient {
  private keyPair!: { privateKey: Uint8Array; publicKey: Uint8Array };
  private nextKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array } | null = null;
  private sessionCrypto!: SessionCrypto;
  private signingKey!: CryptoJS.lib.WordArray;
  private challengeNonce!: string;
  private readonly sessionToken: string;
  private readonly sessionId: string;
  private serverChallenge: string | null = null;
  private serverPublicKey: string | null = null;

  constructor(sessionToken: string, sessionId: string) {
    this.sessionToken = sessionToken;
    this.sessionId = sessionId;
  }

  // Initialize game session
  async initialize(): Promise<void> {
    this.keyPair = await KeyManager.generateKeyPair();
    const response = await this.startGame();
    this.serverPublicKey = response.sessionKey;
    this.sessionCrypto = new SessionCrypto(this.keyPair.publicKey, response.sessionKey);
    this.signingKey = this.sessionCrypto.decryptKey(response.encryptedSigningKey);
    this.sessionCrypto.setSigningKey(this.signingKey);
    this.challengeNonce = response.challengeNonce;
  }

  // Get current cryptographic state for UI display
  async getCryptoState() {
    const timestamp = getServerTime();
    const payload = { score: 0, timestamp, sessionId: this.sessionId };
    const signature = this.sessionCrypto.signPayload(payload);
    const clientProof = await KeyManager.sign(
      new TextEncoder().encode(this.challengeNonce),
      this.keyPair.privateKey
    );

    return {
      clientPublicKey: KeyManager.toBase64(this.keyPair.publicKey),
      serverPublicKey: this.serverPublicKey || '',
      sessionKey: CryptoJS.enc.Hex.stringify(this.sessionCrypto.getSessionKey()),
      signingKey: CryptoJS.enc.Hex.stringify(this.signingKey),
      challengeNonce: this.challengeNonce,
      clientProof,
      signature
    };
  }

  private async startGame(): Promise<{ encryptedSigningKey: string; challengeNonce: string; sessionKey: string }> {
    return await serverStartGame(
      this.sessionToken,
      KeyManager.toBase64(this.keyPair.publicKey)
    );
  }

  async prepareScoreUpdate(score: number): Promise<ScoreUpdate> {
    if (!this.nextKeyPair) {
      this.nextKeyPair = await KeyManager.generateKeyPair();
    }

    const timestamp = getServerTime();
    const payload = { score, timestamp, sessionId: this.sessionId };
    const signature = this.sessionCrypto.signPayload(payload);
    const clientProof = await KeyManager.sign(
      new TextEncoder().encode(this.challengeNonce),
      this.keyPair.privateKey
    );

    return {
      score,
      timestamp,
      sessionId: this.sessionId,
      signature,
      clientProof,
      sessionToken: this.sessionToken,
      serverChallenge: this.challengeNonce,
      newClientPublicKey: KeyManager.toBase64(this.nextKeyPair.publicKey),
    };
  }

  async sendScoreUpdate(score: number): Promise<ServerResponse> {
    this.nextKeyPair = await KeyManager.generateKeyPair();
    const update = await this.prepareScoreUpdate(score);
    const response = await serverProcessUpdate(update);

    // Update session state
    this.signingKey = this.sessionCrypto.decryptKey(response.encryptedNewKey);
    this.sessionCrypto.setSigningKey(this.signingKey);
    this.serverChallenge = this.challengeNonce;
    this.challengeNonce = response.newChallengeNonce;
    this.keyPair = this.nextKeyPair;
    this.nextKeyPair = null;

    return response;
  }
} 