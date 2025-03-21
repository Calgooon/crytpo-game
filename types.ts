import type CryptoJS from 'crypto-js';

// Shared types between client and server
export interface ScoreUpdate {
  score: number;
  timestamp: string;
  sessionId: string;
  signature: string; // HMAC of payload
  clientProof: string; // Ed25519 signature of challenge nonce
  sessionToken: string;
  serverChallenge?: string; // Dynamic challenge
  newClientPublicKey?: string; // New public key for regeneration
}

export interface ServerResponse {
  status: string;
  encryptedNewKey: string; // Encrypted with client's public key
  newChallengeNonce: string;
}

export interface GameSession {
  signingKey: CryptoJS.lib.WordArray;
  challengeNonce: string;
  publicKey: Uint8Array; // Used with ed25519
  score: number;
  status: 'active' | 'completed';
  keyIssuedAt: number;
  lastUpdateTime: number;  // For rate limiting
  sessionKey: CryptoJS.lib.WordArray;
  nonceCounter: number;
}

// Utility function for server time
export const getServerTime = () => new Date().toISOString(); 