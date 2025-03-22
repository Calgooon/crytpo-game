export interface ScoreUpdate {
  sessionToken: string;
  sessionId: string;
  score: number;
  timestamp: string;
  signature: string;
  clientProof: string;
  serverChallenge: string;
  newClientPublicKey?: string;
}

export interface ServerResponse {
  status: 'score_updated';
  encryptedNewKey: string;
  newChallengeNonce: string;
}

export interface GameSession {
  signingKey: CryptoJS.lib.WordArray;
  challengeNonce: string;
  publicKey: Uint8Array;
  score: number;
  status: 'active' | 'completed';
  keyIssuedAt: number;
  lastUpdateTime: number;
  sessionKey: CryptoJS.lib.WordArray;
  nonceCounter: number;
}

export function getServerTime(): string {
  return new Date().toISOString();
} 