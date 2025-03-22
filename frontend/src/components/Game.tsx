import React, { useState, useEffect } from 'react';
import CryptoJS from 'crypto-js';
import * as ed25519 from '@noble/ed25519';
import { api } from '../services/api';
import { ScoreUpdate, ServerResponse } from '../types';

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

  constructor(clientPublicKey: Uint8Array, serverPublicKey: string) {
    this.sessionKey = this.deriveSessionKey(clientPublicKey, serverPublicKey);
  }

  setSigningKey(signingKey: CryptoJS.lib.WordArray) {
    this.signingKey = signingKey;
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

export const Game: React.FC = () => {
  const [score, setScore] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sessionData, setSessionData] = useState<{
    signingKey: CryptoJS.lib.WordArray;
    challengeNonce: string;
    sessionKey: CryptoJS.lib.WordArray;
  } | null>(null);
  const [keyPair, setKeyPair] = useState<{ privateKey: Uint8Array; publicKey: Uint8Array } | null>(null);
  const [nextKeyPair, setNextKeyPair] = useState<{ privateKey: Uint8Array; publicKey: Uint8Array } | null>(null);
  const [sessionCrypto, setSessionCrypto] = useState<SessionCrypto | null>(null);

  const startGame = async () => {
    try {
      // Generate client key pair
      const newKeyPair = await KeyManager.generateKeyPair();
      setKeyPair(newKeyPair);
      
      // Start game session
      const sessionToken = 'dummy_jwt';
      const response = await api.startGame(sessionToken, KeyManager.toBase64(newKeyPair.publicKey));
      
      // Set up session crypto
      const crypto = new SessionCrypto(newKeyPair.publicKey, response.sessionKey);
      const signingKey = crypto.decryptKey(response.encryptedSigningKey);
      crypto.setSigningKey(signingKey);
      setSessionCrypto(crypto);
      
      setSessionData({
        signingKey,
        challengeNonce: response.challengeNonce,
        sessionKey: CryptoJS.enc.Base64.parse(response.sessionKey),
      });
      
      setIsPlaying(true);
      setError(null);
    } catch (err) {
      setError('Failed to start game');
      console.error(err);
    }
  };

  const updateScore = async (newScore: number) => {
    if (!sessionData || !isPlaying || !keyPair || !sessionCrypto) return;

    try {
      // Generate next key pair if not exists
      if (!nextKeyPair) {
        const newPair = await KeyManager.generateKeyPair();
        setNextKeyPair(newPair);
      }

      const timestamp = new Date().toISOString();
      const payload = { score: newScore, timestamp, sessionId: 'xyz' };
      const signature = sessionCrypto.signPayload(payload);
      
      // Generate client proof
      const clientProof = await KeyManager.sign(
        new TextEncoder().encode(sessionData.challengeNonce),
        keyPair.privateKey
      );

      const update: ScoreUpdate = {
        sessionToken: 'dummy_jwt',
        sessionId: 'xyz',
        score: newScore,
        timestamp,
        signature,
        clientProof,
        serverChallenge: sessionData.challengeNonce,
        newClientPublicKey: nextKeyPair ? KeyManager.toBase64(nextKeyPair.publicKey) : undefined,
      };

      const response: ServerResponse = await api.updateScore(update);
      
      setScore(newScore);
      
      // Update session state
      if (sessionCrypto) {
        const newSigningKey = sessionCrypto.decryptKey(response.encryptedNewKey);
        sessionCrypto.setSigningKey(newSigningKey);
        setSessionData(prev => prev ? {
          ...prev,
          signingKey: newSigningKey,
          challengeNonce: response.newChallengeNonce,
        } : null);
      }
      
      // Rotate key pairs
      setKeyPair(nextKeyPair);
      setNextKeyPair(null);
    } catch (err) {
      setError('Failed to update score');
      console.error(err);
    }
  };

  return (
    <div className="game-container">
      <h1>Crypto Game</h1>
      
      {error && <div className="error">{error}</div>}
      
      {!isPlaying ? (
        <button onClick={startGame}>Start Game</button>
      ) : (
        <div>
          <div className="score">Score: {score}</div>
          <div className="controls">
            <button onClick={() => updateScore(score + 10)}>+10</button>
            <button onClick={() => updateScore(score + 50)}>+50</button>
            <button onClick={() => updateScore(score + 100)}>+100</button>
          </div>
        </div>
      )}
    </div>
  );
}; 