import React, { useState, useEffect } from 'react';
import { GameClient } from './client.js';
import { ServerResponse } from './types.js';

const KEY_EXPIRATION_MS = 3000; // 3 seconds

const GameUI: React.FC = () => {
  const [gameClient, setGameClient] = useState<GameClient | null>(null);
  const [score, setScore] = useState<number>(0);
  const [lastResponse, setLastResponse] = useState<ServerResponse | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isUpdating, setIsUpdating] = useState(false);
  const [lastUpdateTime, setLastUpdateTime] = useState<number>(0);
  const [timeUntilNextUpdate, setTimeUntilNextUpdate] = useState<number>(0);
  const [keyExpirationTime, setKeyExpirationTime] = useState<number>(0);
  const [timeUntilKeyExpires, setTimeUntilKeyExpires] = useState<number>(0);
  const [cryptoState, setCryptoState] = useState<{
    clientPublicKey?: string;
    serverPublicKey?: string;
    sessionKey?: string;
    signingKey?: string;
    challengeNonce?: string;
    clientProof?: string;
    signature?: string;
  }>({});

  // Update the countdown timers
  useEffect(() => {
    const timers: NodeJS.Timeout[] = [];

    // Update rate limit countdown
    if (isUpdating && timeUntilNextUpdate > 0) {
      timers.push(
        setInterval(() => {
          setTimeUntilNextUpdate(prev => {
            const newValue = Math.max(0, prev - 1000);
            if (newValue === 0) {
              setIsUpdating(false);
            }
            return newValue;
          });
        }, 1000)
      );
    }

    // Update key expiration countdown
    if (keyExpirationTime > 0) {
      timers.push(
        setInterval(() => {
          const now = Date.now();
          const timeLeft = Math.max(0, keyExpirationTime - now);
          setTimeUntilKeyExpires(Math.ceil(timeLeft / 1000));
        }, 1000)
      );
    }

    return () => timers.forEach(timer => clearInterval(timer));
  }, [isUpdating, timeUntilNextUpdate, keyExpirationTime]);

  const updateCryptoState = async () => {
    if (gameClient) {
      try {
        const state = await gameClient.getCryptoState();
        setCryptoState(state);
      } catch (err) {
        console.error('Failed to get crypto state:', err);
      }
    }
  };

  const initializeGame = async () => {
    try {
      const sessionToken = 'dummy_jwt';
      const sessionId = 'xyz';
      
      const client = new GameClient(sessionToken, sessionId);
      await client.initialize();
      setGameClient(client);
      setIsInitialized(true);
      setError(null);
      setLastUpdateTime(Date.now());
      setKeyExpirationTime(Date.now() + KEY_EXPIRATION_MS);
      
      // Get initial crypto state from the client
      await updateCryptoState();
    } catch (err) {
      setError('Failed to initialize game: ' + (err as Error).message);
    }
  };

  const sendScoreUpdate = async () => {
    if (!gameClient) return;
    
    const now = Date.now();
    const timeSinceLastUpdate = now - lastUpdateTime;
    
    // Check if we need to wait (minimum 500ms between updates)
    if (timeSinceLastUpdate < 500) {
      const waitTime = 500 - timeSinceLastUpdate;
      setTimeUntilNextUpdate(Math.ceil(waitTime / 1000));
      setIsUpdating(true);
      return;
    }

    try {
      setIsUpdating(true);
      const response = await gameClient.sendScoreUpdate(score);
      setLastResponse(response);
      setLastUpdateTime(now);
      setKeyExpirationTime(now + KEY_EXPIRATION_MS);
      setError(null);
      
      // Update crypto state after successful update
      await updateCryptoState();
    } catch (err) {
      setError('Failed to send score update: ' + (err as Error).message);
    } finally {
      setIsUpdating(false);
      setTimeUntilNextUpdate(0);
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-3xl font-bold mb-8 text-center">Blockchain Game Interface</h1>
      
      {!isInitialized ? (
        <button
          onClick={initializeGame}
          className="w-full bg-blue-500 text-white py-3 px-4 rounded-lg hover:bg-blue-600 transition-colors"
        >
          Initialize Game Session
        </button>
      ) : (
        <div className="space-y-6">
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4">Score Update</h2>
            <div className="flex gap-4">
              <input
                type="number"
                value={score}
                onChange={(e) => setScore(Number(e.target.value))}
                className="flex-1 p-2 border rounded"
                placeholder="Enter score"
                disabled={isUpdating}
              />
              <button
                onClick={sendScoreUpdate}
                disabled={isUpdating}
                className={`py-2 px-4 rounded transition-colors ${
                  isUpdating
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-green-500 hover:bg-green-600 text-white'
                }`}
              >
                {isUpdating ? `Wait ${timeUntilNextUpdate}s...` : 'Send Update'}
              </button>
            </div>
            <div className="mt-2 space-y-1">
              <p className="text-sm text-gray-600">
                Note: Updates are rate-limited to 2 per second (minimum 500ms between updates)
              </p>
              <p className="text-sm text-gray-600">
                Signing key expires in: {timeUntilKeyExpires}s
              </p>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4">Cryptographic State</h2>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h3 className="font-medium text-gray-700 mb-2">Client Side</h3>
                  <div className="space-y-2">
                    <div>
                      <label className="text-sm text-gray-600 flex items-center gap-2">
                        Public Key:
                        <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">Sent to Server</span>
                      </label>
                      <pre className="text-xs bg-gray-50 p-2 rounded mt-1 overflow-auto">
                        {cryptoState.clientPublicKey || 'Not set'}
                      </pre>
                    </div>
                    <div>
                      <label className="text-sm text-gray-600 flex items-center gap-2">
                        Signing Key:
                        <span className="text-xs bg-green-100 text-green-800 px-2 py-0.5 rounded">Never Sent</span>
                      </label>
                      <pre className="text-xs bg-gray-50 p-2 rounded mt-1 overflow-auto">
                        {cryptoState.signingKey || 'Not set'}
                      </pre>
                    </div>
                    <div>
                      <label className="text-sm text-gray-600 flex items-center gap-2">
                        Client Proof:
                        <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">Sent to Server</span>
                      </label>
                      <pre className="text-xs bg-gray-50 p-2 rounded mt-1 overflow-auto">
                        {cryptoState.clientProof || 'Not set'}
                      </pre>
                    </div>
                  </div>
                </div>
                <div>
                  <h3 className="font-medium text-gray-700 mb-2">Server Side</h3>
                  <div className="space-y-2">
                    <div>
                      <label className="text-sm text-gray-600 flex items-center gap-2">
                        Public Key:
                        <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">Sent to Client</span>
                      </label>
                      <pre className="text-xs bg-gray-50 p-2 rounded mt-1 overflow-auto">
                        {cryptoState.serverPublicKey || 'Not set'}
                      </pre>
                    </div>
                    <div>
                      <label className="text-sm text-gray-600 flex items-center gap-2">
                        Session Key:
                        <span className="text-xs bg-green-100 text-green-800 px-2 py-0.5 rounded">Never Sent</span>
                      </label>
                      <pre className="text-xs bg-gray-50 p-2 rounded mt-1 overflow-auto">
                        {cryptoState.sessionKey || 'Not set'}
                      </pre>
                    </div>
                    <div>
                      <label className="text-sm text-gray-600 flex items-center gap-2">
                        Challenge Nonce:
                        <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">Sent to Client</span>
                      </label>
                      <pre className="text-xs bg-gray-50 p-2 rounded mt-1 overflow-auto">
                        {cryptoState.challengeNonce || 'Not set'}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
              <div>
                <h3 className="font-medium text-gray-700 mb-2 flex items-center gap-2">
                  Current Signature
                  <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">Sent to Server</span>
                </h3>
                <pre className="text-xs bg-gray-50 p-2 rounded overflow-auto">
                  {cryptoState.signature || 'Not set'}
                </pre>
              </div>
            </div>
            <div className="mt-4 p-4 bg-gray-50 rounded-lg">
              <h4 className="font-medium text-gray-700 mb-2">Legend:</h4>
              <div className="flex gap-4">
                <div className="flex items-center gap-2">
                  <span className="text-xs bg-green-100 text-green-800 px-2 py-0.5 rounded">Never Sent</span>
                  <span className="text-sm text-gray-600">- Kept local only</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">Sent</span>
                  <span className="text-sm text-gray-600">- Transmitted over network</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4">Key Exchange Process</h2>
            <div className="space-y-4">
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-medium text-gray-700 mb-2">1. Initial Key Exchange</h3>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">1</div>
                    <span className="text-sm">Client generates Ed25519 key pair</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">2</div>
                    <span className="text-sm">Server generates Ed25519 key pair</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">3</div>
                    <span className="text-sm">Both sides exchange public keys</span>
                  </div>
                </div>
              </div>

              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-medium text-gray-700 mb-2">2. Session Key Derivation</h3>
                <div className="text-sm space-y-2">
                  <p>Both sides derive the same session key using:</p>
                  <pre className="bg-white p-2 rounded text-xs overflow-auto">
                    sessionKey = SHA256(sorted(clientPublicKey + serverPublicKey))
                  </pre>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center text-green-800 font-bold">1</div>
                    <span>Sort public keys alphabetically</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center text-green-800 font-bold">2</div>
                    <span>Concatenate sorted keys</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center text-green-800 font-bold">3</div>
                    <span>Hash with SHA256</span>
                  </div>
                </div>
              </div>

              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-medium text-gray-700 mb-2">3. Signing Key Exchange</h3>
                <div className="text-sm space-y-2">
                  <p>Server generates and encrypts signing key:</p>
                  <pre className="bg-white p-2 rounded text-xs overflow-auto">
                    encryptedSigningKey = AES-CBC(signingKey, sessionKey, randomIV)
                  </pre>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">1</div>
                    <span>Server generates random signing key</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">2</div>
                    <span>Encrypts with session key using AES-CBC</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">3</div>
                    <span>Client decrypts using derived session key</span>
                  </div>
                </div>
              </div>

              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-medium text-gray-700 mb-2">4. Challenge-Response</h3>
                <div className="text-sm space-y-2">
                  <p>For each score update:</p>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">1</div>
                    <span>Server generates challenge nonce</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">2</div>
                    <span>Client signs nonce with private key</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-800 font-bold">3</div>
                    <span>Server verifies signature with client's public key</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {lastResponse && (
            <div className="bg-white p-6 rounded-lg shadow-md">
              <h2 className="text-xl font-semibold mb-4">Last Response</h2>
              <pre className="bg-gray-50 p-4 rounded overflow-auto">
                {JSON.stringify(lastResponse, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="mt-4 p-4 bg-red-100 text-red-700 rounded-lg">
          {error}
        </div>
      )}
    </div>
  );
};

export default GameUI; 