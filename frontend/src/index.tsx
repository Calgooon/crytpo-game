import CryptoJS from 'crypto-js';
const { SHA512 } = CryptoJS;
import * as ed25519 from '@noble/ed25519';
import { GameClient } from './client.js';
import { api } from './services/api.js';

// Set up SHA-512 for ed25519 using crypto-js
ed25519.etc.sha512Sync = (...messages) => {
  const message = messages.map(m => {
    if (typeof m === 'string') {
      return new TextEncoder().encode(m);
    }
    return m;
  });
  const concatenated = new Uint8Array(message.reduce((acc, curr) => acc + curr.length, 0));
  let offset = 0;
  for (const m of message) {
    concatenated.set(m, offset);
    offset += m.length;
  }
  return new Uint8Array(CryptoJS.enc.Hex.parse(SHA512(CryptoJS.lib.WordArray.create(concatenated)).toString()).words);
};

// Test the crypto flow
async function testCrypto() {
  const client = new GameClient('dummy_jwt', 'xyz');

  // Start game
  await client.initialize();
  console.log('Game started');
  await new Promise(resolve => setTimeout(resolve, 50)); // Allow rate limit to reset

  // Test rate limiting by sending updates too quickly
  console.log('Testing rate limiting...');
  try {
    // Send 5 updates with minimal delay (should trigger rate limit)
    for (let i = 0; i < 5; i++) {
      const response = await client.sendScoreUpdate(100 + i);
      console.log(`Rapid update ${i + 1}: ${response.status}`);
      await new Promise(resolve => setTimeout(resolve, 10)); // Too fast
    }
  } catch (error: any) {
    console.log('Rate limiting test result:', error.message);
  }

  // Reset client and wait for rate limit to reset
  await client.initialize();
  await new Promise(resolve => setTimeout(resolve, 520)); // Allow rate limit to reset
  
  console.log('\nTesting with proper timing...');
  
  // Now test with proper timing (at least 33ms between updates)
  for (let score = 100; score <= 1000; score += 100) {
    try {
      const response = await client.sendScoreUpdate(score);
      console.log(response)
      console.log(`Score updated to ${score}: ${response.status}`);
      await new Promise(resolve => setTimeout(resolve, 520)); // 50ms delay > 33ms minimum
    } catch (error: any) {
      console.error(`Update failed: ${error.message}`);
      break;
    }
  }

  console.log(`Final score: ${(await api.getScore('xyz')).score}`);
}

// Run the test
testCrypto().catch(console.error); 