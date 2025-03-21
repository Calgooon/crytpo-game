import CryptoJS from 'crypto-js';
const { SHA512 } = CryptoJS;
import * as ed25519 from '@noble/ed25519';
import { GameClient } from './client.js';
import { GameServer } from './server.js';
import { ScoreUpdate } from './types.js';
import { serverProcessUpdate } from './server-functions.js';

// Set up SHA-512 for ed25519 using crypto-js
ed25519.etc.sha512Sync = (...messages) => {
  const message = messages.map(m => Buffer.from(m)).join('');
  return Buffer.from(SHA512(message).toString(), 'hex');
};

async function testCryptoSecurity() {
  console.log('\n=== Starting Crypto Security Tests ===\n');
  
  // Test 1: Invalid Session Token
  console.log('Test 1: Invalid Session Token');
  try {
    const client = new GameClient('invalid_token', 'xyz');
    await client.initialize();
    console.log('❌ Test failed: Should have rejected invalid token');
  } catch (error: any) {
    console.log('✅ Test passed: Invalid token rejected');
  }

  // Test 2: Tampered Score Update
  console.log('\nTest 2: Tampered Score Update');
  const validClient = new GameClient('dummy_jwt', 'xyz');
  await validClient.initialize();
  
  try {
    // Create a valid update but modify the score after signing
    const update = await validClient.prepareScoreUpdate(100);
    const tamperedUpdate: ScoreUpdate = {
      ...update,
      score: 999999 // Modify score after signing
    };
    await serverProcessUpdate(tamperedUpdate);
    console.log('❌ Test failed: Should have rejected tampered score');
  } catch (error: any) {
    console.log('✅ Test passed: Tampered score rejected');
  }

  // Test 3: Replay Attack
  console.log('\nTest 3: Replay Attack');
  try {
    // Capture a valid update
    const update = await validClient.prepareScoreUpdate(200);
    // Try to reuse the same update
    await serverProcessUpdate(update);
    await serverProcessUpdate(update); // Try to reuse the same update
    console.log('❌ Test failed: Should have rejected replayed update');
  } catch (error: any) {
    console.log('✅ Test passed: Replayed update rejected');
  }

  // Test 4: Expired Key
  console.log('\nTest 4: Expired Key');
  try {
    // Wait for key to expire (3.1 seconds)
    await new Promise(resolve => setTimeout(resolve, 3100));
    await validClient.sendScoreUpdate(300);
    console.log('❌ Test failed: Should have rejected expired key');
  } catch (error: any) {
    console.log('✅ Test passed: Expired key rejected');
  }

  // Test 5: Invalid Challenge Nonce
  console.log('\nTest 5: Invalid Challenge Nonce');
  try {
    const update = await validClient.prepareScoreUpdate(400);
    const invalidUpdate: ScoreUpdate = {
      ...update,
      clientProof: 'invalid_proof' // Invalid proof for challenge
    };
    await serverProcessUpdate(invalidUpdate);
    console.log('❌ Test failed: Should have rejected invalid challenge proof');
  } catch (error: any) {
    console.log('✅ Test passed: Invalid challenge proof rejected');
  }

  // Test 6: Rate Limiting
  console.log('\nTest 6: Rate Limiting');
  try {
    // Send updates too quickly
    for (let i = 0; i < 5; i++) {
      await validClient.sendScoreUpdate(500 + i);
      await new Promise(resolve => setTimeout(resolve, 10)); // Too fast
    }
    console.log('❌ Test failed: Should have enforced rate limiting');
  } catch (error: any) {
    console.log('✅ Test passed: Rate limiting enforced');
  }

  // Test 7: Invalid Session Key
  console.log('\nTest 7: Invalid Session Key');
  try {
    const update = await validClient.prepareScoreUpdate(600);
    const invalidUpdate: ScoreUpdate = {
      ...update,
      sessionToken: 'different_session' // Different session
    };
    await serverProcessUpdate(invalidUpdate);
    console.log('❌ Test failed: Should have rejected invalid session');
  } catch (error: any) {
    console.log('✅ Test passed: Invalid session rejected');
  }

  // Test 8: Future Timestamp
  console.log('\nTest 8: Future Timestamp');
  try {
    const update = await validClient.prepareScoreUpdate(700);
    const futureUpdate: ScoreUpdate = {
      ...update,
      timestamp: new Date(Date.now() + 5000).toISOString() // 5 seconds in future
    };
    await serverProcessUpdate(futureUpdate);
    console.log('❌ Test failed: Should have rejected future timestamp');
  } catch (error: any) {
    console.log('✅ Test passed: Future timestamp rejected');
  }

  console.log('\n=== Crypto Security Tests Completed ===\n');
}

// Run the tests
testCryptoSecurity().catch(console.error); 