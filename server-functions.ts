import { GameServer } from './server.js';
import { ScoreUpdate } from './types.js';

// Create a single server instance
const gameServer = new GameServer();

// Server functions
export async function serverStartGame(sessionToken: string, clientPublicKey: string) {
  return gameServer.startGame(sessionToken, clientPublicKey);
}

export async function serverProcessUpdate(update: ScoreUpdate) {
  return gameServer.processUpdate(update);
}

export function getServerScore(sessionId: string): number {
  return gameServer.getScore(sessionId);
} 