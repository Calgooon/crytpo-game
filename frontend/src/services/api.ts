import { ScoreUpdate, ServerResponse } from '../types';

const API_BASE_URL = 'http://localhost:4000/api';

export const api = {
  async startGame(sessionToken: string, clientPublicKey: string) {
    const response = await fetch(`${API_BASE_URL}/start-game`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ sessionToken, clientPublicKey }),
    });
    
    if (!response.ok) {
      throw new Error('Failed to start game');
    }
    
    return response.json();
  },

  async updateScore(update: ScoreUpdate): Promise<ServerResponse> {
    const response = await fetch(`${API_BASE_URL}/update-score`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(update),
    });
    
    if (!response.ok) {
      throw new Error('Failed to update score');
    }
    
    return response.json();
  },

  async getScore(sessionId: string): Promise<{ score: number }> {
    const response = await fetch(`${API_BASE_URL}/score/${sessionId}`);
    
    if (!response.ok) {
      throw new Error('Failed to get score');
    }
    
    return response.json();
  },
}; 