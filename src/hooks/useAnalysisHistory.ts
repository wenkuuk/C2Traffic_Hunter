
import { useState, useCallback } from 'react';

interface HistoryEntry {
  id: string;
  filename: string;
  timestamp: string;
  threatLevel: string;
  threatScore: number;
  confidenceScore: number;
  totalDetections: number;
  summary: {
    signature_detections: number;
    ml_classifications: number;
    beaconing_patterns: number;
    behavioral_anomalies: number;
  };
  fullResults?: any; // Store complete results for viewing later
}

export const useAnalysisHistory = () => {
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  const loadHistory = useCallback(() => {
    const savedHistory = localStorage.getItem('c2-analysis-history');
    if (savedHistory) {
      const parsed = JSON.parse(savedHistory);
      setHistory(parsed);
      return parsed;
    }
    return [];
  }, []);

  const saveToHistory = useCallback((filename: string, results: any) => {
    const historyEntry: HistoryEntry = {
      id: `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      filename,
      timestamp: new Date().toISOString(),
      threatLevel: results.summary.threat_level,
      threatScore: results.summary.threat_score,
      confidenceScore: results.summary.confidence_score,
      totalDetections: results.summary.total_detections,
      summary: results.summary.detection_breakdown,
      fullResults: results
    };

    const currentHistory = loadHistory();
    const updatedHistory = [historyEntry, ...currentHistory].slice(0, 50); // Keep only last 50 entries
    
    setHistory(updatedHistory);
    localStorage.setItem('c2-analysis-history', JSON.stringify(updatedHistory));
    
    return historyEntry;
  }, [loadHistory]);

  const deleteFromHistory = useCallback((id: string) => {
    const currentHistory = loadHistory();
    const updatedHistory = currentHistory.filter((entry: HistoryEntry) => entry.id !== id);
    setHistory(updatedHistory);
    localStorage.setItem('c2-analysis-history', JSON.stringify(updatedHistory));
  }, [loadHistory]);

  const clearHistory = useCallback(() => {
    setHistory([]);
    localStorage.removeItem('c2-analysis-history');
  }, []);

  const getHistoryEntry = useCallback((id: string): HistoryEntry | null => {
    const currentHistory = loadHistory();
    return currentHistory.find((entry: HistoryEntry) => entry.id === id) || null;
  }, [loadHistory]);

  return {
    history,
    loadHistory,
    saveToHistory,
    deleteFromHistory,
    clearHistory,
    getHistoryEntry
  };
};
