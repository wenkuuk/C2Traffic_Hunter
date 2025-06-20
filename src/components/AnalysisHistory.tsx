
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { History, FileText, Download, Trash2, Eye, Calendar } from "lucide-react";
import { format } from "date-fns";

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
}

interface AnalysisHistoryProps {
  onViewResults: (entry: HistoryEntry) => void;
}

const AnalysisHistory: React.FC<AnalysisHistoryProps> = ({ onViewResults }) => {
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [filter, setFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = () => {
    const savedHistory = localStorage.getItem('c2-analysis-history');
    if (savedHistory) {
      setHistory(JSON.parse(savedHistory));
    }
  };

  const clearHistory = () => {
    localStorage.removeItem('c2-analysis-history');
    setHistory([]);
  };

  const deleteEntry = (id: string) => {
    const updatedHistory = history.filter(entry => entry.id !== id);
    setHistory(updatedHistory);
    localStorage.setItem('c2-analysis-history', JSON.stringify(updatedHistory));
  };

  const exportHistory = () => {
    const dataStr = JSON.stringify(history, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `c2-analysis-history-${format(new Date(), 'yyyy-MM-dd')}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getThreatLevelColor = (level: string) => {
    switch (level.toUpperCase()) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM-HIGH': return 'secondary';
      case 'MEDIUM': return 'secondary';
      case 'LOW-MEDIUM': return 'outline';
      case 'LOW': return 'outline';
      default: return 'outline';
    }
  };

  const filteredHistory = history.filter(entry => {
    if (filter === 'all') return true;
    const level = entry.threatLevel.toLowerCase();
    if (filter === 'high') return level === 'critical' || level === 'high';
    if (filter === 'medium') return level.includes('medium');
    if (filter === 'low') return level === 'low' || level === 'low-medium';
    return true;
  });

  const getDetectionSummary = (entry: HistoryEntry) => {
    const { summary } = entry;
    const total = summary.signature_detections + summary.ml_classifications + 
                 summary.beaconing_patterns + summary.behavioral_anomalies;
    return `${total} detections`;
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <History className="h-5 w-5 text-blue-600" />
          Analysis History
        </CardTitle>
        <CardDescription>
          View and manage previously analyzed PCAP files
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Controls */}
          <div className="flex items-center justify-between">
            <Tabs value={filter} onValueChange={(value) => setFilter(value as any)}>
              <TabsList>
                <TabsTrigger value="all">All ({history.length})</TabsTrigger>
                <TabsTrigger value="high">
                  High Risk ({history.filter(h => ['critical', 'high'].includes(h.threatLevel.toLowerCase())).length})
                </TabsTrigger>
                <TabsTrigger value="medium">
                  Medium Risk ({history.filter(h => h.threatLevel.toLowerCase().includes('medium')).length})
                </TabsTrigger>
                <TabsTrigger value="low">
                  Low Risk ({history.filter(h => ['low', 'low-medium'].includes(h.threatLevel.toLowerCase())).length})
                </TabsTrigger>
              </TabsList>
            </Tabs>
            
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={exportHistory} disabled={history.length === 0}>
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
              <Button variant="outline" size="sm" onClick={clearHistory} disabled={history.length === 0}>
                <Trash2 className="h-4 w-4 mr-2" />
                Clear All
              </Button>
            </div>
          </div>

          {/* History Table */}
          {filteredHistory.length > 0 ? (
            <div className="border rounded-lg">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>File Name</TableHead>
                    <TableHead>Date & Time</TableHead>
                    <TableHead>Threat Level</TableHead>
                    <TableHead>Threat Score</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Detections</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredHistory.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <FileText className="h-4 w-4 text-gray-500" />
                          <span className="font-medium">{entry.filename}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2 text-sm text-gray-600">
                          <Calendar className="h-4 w-4" />
                          {format(new Date(entry.timestamp), 'MMM dd, yyyy HH:mm')}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getThreatLevelColor(entry.threatLevel)}>
                          {entry.threatLevel}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono">
                          {(entry.threatScore * 100).toFixed(1)}%
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono">
                          {(entry.confidenceScore * 100).toFixed(1)}%
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm">{getDetectionSummary(entry)}</span>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => onViewResults(entry)}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteEntry(entry.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <History className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p className="text-lg font-medium">No analysis history found</p>
              <p className="text-sm">
                {filter === 'all' 
                  ? 'Upload and analyze PCAP files to see them here'
                  : `No files found for ${filter} risk level`
                }
              </p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default AnalysisHistory;
