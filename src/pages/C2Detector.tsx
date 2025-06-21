import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Upload, AlertTriangle, Shield, Activity, FileText } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import ThreatAssessmentCard from "@/components/ThreatAssessmentCard";
import AnalysisHistory from "@/components/AnalysisHistory";
import { useAnalysisHistory } from "@/hooks/useAnalysisHistory";

interface EnhancedDetectionResult {
  analysis_timestamp: string;
  summary: {
    total_sessions: number;
    threat_score: number;
    threat_level: string;
    confidence_score: number;
    confidence_level: string;
    component_scores: {
      signature: number;
      ml: number;
      beaconing: number;
      behavioral: number;
    };
    detection_breakdown: {
      signature_detections: number;
      ml_classifications: number;
      beaconing_patterns: number;
      behavioral_anomalies: number;
    };
    risk_factors: {
      persistence: boolean;
      lateral_movement: boolean;
      data_exfiltration: boolean;
      command_control: boolean;
      privilege_escalation: boolean;
      steganography: boolean;
      dns_tunneling: boolean;
    };
    correlation_bonus: number;
    total_detections: number;
    assessment_metadata: {
      active_detection_types: number;
      analysis_version: string;
      timestamp: string;
    };
  };
  detections: {
    signature_detections: Array<{
      session: {
        src_ip: string;
        dst_ip: string;
        host: string;
        path: string;
        method: string;
        user_agent: string;
        timestamp: number;
      };
      score: number;
      matches: string[];
      confidence: number;
    }>;
    ml_classifications: Array<{
      session: {
        src_ip: string;
        dst_ip: string;
        host: string;
        path: string;
      };
      score: number;
      reason: string;
      ml_confidence: number;
      category: string;
    }>;
    beaconing_patterns: Array<{
      host_key: string;
      session_count: number;
      mean_interval: number;
      confidence: number;
      pattern_type: string;
      strength: number;
      duration_hours: number;
      frequency_per_hour: number;
    }>;
    behavioral_anomalies: Array<{
      host_key: string;
      anomaly_type: string;
      confidence: number;
      anomaly_score: number;
      baseline: number;
      current: number;
      z_score: number;
      persistence_hours: number;
    }>;
  };
}

const C2Detector = () => {
  const [file, setFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<EnhancedDetectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [activeTab, setActiveTab] = useState<'upload' | 'history'>('upload');
  const { saveToHistory, loadHistory } = useAnalysisHistory();

  const generateVariedMockResults = (filename: string): EnhancedDetectionResult => {
    // Create a simple hash from filename to ensure consistent but varied results
    const hash = filename.split('').reduce((a, b) => {
      a = ((a << 5) - a) + b.charCodeAt(0);
      return a & a;
    }, 0);
    
    const absHash = Math.abs(hash);
    const seed = absHash % 1000;
    
    // Generate varied threat levels and scores based on filename
    const threatLevels = ['LOW', 'LOW-MEDIUM', 'MEDIUM', 'MEDIUM-HIGH', 'HIGH', 'CRITICAL'];
    const confidenceLevels = ['LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH'];
    
    const threatIndex = seed % threatLevels.length;
    const threatLevel = threatLevels[threatIndex];
    const threatScore = Math.min(0.95, (threatIndex + 1) / threatLevels.length + (seed % 20) / 100);
    
    const confidenceIndex = (seed + 2) % confidenceLevels.length;
    const confidenceLevel = confidenceLevels[confidenceIndex];
    const confidenceScore = Math.min(0.95, (confidenceIndex + 1) / confidenceLevels.length + (seed % 15) / 100);
    
    // Generate varied detection counts
    const sigDetections = (seed % 6);
    const mlDetections = ((seed + 7) % 5);
    const beaconDetections = ((seed + 3) % 4);
    const behavioralDetections = ((seed + 11) % 5);
    
    const totalDetections = sigDetections + mlDetections + beaconDetections + behavioralDetections;
    const totalSessions = Math.max(10, seed % 100 + 20);
    
    // Generate varied component scores
    const componentScores = {
      signature: Math.min(0.4, sigDetections * 0.08 + (seed % 10) / 100),
      ml: Math.min(0.35, mlDetections * 0.07 + (seed % 12) / 100),
      beaconing: Math.min(0.25, beaconDetections * 0.06 + (seed % 8) / 100),
      behavioral: Math.min(0.2, behavioralDetections * 0.05 + (seed % 6) / 100)
    };
    
    // Generate varied risk factors
    const riskFactors = {
      persistence: (seed % 3) === 0,
      lateral_movement: (seed % 5) === 0,
      data_exfiltration: (seed % 4) === 0,
      command_control: beaconDetections > 0,
      privilege_escalation: (seed % 7) === 0,
      steganography: (seed % 9) === 0,
      dns_tunneling: (seed % 8) === 0
    };
    
    // Generate sample IP addresses based on seed
    const generateIP = (offset: number) => {
      const base = (seed + offset) % 255;
      return `192.168.${Math.floor(base / 10)}.${base % 10 + 1}`;
    };
    
    const generateExternalIP = (offset: number) => {
      const base = (seed + offset) % 255;
      return `${203 + (base % 50)}.${base % 255}.${(base + offset) % 255}.${(base * 2) % 255}`;
    };
    
    // Generate malicious domains based on seed
    const domains = [
      'suspicious-domain.com',
      'malicious-site.net',
      'c2-server.org',
      'backdoor-host.io',
      'evil-command.xyz'
    ];
    const selectedDomain = domains[seed % domains.length];
    
    return {
      analysis_timestamp: new Date().toISOString(),
      summary: {
        total_sessions: totalSessions,
        threat_score: threatScore,
        threat_level: threatLevel,
        confidence_score: confidenceScore,
        confidence_level: confidenceLevel,
        component_scores: componentScores,
        detection_breakdown: {
          signature_detections: sigDetections,
          ml_classifications: mlDetections,
          beaconing_patterns: beaconDetections,
          behavioral_anomalies: behavioralDetections
        },
        risk_factors: riskFactors,
        correlation_bonus: Math.min(0.15, totalDetections * 0.01),
        total_detections: totalDetections,
        assessment_metadata: {
          active_detection_types: [sigDetections, mlDetections, beaconDetections, behavioralDetections].filter(x => x > 0).length,
          analysis_version: '3.0',
          timestamp: new Date().toISOString()
        }
      },
      detections: {
        signature_detections: Array.from({ length: sigDetections }, (_, i) => ({
          session: {
            src_ip: generateIP(i),
            dst_ip: generateExternalIP(i + 10),
            host: selectedDomain,
            path: [`/gate.php`, `/admin.php`, `/upload.php`, `/cmd.php`][i % 4],
            method: ['POST', 'GET'][i % 2],
            user_agent: [
              'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
              'curl/7.68.0',
              'python-requests/2.25.1'
            ][i % 3],
            timestamp: Date.now() / 1000 - (i * 300)
          },
          score: Math.min(10, 6 + (seed + i) % 4),
          matches: [
            'Suspicious path detected',
            'Malicious user agent',
            'Known C2 signature'
          ].slice(0, ((seed + i) % 3) + 1),
          confidence: Math.min(0.95, 0.7 + ((seed + i) % 25) / 100)
        })),
        ml_classifications: Array.from({ length: mlDetections }, (_, i) => ({
          session: {
            src_ip: generateIP(i + 5),
            dst_ip: generateExternalIP(i + 15),
            host: generateExternalIP(i + 15),
            path: `/data${i + 1}`
          },
          score: Math.min(0.95, 0.6 + ((seed + i) % 30) / 100),
          reason: [
            'High path entropy; Direct IP communication',
            'Unusual payload patterns detected',
            'Suspicious timing intervals'
          ][i % 3],
          ml_confidence: Math.min(0.95, 0.75 + ((seed + i) % 20) / 100),
          category: ['c2_communication', 'data_exfiltration', 'lateral_movement'][i % 3]
        })),
        beaconing_patterns: Array.from({ length: beaconDetections }, (_, i) => ({
          host_key: `${generateIP(i + 2)}->${generateExternalIP(i + 20)}:${selectedDomain}`,
          session_count: 10 + ((seed + i) % 15),
          mean_interval: 250 + ((seed + i) % 200),
          confidence: Math.min(0.95, 0.8 + ((seed + i) % 15) / 100),
          pattern_type: ['regular_beaconing', 'jittered_beaconing'][i % 2],
          strength: Math.min(0.95, 0.7 + ((seed + i) % 20) / 100),
          duration_hours: 1.5 + ((seed + i) % 10) / 2,
          frequency_per_hour: 8 + ((seed + i) % 12)
        })),
        behavioral_anomalies: Array.from({ length: behavioralDetections }, (_, i) => ({
          host_key: `${generateIP(i + 3)}->${generateExternalIP(i + 25)}`,
          anomaly_type: [
            'repetitive_paths',
            'unusual_timing',
            'abnormal_payload_sizes',
            'suspicious_user_agents'
          ][i % 4],
          confidence: Math.min(0.95, 0.65 + ((seed + i) % 25) / 100),
          anomaly_score: Math.min(0.95, 0.7 + ((seed + i) % 20) / 100),
          baseline: 8 + ((seed + i) % 12),
          current: 35 + ((seed + i) % 25),
          z_score: 2.1 + ((seed + i) % 15) / 10,
          persistence_hours: 2.0 + ((seed + i) % 8) / 2
        }))
      }
    };
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (selectedFile && selectedFile.name.endsWith('.pcap')) {
      setFile(selectedFile);
      setError(null);
    } else {
      setError('Please select a valid .pcap file');
    }
  };

  const analyzeFile = async () => {
    if (!file) return;

    setIsAnalyzing(true);
    setProgress(0);
    setError(null);

    // Simulate analysis progress
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + 10;
      });
    }, 500);

    try {
      // In a real implementation, this would call the Python C2 detection script
      // For demo purposes, we'll simulate the analysis with varied mock data
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      // Generate varied results based on filename
      const mockResults = generateVariedMockResults(file.name);

      clearInterval(progressInterval);
      setProgress(100);
      setResults(mockResults);
      
      // Save to history
      saveToHistory(file.name, mockResults);
    } catch (err) {
      setError('Analysis failed. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleViewHistoryResults = (historyEntry: any) => {
    setResults(historyEntry.fullResults);
    setActiveTab('upload');
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
            <Shield className="h-8 w-8 text-blue-600" />
            Enhanced C2 Traffic Detection System
          </h1>
          <p className="text-gray-600 mt-2">
            Advanced threat detection with multi-layered analysis, adaptive scoring, and behavioral intelligence
          </p>
        </div>

        {/* Navigation Tabs */}
        <div className="mb-6">
          <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as 'upload' | 'history')}>
            <TabsList className="grid w-full grid-cols-2 max-w-md">
              <TabsTrigger value="upload">Analysis</TabsTrigger>
              <TabsTrigger value="history">History</TabsTrigger>
            </TabsList>
          </Tabs>
        </div>

        {activeTab === 'upload' && (
          <>
            {!results && (
              <Card className="mb-8">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Upload className="h-5 w-5" />
                    Upload PCAP File
                  </CardTitle>
                  <CardDescription>
                    Select a .pcap file to analyze for potential C2 traffic patterns using enhanced threat assessment
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
                      <input
                        type="file"
                        accept=".pcap"
                        onChange={handleFileUpload}
                        className="hidden"
                        id="pcap-upload"
                      />
                      <label htmlFor="pcap-upload" className="cursor-pointer">
                        <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <p className="text-lg font-medium text-gray-700">
                          {file ? file.name : 'Click to upload PCAP file'}
                        </p>
                        <p className="text-sm text-gray-500">
                          Supports .pcap files up to 100MB
                        </p>
                      </label>
                    </div>

                    {error && (
                      <Alert>
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>{error}</AlertDescription>
                      </Alert>
                    )}

                    {file && (
                      <div className="flex justify-center">
                        <Button 
                          onClick={analyzeFile} 
                          disabled={isAnalyzing}
                          className="px-8"
                        >
                          {isAnalyzing ? (
                            <>
                              <Activity className="h-4 w-4 mr-2 animate-spin" />
                              Analyzing...
                            </>
                          ) : (
                            <>
                              <Shield className="h-4 w-4 mr-2" />
                              Start Enhanced Analysis
                            </>
                          )}
                        </Button>
                      </div>
                    )}

                    {isAnalyzing && (
                      <div className="space-y-2">
                        <Progress value={progress} className="w-full" />
                        <p className="text-sm text-gray-600 text-center">
                          Processing packets with enhanced threat assessment engine...
                        </p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {results && (
              <div className="space-y-6">
                {/* Enhanced Threat Assessment */}
                <ThreatAssessmentCard assessment={results.summary} />

                {/* Detailed Results */}
                <Tabs defaultValue="signatures" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="signatures">Signatures</TabsTrigger>
                    <TabsTrigger value="ml">ML Analysis</TabsTrigger>
                    <TabsTrigger value="beacons">Beacons</TabsTrigger>
                    <TabsTrigger value="behavioral">Behavioral</TabsTrigger>
                  </TabsList>

                  <TabsContent value="signatures">
                    <Card>
                      <CardHeader>
                        <CardTitle>Signature-based Detections</CardTitle>
                        <CardDescription>
                          Known malicious patterns detected with confidence scoring
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        {results.detections.signature_detections.length > 0 ? (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Source → Destination</TableHead>
                                <TableHead>Host</TableHead>
                                <TableHead>Path</TableHead>
                                <TableHead>Score</TableHead>
                                <TableHead>Confidence</TableHead>
                                <TableHead>Matches</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {results.detections.signature_detections.map((detection, index) => (
                                <TableRow key={index}>
                                  <TableCell className="font-mono text-sm">
                                    {detection.session.src_ip} → {detection.session.dst_ip}
                                  </TableCell>
                                  <TableCell>{detection.session.host}</TableCell>
                                  <TableCell className="font-mono text-sm">
                                    {detection.session.path}
                                  </TableCell>
                                  <TableCell>
                                    <Badge variant="destructive">{detection.score}</Badge>
                                  </TableCell>
                                  <TableCell>
                                    <Badge variant="outline">
                                      {(detection.confidence * 100).toFixed(0)}%
                                    </Badge>
                                  </TableCell>
                                  <TableCell className="text-sm">
                                    {detection.matches.join(', ')}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        ) : (
                          <p className="text-gray-500 text-center py-8">
                            No signature-based detections found
                          </p>
                        )}
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="ml">
                    <Card>
                      <CardHeader>
                        <CardTitle>Machine Learning Classifications</CardTitle>
                        <CardDescription>
                          Suspicious patterns identified through enhanced feature analysis
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        {results.detections.ml_classifications.length > 0 ? (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Source → Destination</TableHead>
                                <TableHead>Host</TableHead>
                                <TableHead>Path</TableHead>
                                <TableHead>Score</TableHead>
                                <TableHead>Confidence</TableHead>
                                <TableHead>Category</TableHead>
                                <TableHead>Reason</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {results.detections.ml_classifications.map((classification, index) => (
                                <TableRow key={index}>
                                  <TableCell className="font-mono text-sm">
                                    {classification.session.src_ip} → {classification.session.dst_ip}
                                  </TableCell>
                                  <TableCell>{classification.session.host}</TableCell>
                                  <TableCell className="font-mono text-sm">
                                    {classification.session.path}
                                  </TableCell>
                                  <TableCell>
                                    <Badge variant="secondary">
                                      {(classification.score * 100).toFixed(0)}%
                                    </Badge>
                                  </TableCell>
                                  <TableCell>
                                    <Badge variant="outline">
                                      {(classification.ml_confidence * 100).toFixed(0)}%
                                    </Badge>
                                  </TableCell>
                                  <TableCell>
                                    <Badge variant="outline">
                                      {classification.category}
                                    </Badge>
                                  </TableCell>
                                  <TableCell className="text-sm">
                                    {classification.reason}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        ) : (
                          <p className="text-gray-500 text-center py-8">
                            No ML classifications found
                          </p>
                        )}
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="beacons">
                    <Card>
                      <CardHeader>
                        <CardTitle>Beaconing Patterns</CardTitle>
                        <CardDescription>
                          Regular communication patterns with enhanced strength analysis
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        {results.detections.beaconing_patterns.length > 0 ? (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Host Key</TableHead>
                                <TableHead>Sessions</TableHead>
                                <TableHead>Interval (s)</TableHead>
                                <TableHead>Confidence</TableHead>
                                <TableHead>Strength</TableHead>
                                <TableHead>Duration (h)</TableHead>
                                <TableHead>Pattern Type</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {results.detections.beaconing_patterns.map((beacon, index) => (
                                <TableRow key={index}>
                                  <TableCell className="font-mono text-sm">
                                    {beacon.host_key}
                                  </TableCell>
                                  <TableCell>{beacon.session_count}</TableCell>
                                  <TableCell>{beacon.mean_interval.toFixed(1)}</TableCell>
                                  <TableCell>
                                    <Badge variant="outline">
                                      {(beacon.confidence * 100).toFixed(0)}%
                                    </Badge>
                                  </TableCell>
                                  <TableCell>
                                    <Badge variant="secondary">
                                      {(beacon.strength * 100).toFixed(0)}%
                                    </Badge>
                                  </TableCell>
                                  <TableCell>{beacon.duration_hours.toFixed(1)}</TableCell>
                                  <TableCell>{beacon.pattern_type}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        ) : (
                          <p className="text-gray-500 text-center py-8">
                            No beaconing patterns detected
                          </p>
                        )}
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="behavioral">
                    <Card>
                      <CardHeader>
                        <CardTitle>Behavioral Anomalies</CardTitle>
                        <CardDescription>
                          Unusual communication behaviors with statistical analysis
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        {results.detections.behavioral_anomalies.length > 0 ? (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Host Key</TableHead>
                                <TableHead>Anomaly Type</TableHead>
                                <TableHead>Confidence</TableHead>
                                <TableHead>Anomaly Score</TableHead>
                                <TableHead>Z-Score</TableHead>
                                <TableHead>Baseline</TableHead>
                                <TableHead>Current</TableHead>
                                <TableHead>Persistence (h)</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {results.detections.behavioral_anomalies.map((anomaly, index) => (
                                <TableRow key={index}>
                                  <TableCell className="font-mono text-sm">
                                    {anomaly.host_key}
                                  </TableCell>
                                  <TableCell>{anomaly.anomaly_type.replace('_', ' ')}</TableCell>
                                  <TableCell>
                                    <Badge variant="outline">
                                      {(anomaly.confidence * 100).toFixed(0)}%
                                    </Badge>
                                  </TableCell>
                                  <TableCell>
                                    <Badge variant="secondary">
                                      {(anomaly.anomaly_score * 100).toFixed(0)}%
                                    </Badge>
                                  </TableCell>
                                  <TableCell>{anomaly.z_score.toFixed(2)}</TableCell>
                                  <TableCell>{anomaly.baseline}</TableCell>
                                  <TableCell>{anomaly.current}</TableCell>
                                  <TableCell>{anomaly.persistence_hours.toFixed(1)}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        ) : (
                          <p className="text-gray-500 text-center py-8">
                            No behavioral anomalies detected
                          </p>
                        )}
                      </CardContent>
                    </Card>
                  </TabsContent>
                </Tabs>

                <div className="flex justify-center">
                  <Button 
                    variant="outline" 
                    onClick={() => {
                      setResults(null);
                      setFile(null);
                      setProgress(0);
                    }}
                  >
                    <FileText className="h-4 w-4 mr-2" />
                    Analyze Another File
                  </Button>
                </div>
              </div>
            )}
          </>
        )}

        {activeTab === 'history' && (
          <AnalysisHistory onViewResults={handleViewHistoryResults} />
        )}
      </div>
    </div>
  );
};

export default C2Detector;
