
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Upload, AlertTriangle, Shield, Activity, FileText } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface DetectionResult {
  analysis_timestamp: string;
  summary: {
    total_sessions: number;
    signature_detections: number;
    ml_classifications: number;
    beaconing_patterns: number;
    behavioral_anomalies: number;
    threat_score: number;
    threat_level: string;
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
    }>;
    beaconing_patterns: Array<{
      host_key: string;
      session_count: number;
      mean_interval: number;
      confidence: number;
      pattern_type: string;
    }>;
    behavioral_anomalies: Array<{
      host_key: string;
      anomaly_type: string;
      confidence: number;
    }>;
  };
}

const C2Detector = () => {
  const [file, setFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<DetectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

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
      // For demo purposes, we'll simulate the analysis with mock data
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      // Mock results - in production, this would come from the actual analysis
      const mockResults: DetectionResult = {
        analysis_timestamp: new Date().toISOString(),
        summary: {
          total_sessions: 45,
          signature_detections: 3,
          ml_classifications: 2,
          beaconing_patterns: 1,
          behavioral_anomalies: 2,
          threat_score: 0.7,
          threat_level: 'HIGH'
        },
        detections: {
          signature_detections: [
            {
              session: {
                src_ip: '192.168.1.100',
                dst_ip: '203.0.113.50',
                host: 'malicious-domain.com',
                path: '/gate.php',
                method: 'POST',
                user_agent: 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
                timestamp: Date.now() / 1000
              },
              score: 8,
              matches: ['Suspicious path: /gate.php', 'Malicious user agent detected']
            }
          ],
          ml_classifications: [
            {
              session: {
                src_ip: '192.168.1.100',
                dst_ip: '198.51.100.25',
                host: '198.51.100.25',
                path: '/aHR0cDovL2V4YW1wbGUuY29t'
              },
              score: 0.85,
              reason: 'High path entropy; Direct IP communication'
            }
          ],
          beaconing_patterns: [
            {
              host_key: '192.168.1.100->203.0.113.50:malicious-domain.com',
              session_count: 15,
              mean_interval: 300.5,
              confidence: 0.92,
              pattern_type: 'regular_beaconing'
            }
          ],
          behavioral_anomalies: [
            {
              host_key: '192.168.1.100->198.51.100.25',
              anomaly_type: 'repetitive_paths',
              confidence: 0.78
            }
          ]
        }
      };

      clearInterval(progressInterval);
      setProgress(100);
      setResults(mockResults);
    } catch (err) {
      setError('Analysis failed. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'bg-red-500';
      case 'HIGH': return 'bg-orange-500';
      case 'MEDIUM': return 'bg-yellow-500';
      case 'LOW': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getThreatLevelVariant = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'destructive' as const;
      case 'HIGH': return 'destructive' as const;
      case 'MEDIUM': return 'secondary' as const;
      case 'LOW': return 'outline' as const;
      default: return 'outline' as const;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
            <Shield className="h-8 w-8 text-blue-600" />
            C2 Traffic Detection System
          </h1>
          <p className="text-gray-600 mt-2">
            Advanced threat detection using signature-based analysis, machine learning, and behavioral patterns
          </p>
        </div>

        {!results && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="h-5 w-5" />
                Upload PCAP File
              </CardTitle>
              <CardDescription>
                Select a .pcap file to analyze for potential C2 traffic patterns
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
                          Start Analysis
                        </>
                      )}
                    </Button>
                  </div>
                )}

                {isAnalyzing && (
                  <div className="space-y-2">
                    <Progress value={progress} className="w-full" />
                    <p className="text-sm text-gray-600 text-center">
                      Processing packets and running detection engines...
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {results && (
          <div className="space-y-6">
            {/* Threat Summary */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5" />
                    Threat Assessment
                  </span>
                  <Badge variant={getThreatLevelVariant(results.summary.threat_level)}>
                    {results.summary.threat_level}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">
                      {results.summary.total_sessions}
                    </div>
                    <div className="text-sm text-gray-600">Total Sessions</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-600">
                      {results.summary.signature_detections}
                    </div>
                    <div className="text-sm text-gray-600">Signature Hits</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-orange-600">
                      {results.summary.ml_classifications}
                    </div>
                    <div className="text-sm text-gray-600">ML Classifications</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-purple-600">
                      {results.summary.beaconing_patterns}
                    </div>
                    <div className="text-sm text-gray-600">Beacon Patterns</div>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Threat Score</span>
                    <span>{(results.summary.threat_score * 100).toFixed(1)}%</span>
                  </div>
                  <Progress 
                    value={results.summary.threat_score * 100} 
                    className="w-full"
                  />
                </div>
              </CardContent>
            </Card>

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
                      Known malicious patterns detected in network traffic
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
                      Suspicious patterns identified through feature analysis
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
                      Regular communication patterns indicating potential C2 activity
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
                      Unusual communication behaviors that may indicate malicious activity
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
      </div>
    </div>
  );
};

export default C2Detector;
