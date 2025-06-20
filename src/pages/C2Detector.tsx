
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
      // For demo purposes, we'll simulate the analysis with enhanced mock data
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      // Enhanced mock results with new assessment structure
      const mockResults: EnhancedDetectionResult = {
        analysis_timestamp: new Date().toISOString(),
        summary: {
          total_sessions: 45,
          threat_score: 0.78,
          threat_level: 'HIGH',
          confidence_score: 0.85,
          confidence_level: 'HIGH',
          component_scores: {
            signature: 0.35,
            ml: 0.28,
            beaconing: 0.12,
            behavioral: 0.03
          },
          detection_breakdown: {
            signature_detections: 4,
            ml_classifications: 3,
            beaconing_patterns: 2,
            behavioral_anomalies: 3
          },
          risk_factors: {
            persistence: true,
            lateral_movement: false,
            data_exfiltration: true,
            command_control: true,
            privilege_escalation: false,
            steganography: false,
            dns_tunneling: false
          },
          correlation_bonus: 0.08,
          total_detections: 12,
          assessment_metadata: {
            active_detection_types: 4,
            analysis_version: '3.0',
            timestamp: new Date().toISOString()
          }
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
              matches: ['Suspicious path: /gate.php', 'Malicious user agent detected'],
              confidence: 0.92
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
              reason: 'High path entropy; Direct IP communication',
              ml_confidence: 0.88,
              category: 'c2_communication'
            }
          ],
          beaconing_patterns: [
            {
              host_key: '192.168.1.100->203.0.113.50:malicious-domain.com',
              session_count: 15,
              mean_interval: 300.5,
              confidence: 0.92,
              pattern_type: 'regular_beaconing',
              strength: 0.89,
              duration_hours: 2.5,
              frequency_per_hour: 12
            }
          ],
          behavioral_anomalies: [
            {
              host_key: '192.168.1.100->198.51.100.25',
              anomaly_type: 'repetitive_paths',
              confidence: 0.78,
              anomaly_score: 0.82,
              baseline: 10,
              current: 45,
              z_score: 2.8,
              persistence_hours: 3.2
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
      </div>
    </div>
  );
};

export default C2Detector;
