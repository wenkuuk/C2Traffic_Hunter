import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Upload, FileText, AlertTriangle, Activity } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import ThreatAssessmentCard from "@/components/ThreatAssessmentCard";
import RemediationSummary from "@/components/RemediationSummary";
import RemediationReport from "@/components/RemediationReport";
import { MockApiService } from "@/services/mockApiService";

interface AnalysisReport {
  summary: {
    threat_level: string;
    threat_score: number;
    assessment_confidence: number;
    correlation_bonus: number;
    component_scores: {
      signature: number;
      ml: number;
      beaconing: number;
      behavioral: number;
    };
    suspicious_hosts: number;
    beacon_candidates: number;
    suspicious_requests: number;
    signature_detections: number;
    ml_classifications: number;
    behavioral_anomalies: number;
    beaconing_patterns: number;
    remediation_report?: any;
  };
  details: any;
  threat_remediation?: any;
}

const C2Detector: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [activeTab, setActiveTab] = useState<'assessment' | 'remediation'>('assessment');
  const { toast } = useToast();

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (selectedFile) {
      if (selectedFile.name.match(/\.(pcap|pcapng|cap)$/i)) {
        setFile(selectedFile);
        toast({
          title: "File Selected",
          description: `${selectedFile.name} is ready for analysis`,
        });
      } else {
        toast({
          title: "Invalid File Type",
          description: "Please select a PCAP file (.pcap, .pcapng, or .cap)",
          variant: "destructive",
        });
      }
    }
  };

  const handleAnalyze = async () => {
    if (!file) {
      toast({
        title: "No File Selected",
        description: "Please select a PCAP file first",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);

    try {
      // Use mock API service instead of real backend
      const result = await MockApiService.uploadAndAnalyze(file);
      setReport(result.report);
      
      // Show remediation tab if threats detected
      if (result.report?.summary?.threat_level && 
          !['LOW', 'LOW-MEDIUM'].includes(result.report.summary.threat_level)) {
        setActiveTab('remediation');
      }
      
      toast({
        title: "Analysis Complete",
        description: `Threat Level: ${result.report?.summary?.threat_level || 'Unknown'}`,
      });
    } catch (error) {
      toast({
        title: "Analysis Failed",
        description: "Failed to analyze PCAP file. Please try again.",
        variant: "destructive",
      });
      console.error('Analysis error:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getThreatAssessmentData = () => {
    if (!report) return null;
    
    return {
      threat_score: report.summary.threat_score || 0,
      threat_level: report.summary.threat_level || 'LOW',
      confidence_score: report.summary.assessment_confidence || 0,
      confidence_level: getConfidenceLevel(report.summary.assessment_confidence || 0),
      component_scores: report.summary.component_scores || {
        signature: 0,
        ml: 0,
        beaconing: 0,
        behavioral: 0
      },
      detection_breakdown: {
        signature_detections: report.summary.signature_detections || 0,
        ml_classifications: report.summary.ml_classifications || 0,
        beaconing_patterns: report.summary.beaconing_patterns || 0,
        behavioral_anomalies: report.summary.behavioral_anomalies || 0
      },
      risk_factors: {
        persistence: (report.summary.beaconing_patterns || 0) > 0,
        lateral_movement: (report.summary.suspicious_hosts || 0) > 2,
        data_exfiltration: (report.summary.suspicious_requests || 0) > 5,
        command_control: (report.summary.beacon_candidates || 0) > 0,
        privilege_escalation: false,
        steganography: false,
        dns_tunneling: false
      },
      correlation_bonus: report.summary.correlation_bonus || 0,
      total_detections: (report.summary.signature_detections || 0) + 
                       (report.summary.ml_classifications || 0) + 
                       (report.summary.beaconing_patterns || 0) + 
                       (report.summary.behavioral_anomalies || 0)
    };
  };

  const getConfidenceLevel = (score: number): string => {
    if (score >= 0.8) return 'HIGH';
    if (score >= 0.6) return 'MEDIUM';
    if (score >= 0.4) return 'LOW-MEDIUM';
    return 'LOW';
  };

  const getRemediationData = () => {
    // Check both possible locations for remediation data
    const remediation = report?.summary?.remediation_report || report?.threat_remediation;
    
    if (!remediation) return null;

    // If it's a summary format, return it directly
    if (remediation.immediate_actions && Array.isArray(remediation.immediate_actions)) {
      return remediation;
    }

    // If it's a full report format, return it
    return remediation;
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold mb-4">Advanced C2 Traffic Detector</h1>
        <p className="text-gray-600 mb-6">
          Upload a PCAP file to analyze network traffic for Command & Control patterns
        </p>
      </div>

      {/* Upload Section */}
      <Card className="mb-8">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Upload PCAP File
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Input
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileChange}
              className="flex-1"
            />
            <Button 
              onClick={handleAnalyze} 
              disabled={!file || isAnalyzing}
              className="min-w-[120px]"
            >
              {isAnalyzing ? (
                <>
                  <Activity className="h-4 w-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <FileText className="h-4 w-4 mr-2" />
                  Analyze
                </>
              )}
            </Button>
          </div>
          {file && (
            <p className="text-sm text-gray-600">
              Selected: {file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)
            </p>
          )}
        </CardContent>
      </Card>

      {/* Results Section */}
      {report && (
        <div className="space-y-6">
          {/* Tab Navigation */}
          <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg">
            <button
              onClick={() => setActiveTab('assessment')}
              className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'assessment'
                  ? 'bg-white text-blue-600 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Threat Assessment
            </button>
            <button
              onClick={() => setActiveTab('remediation')}
              className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'remediation'
                  ? 'bg-white text-blue-600 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              <AlertTriangle className="h-4 w-4 inline mr-2" />
              Remediation Plan
              {getRemediationData() && (
                <span className="ml-2 bg-red-500 text-white text-xs px-2 py-1 rounded-full">
                  Action Required
                </span>
              )}
            </button>
          </div>

          {/* Tab Content */}
          {activeTab === 'assessment' && getThreatAssessmentData() && (
            <ThreatAssessmentCard assessment={getThreatAssessmentData()!} />
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-6">
              {getRemediationData() ? (
                <>
                  <RemediationSummary remediationReport={getRemediationData()!} />
                  <RemediationReport report={getRemediationData()!} />
                </>
              ) : (
                <Card>
                  <CardContent className="text-center py-8">
                    <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">
                      No Remediation Required
                    </h3>
                    <p className="text-gray-600">
                      The current threat level does not require immediate remediation actions.
                      Continue monitoring for any changes in threat patterns.
                    </p>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default C2Detector;
