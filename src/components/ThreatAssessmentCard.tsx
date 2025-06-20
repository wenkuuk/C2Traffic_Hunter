
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { AlertTriangle, Shield, Activity, TrendingUp, Eye } from "lucide-react";

interface ThreatAssessmentProps {
  assessment: {
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
  };
}

const ThreatAssessmentCard: React.FC<ThreatAssessmentProps> = ({ assessment }) => {
  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'bg-red-600';
      case 'HIGH': return 'bg-red-500';
      case 'MEDIUM-HIGH': return 'bg-orange-500';
      case 'MEDIUM': return 'bg-yellow-500';
      case 'LOW-MEDIUM': return 'bg-yellow-400';
      case 'LOW': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getThreatLevelVariant = (level: string) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH': return 'destructive' as const;
      case 'MEDIUM-HIGH':
      case 'MEDIUM': return 'secondary' as const;
      case 'LOW-MEDIUM':
      case 'LOW': return 'outline' as const;
      default: return 'outline' as const;
    }
  };

  const getConfidenceLevelColor = (level: string) => {
    switch (level) {
      case 'HIGH': return 'text-green-600';
      case 'MEDIUM': return 'text-yellow-600';
      case 'LOW-MEDIUM': return 'text-orange-600';
      case 'LOW': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const activeRiskFactors = Object.entries(assessment.risk_factors)
    .filter(([_, active]) => active)
    .map(([factor, _]) => factor);

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-blue-600" />
            Enhanced Threat Assessment
          </span>
          <div className="flex items-center gap-2">
            <Badge variant={getThreatLevelVariant(assessment.threat_level)}>
              {assessment.threat_level}
            </Badge>
            <Badge variant="outline" className={getConfidenceLevelColor(assessment.confidence_level)}>
              {assessment.confidence_level} Confidence
            </Badge>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Overall Scores */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">Threat Score</span>
              <span className="text-sm font-bold">{(assessment.threat_score * 100).toFixed(1)}%</span>
            </div>
            <Progress 
              value={assessment.threat_score * 100} 
              className="h-2"
            />
          </div>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm font-medium">Confidence Score</span>
              <span className="text-sm font-bold">{(assessment.confidence_score * 100).toFixed(1)}%</span>
            </div>
            <Progress 
              value={assessment.confidence_score * 100} 
              className="h-2"
            />
          </div>
        </div>

        {/* Detection Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center p-3 bg-blue-50 rounded-lg">
            <div className="text-2xl font-bold text-blue-600">
              {assessment.total_detections}
            </div>
            <div className="text-xs text-gray-600">Total Detections</div>
          </div>
          <div className="text-center p-3 bg-red-50 rounded-lg">
            <div className="text-2xl font-bold text-red-600">
              {assessment.detection_breakdown.signature_detections}
            </div>
            <div className="text-xs text-gray-600">Signature Hits</div>
          </div>
          <div className="text-center p-3 bg-orange-50 rounded-lg">
            <div className="text-2xl font-bold text-orange-600">
              {assessment.detection_breakdown.ml_classifications}
            </div>
            <div className="text-xs text-gray-600">ML Classifications</div>
          </div>
          <div className="text-center p-3 bg-purple-50 rounded-lg">
            <div className="text-2xl font-bold text-purple-600">
              {assessment.detection_breakdown.beaconing_patterns}
            </div>
            <div className="text-xs text-gray-600">Beacon Patterns</div>
          </div>
        </div>

        {/* Component Scores */}
        <div className="space-y-3">
          <h4 className="font-semibold flex items-center gap-2">
            <TrendingUp className="h-4 w-4" />
            Component Analysis
          </h4>
          <div className="space-y-2">
            {Object.entries(assessment.component_scores).map(([component, score]) => (
              <div key={component} className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span className="capitalize">{component.replace('_', ' ')}</span>
                  <span className="font-medium">{(score * 100).toFixed(1)}%</span>
                </div>
                <Progress value={score * 100} className="h-1" />
              </div>
            ))}
          </div>
        </div>

        {/* Risk Factors */}
        {activeRiskFactors.length > 0 && (
          <div className="space-y-3">
            <h4 className="font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-500" />
              Active Risk Factors
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {activeRiskFactors.map((factor) => (
                <div key={factor} className="flex items-center gap-2 p-2 bg-orange-50 rounded">
                  <Eye className="h-3 w-3 text-red-500" />
                  <span className="text-sm capitalize">
                    {factor.replace('_', ' ')}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Correlation Bonus */}
        {assessment.correlation_bonus > 0 && (
          <div className="p-3 bg-blue-50 rounded-lg">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium flex items-center gap-2">
                <Activity className="h-4 w-4 text-blue-500" />
                Correlation Bonus
              </span>
              <span className="text-sm font-bold text-blue-600">
                +{(assessment.correlation_bonus * 100).toFixed(1)}%
              </span>
            </div>
            <p className="text-xs text-gray-600 mt-1">
              Multiple detection types correlate, increasing threat confidence
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ThreatAssessmentCard;
