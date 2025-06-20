
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { AlertTriangle, TrendingUp, Clock, Users, Shield, Activity } from "lucide-react";

interface ConfidenceMetrics {
  base_score: number;
  type_confidence: number;
  recency_factor: number;
  frequency_factor: number;
  correlation_factor: number;
  severity_factor: number;
  reliability_factor: number;
  context_factor: number;
  final_score: number;
  confidence_level: string;
  warnings: string[];
}

interface ConfidenceBreakdownProps {
  metrics: ConfidenceMetrics;
}

const ConfidenceBreakdown: React.FC<ConfidenceBreakdownProps> = ({ metrics }) => {
  const getConfidenceLevelColor = (level: string) => {
    switch (level) {
      case 'VERY_HIGH': return 'text-green-700 bg-green-100';
      case 'HIGH': return 'text-green-600 bg-green-50';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-50';
      case 'LOW': return 'text-orange-600 bg-orange-50';
      case 'VERY_LOW': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getConfidenceLevelVariant = (level: string) => {
    switch (level) {
      case 'VERY_HIGH':
      case 'HIGH': return 'default' as const;
      case 'MEDIUM': return 'secondary' as const;
      case 'LOW':
      case 'VERY_LOW': return 'destructive' as const;
      default: return 'outline' as const;
    }
  };

  const factorData = [
    {
      name: 'Base Score',
      value: metrics.base_score,
      icon: <Shield className="h-4 w-4" />,
      description: 'Fundamental confidence baseline'
    },
    {
      name: 'Type Confidence',
      value: metrics.type_confidence,
      icon: <Activity className="h-4 w-4" />,
      description: 'Detection method reliability'
    },
    {
      name: 'Recency Factor',
      value: metrics.recency_factor,
      icon: <Clock className="h-4 w-4" />,
      description: 'Age-based confidence decay'
    },
    {
      name: 'Frequency Factor',
      value: metrics.frequency_factor,
      icon: <TrendingUp className="h-4 w-4" />,
      description: 'Detection frequency impact'
    },
    {
      name: 'Correlation Factor',
      value: metrics.correlation_factor,
      icon: <Users className="h-4 w-4" />,
      description: 'Cross-detection correlation'
    },
    {
      name: 'Severity Factor',
      value: metrics.severity_factor,
      icon: <AlertTriangle className="h-4 w-4" />,
      description: 'Threat severity impact'
    },
    {
      name: 'Reliability Factor',
      value: metrics.reliability_factor,
      icon: <Shield className="h-4 w-4" />,
      description: 'Source reliability score'
    },
    {
      name: 'Context Factor',
      value: metrics.context_factor,
      icon: <Activity className="h-4 w-4" />,
      description: 'Environmental context'
    }
  ];

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-blue-600" />
            Confidence Analysis Breakdown
          </span>
          <div className="flex items-center gap-2">
            <Badge variant={getConfidenceLevelVariant(metrics.confidence_level)}>
              {metrics.confidence_level}
            </Badge>
            <Badge variant="outline">
              {(metrics.final_score * 100).toFixed(1)}%
            </Badge>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Overall Score */}
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-sm font-medium">Final Confidence Score</span>
            <span className="text-sm font-bold">{(metrics.final_score * 100).toFixed(1)}%</span>
          </div>
          <Progress value={metrics.final_score * 100} className="h-3" />
          <div className={`text-center p-2 rounded-lg text-sm ${getConfidenceLevelColor(metrics.confidence_level)}`}>
            Confidence Level: {metrics.confidence_level.replace('_', ' ')}
          </div>
        </div>

        {/* Factor Breakdown */}
        <div className="space-y-4">
          <h4 className="font-semibold text-sm">Contributing Factors</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {factorData.map((factor, index) => (
              <div key={index} className="p-3 border rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm font-medium">
                    {factor.icon}
                    {factor.name}
                  </span>
                  <span className="text-sm font-bold">
                    {(factor.value * 100).toFixed(1)}%
                  </span>
                </div>
                <Progress value={factor.value * 100} className="h-2" />
                <p className="text-xs text-gray-600">{factor.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Warnings */}
        {metrics.warnings && metrics.warnings.length > 0 && (
          <div className="space-y-2">
            <h4 className="font-semibold text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              Analysis Warnings
            </h4>
            <div className="space-y-1">
              {metrics.warnings.map((warning, index) => (
                <div key={index} className="bg-amber-50 border border-amber-200 p-2 rounded text-sm text-amber-800">
                  {warning}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Confidence Interpretation */}
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="font-semibold text-blue-800 mb-2">Confidence Interpretation</h4>
          <div className="text-sm text-blue-700 space-y-1">
            {metrics.confidence_level === 'VERY_HIGH' && (
              <p>Extremely high confidence in threat detection. Multiple strong indicators present.</p>
            )}
            {metrics.confidence_level === 'HIGH' && (
              <p>High confidence in threat detection. Strong evidence with good correlation.</p>
            )}
            {metrics.confidence_level === 'MEDIUM' && (
              <p>Moderate confidence. Some indicators present but may require additional verification.</p>
            )}
            {metrics.confidence_level === 'LOW' && (
              <p>Low confidence. Limited evidence or weak indicators. Consider false positive possibility.</p>
            )}
            {metrics.confidence_level === 'VERY_LOW' && (
              <p>Very low confidence. High likelihood of false positive. Review detection logic.</p>
            )}
          </div>
        </div>

        {/* Factor Insights */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="space-y-2">
            <h5 className="font-medium">High Impact Factors</h5>
            {factorData
              .filter(f => f.value > 0.7)
              .map((factor, index) => (
                <div key={index} className="flex items-center gap-2 text-green-600">
                  <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                  {factor.name}: {(factor.value * 100).toFixed(0)}%
                </div>
              ))}
          </div>
          <div className="space-y-2">
            <h5 className="font-medium">Areas for Improvement</h5>
            {factorData
              .filter(f => f.value < 0.5)
              .map((factor, index) => (
                <div key={index} className="flex items-center gap-2 text-amber-600">
                  <span className="w-2 h-2 bg-amber-500 rounded-full"></span>
                  {factor.name}: {(factor.value * 100).toFixed(0)}%
                </div>
              ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ConfidenceBreakdown;
