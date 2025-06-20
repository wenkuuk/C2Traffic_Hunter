
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { 
  AlertTriangle, 
  Clock, 
  Shield, 
  CheckCircle2, 
  AlertCircle,
  Users,
  Network,
  FileSearch,
  Monitor
} from "lucide-react";

interface RemediationAction {
  title: string;
  description: string;
  category: string;
  priority: string;
  estimated_time: string;
  prerequisites: string[];
  steps: string[];
  verification: string;
  automation_possible: boolean;
  impact_level: string;
}

interface RemediationReportProps {
  report: {
    threat_id: string;
    threat_type: string;
    threat_level: string;
    confidence_score: number;
    generated_at: string;
    immediate_actions: RemediationAction[];
    short_term_actions: RemediationAction[];
    long_term_actions: RemediationAction[];
    monitoring_recommendations: string[];
    prevention_measures: string[];
    estimated_total_time: string;
    business_impact_assessment: string;
    compliance_considerations: string[];
  };
}

const RemediationReport: React.FC<RemediationReportProps> = ({ report }) => {
  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'IMMEDIATE': return 'bg-red-600';
      case 'HIGH': return 'bg-orange-500';
      case 'MEDIUM': return 'bg-yellow-500';
      case 'LOW': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getPriorityVariant = (priority: string) => {
    switch (priority) {
      case 'IMMEDIATE':
      case 'HIGH': return 'destructive' as const;
      case 'MEDIUM': return 'secondary' as const;
      case 'LOW': return 'outline' as const;
      default: return 'outline' as const;
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'CONTAINMENT': return <Shield className="h-4 w-4" />;
      case 'ERADICATION': return <AlertTriangle className="h-4 w-4" />;
      case 'RECOVERY': return <CheckCircle2 className="h-4 w-4" />;
      case 'MONITORING': return <Monitor className="h-4 w-4" />;
      case 'PREVENTION': return <Network className="h-4 w-4" />;
      default: return <FileSearch className="h-4 w-4" />;
    }
  };

  const renderActionCard = (action: RemediationAction, index: number) => (
    <Card key={index} className="mb-4">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center justify-between text-sm">
          <span className="flex items-center gap-2">
            {getCategoryIcon(action.category)}
            {action.title}
          </span>
          <div className="flex items-center gap-2">
            <Badge variant={getPriorityVariant(action.priority)}>
              {action.priority}
            </Badge>
            {action.automation_possible && (
              <Badge variant="outline" className="text-blue-600">
                Automatable
              </Badge>
            )}
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-gray-600">{action.description}</p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div>
            <span className="font-medium">Estimated Time:</span>
            <p className="text-gray-600">{action.estimated_time}</p>
          </div>
          <div>
            <span className="font-medium">Impact Level:</span>
            <p className="text-gray-600">{action.impact_level}</p>
          </div>
          <div>
            <span className="font-medium">Category:</span>
            <p className="text-gray-600">{action.category}</p>
          </div>
        </div>

        {action.prerequisites.length > 0 && (
          <div>
            <span className="font-medium text-sm">Prerequisites:</span>
            <ul className="list-disc list-inside text-sm text-gray-600 mt-1">
              {action.prerequisites.map((prereq, idx) => (
                <li key={idx}>{prereq}</li>
              ))}
            </ul>
          </div>
        )}

        <div>
          <span className="font-medium text-sm">Implementation Steps:</span>
          <ol className="list-decimal list-inside text-sm text-gray-600 mt-1 space-y-1">
            {action.steps.map((step, idx) => (
              <li key={idx}>{step}</li>
            ))}
          </ol>
        </div>

        <div className="bg-blue-50 p-3 rounded-lg">
          <span className="font-medium text-sm text-blue-800">Verification:</span>
          <p className="text-sm text-blue-700 mt-1">{action.verification}</p>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <AlertTriangle className="h-6 w-6 text-red-600" />
              Threat Remediation Report
            </span>
            <Badge variant="outline">{report.threat_id}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="text-center p-3 bg-red-50 rounded-lg">
              <div className="text-lg font-bold text-red-600">{report.threat_level}</div>
              <div className="text-xs text-gray-600">Threat Level</div>
            </div>
            <div className="text-center p-3 bg-blue-50 rounded-lg">
              <div className="text-lg font-bold text-blue-600">{report.threat_type}</div>
              <div className="text-xs text-gray-600">Threat Type</div>
            </div>
            <div className="text-center p-3 bg-green-50 rounded-lg">
              <div className="text-lg font-bold text-green-600">
                {(report.confidence_score * 100).toFixed(1)}%
              </div>
              <div className="text-xs text-gray-600">Confidence</div>
            </div>
            <div className="text-center p-3 bg-orange-50 rounded-lg">
              <div className="text-lg font-bold text-orange-600">{report.estimated_total_time}</div>
              <div className="text-xs text-gray-600">Est. Timeline</div>
            </div>
          </div>

          <div className="bg-yellow-50 p-4 rounded-lg">
            <h4 className="font-semibold text-yellow-800 mb-2">Business Impact Assessment</h4>
            <p className="text-yellow-700">{report.business_impact_assessment}</p>
          </div>
        </CardContent>
      </Card>

      {/* Immediate Actions */}
      {report.immediate_actions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-600">
              <AlertCircle className="h-5 w-5" />
              Immediate Actions Required
            </CardTitle>
          </CardHeader>
          <CardContent>
            {report.immediate_actions.map((action, index) => renderActionCard(action, index))}
          </CardContent>
        </Card>
      )}

      {/* Short-term Actions */}
      {report.short_term_actions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-orange-600">
              <Clock className="h-5 w-5" />
              Short-term Actions
            </CardTitle>
          </CardHeader>
          <CardContent>
            {report.short_term_actions.map((action, index) => renderActionCard(action, index))}
          </CardContent>
        </Card>
      )}

      {/* Long-term Actions */}
      {report.long_term_actions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-blue-600">
              <Shield className="h-5 w-5" />
              Long-term Actions
            </CardTitle>
          </CardHeader>
          <CardContent>
            {report.long_term_actions.map((action, index) => renderActionCard(action, index))}
          </CardContent>
        </Card>
      )}

      {/* Monitoring and Prevention */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Monitor className="h-5 w-5" />
              Monitoring Recommendations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {report.monitoring_recommendations.map((rec, index) => (
                <li key={index} className="flex items-start gap-2 text-sm">
                  <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                  {rec}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Network className="h-5 w-5" />
              Prevention Measures
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {report.prevention_measures.map((measure, index) => (
                <li key={index} className="flex items-start gap-2 text-sm">
                  <Shield className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
                  {measure}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      {/* Compliance Considerations */}
      {report.compliance_considerations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileSearch className="h-5 w-5" />
              Compliance Considerations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {report.compliance_considerations.map((consideration, index) => (
                <li key={index} className="flex items-start gap-2 text-sm">
                  <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 flex-shrink-0" />
                  {consideration}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default RemediationReport;
