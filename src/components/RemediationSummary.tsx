
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Clock, Shield, CheckCircle2 } from "lucide-react";

interface RemediationSummaryProps {
  remediationReport: {
    threat_id: string;
    threat_type: string;
    threat_level: string;
    estimated_total_time: string;
    immediate_actions: Array<{
      title: string;
      priority: string;
      category: string;
    }>;
    short_term_actions: Array<{
      title: string;
      priority: string;
      category: string;
    }>;
    long_term_actions: Array<{
      title: string;
      priority: string;
      category: string;
    }>;
    business_impact_assessment: string;
  };
}

const RemediationSummary: React.FC<RemediationSummaryProps> = ({ remediationReport }) => {
  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'IMMEDIATE': return 'bg-red-600 text-white';
      case 'HIGH': return 'bg-orange-500 text-white';
      case 'MEDIUM': return 'bg-yellow-500 text-white';
      case 'LOW': return 'bg-green-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'CONTAINMENT': return <Shield className="h-3 w-3" />;
      case 'ERADICATION': return <AlertTriangle className="h-3 w-3" />;
      case 'RECOVERY': return <CheckCircle2 className="h-3 w-3" />;
      case 'MONITORING': return <Clock className="h-3 w-3" />;
      default: return <Shield className="h-3 w-3" />;
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-600" />
            Threat Remediation Plan
          </span>
          <Badge variant="outline">{remediationReport.threat_id}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Quick Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center p-3 bg-red-50 rounded-lg">
            <div className="text-lg font-bold text-red-600">{remediationReport.threat_type}</div>
            <div className="text-xs text-gray-600">Threat Type</div>
          </div>
          <div className="text-center p-3 bg-orange-50 rounded-lg">
            <div className="text-lg font-bold text-orange-600">{remediationReport.threat_level}</div>
            <div className="text-xs text-gray-600">Severity Level</div>
          </div>
          <div className="text-center p-3 bg-blue-50 rounded-lg">
            <div className="text-lg font-bold text-blue-600">{remediationReport.estimated_total_time}</div>
            <div className="text-xs text-gray-600">Est. Timeline</div>
          </div>
        </div>

        {/* Business Impact */}
        <div className="bg-yellow-50 p-3 rounded-lg">
          <h4 className="font-semibold text-yellow-800 mb-1">Business Impact</h4>
          <p className="text-sm text-yellow-700">{remediationReport.business_impact_assessment}</p>
        </div>

        {/* Action Summary */}
        <div className="space-y-3">
          <h4 className="font-semibold">Action Summary</h4>
          
          {/* Immediate Actions */}
          {remediationReport.immediate_actions.length > 0 && (
            <div>
              <h5 className="text-sm font-medium text-red-600 mb-2">
                Immediate Actions ({remediationReport.immediate_actions.length})
              </h5>
              <div className="space-y-1">
                {remediationReport.immediate_actions.slice(0, 3).map((action, index) => (
                  <div key={index} className="flex items-center gap-2 text-sm p-2 bg-red-50 rounded">
                    {getCategoryIcon(action.category)}
                    <span className="flex-1">{action.title}</span>
                    <Badge className={getPriorityColor(action.priority)} variant="secondary">
                      {action.priority}
                    </Badge>
                  </div>
                ))}
                {remediationReport.immediate_actions.length > 3 && (
                  <div className="text-xs text-gray-500 pl-2">
                    +{remediationReport.immediate_actions.length - 3} more actions
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Short-term Actions */}
          {remediationReport.short_term_actions.length > 0 && (
            <div>
              <h5 className="text-sm font-medium text-orange-600 mb-2">
                Short-term Actions ({remediationReport.short_term_actions.length})
              </h5>
              <div className="space-y-1">
                {remediationReport.short_term_actions.slice(0, 2).map((action, index) => (
                  <div key={index} className="flex items-center gap-2 text-sm p-2 bg-orange-50 rounded">
                    {getCategoryIcon(action.category)}
                    <span className="flex-1">{action.title}</span>
                    <Badge className={getPriorityColor(action.priority)} variant="secondary">
                      {action.priority}
                    </Badge>
                  </div>
                ))}
                {remediationReport.short_term_actions.length > 2 && (
                  <div className="text-xs text-gray-500 pl-2">
                    +{remediationReport.short_term_actions.length - 2} more actions
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Long-term Actions */}
          {remediationReport.long_term_actions.length > 0 && (
            <div>
              <h5 className="text-sm font-medium text-blue-600 mb-2">
                Long-term Actions ({remediationReport.long_term_actions.length})
              </h5>
              <div className="text-xs text-gray-600">
                Strategic improvements and prevention measures
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default RemediationSummary;

