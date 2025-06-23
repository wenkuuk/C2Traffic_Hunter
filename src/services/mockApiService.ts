
// Mock API service to simulate PCAP analysis
export interface MockAnalysisReport {
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

export class MockApiService {
  private static generateMockReport(filename: string): MockAnalysisReport {
    // Generate realistic mock data based on filename
    const isSuspicious = filename.toLowerCase().includes('malware') || 
                        filename.toLowerCase().includes('c2') ||
                        filename.toLowerCase().includes('suspicious');
    
    const baseScore = isSuspicious ? 0.7 + Math.random() * 0.25 : Math.random() * 0.4;
    const threatLevel = this.getThreatLevel(baseScore);
    
    const componentScores = {
      signature: Math.max(0, baseScore + (Math.random() - 0.5) * 0.2),
      ml: Math.max(0, baseScore + (Math.random() - 0.5) * 0.2),
      beaconing: Math.max(0, baseScore + (Math.random() - 0.5) * 0.3),
      behavioral: Math.max(0, baseScore + (Math.random() - 0.5) * 0.2)
    };

    const detectionCounts = {
      signature_detections: isSuspicious ? Math.floor(Math.random() * 5) + 1 : 0,
      ml_classifications: isSuspicious ? Math.floor(Math.random() * 3) + 1 : 0,
      beaconing_patterns: isSuspicious ? Math.floor(Math.random() * 2) + 1 : 0,
      behavioral_anomalies: isSuspicious ? Math.floor(Math.random() * 4) + 1 : 0
    };

    let remediationReport = null;
    if (baseScore >= 0.5) {
      remediationReport = this.generateRemediationReport(threatLevel, baseScore);
    }

    return {
      summary: {
        threat_level: threatLevel,
        threat_score: baseScore,
        assessment_confidence: 0.6 + Math.random() * 0.3,
        correlation_bonus: isSuspicious ? Math.random() * 0.2 : 0,
        component_scores: componentScores,
        suspicious_hosts: Math.floor(Math.random() * 3) + 1,
        beacon_candidates: isSuspicious ? Math.floor(Math.random() * 2) + 1 : 0,
        suspicious_requests: Math.floor(Math.random() * 10) + 1,
        ...detectionCounts,
        remediation_report: remediationReport
      },
      details: {
        analysis_duration: '2.3 seconds',
        packets_analyzed: Math.floor(Math.random() * 10000) + 1000,
        timestamp: new Date().toISOString()
      },
      threat_remediation: remediationReport
    };
  }

  private static getThreatLevel(score: number): string {
    if (score >= 0.85) return 'CRITICAL';
    if (score >= 0.7) return 'HIGH';
    if (score >= 0.55) return 'MEDIUM-HIGH';
    if (score >= 0.4) return 'MEDIUM';
    if (score >= 0.25) return 'LOW-MEDIUM';
    return 'LOW';
  }

  private static generateRemediationReport(threatLevel: string, score: number) {
    const immediateActions = [
      {
        title: "Isolate Affected Systems",
        description: "Immediately isolate systems showing C2 communication patterns",
        category: "containment",
        priority: "CRITICAL",
        estimated_time: "15 minutes",
        prerequisites: ["Network access", "Administrative privileges"],
        steps: [
          "Identify affected IP addresses from analysis",
          "Block network access at firewall level",
          "Notify network security team"
        ],
        verification: "Confirm no outbound connections from isolated systems",
        automation_possible: true,
        impact_level: "Medium"
      },
      {
        title: "Analyze Network Logs",
        description: "Review network logs for additional compromise indicators",
        category: "investigation",
        priority: "HIGH",
        estimated_time: "30 minutes",
        prerequisites: ["Access to network logs", "SIEM tools"],
        steps: [
          "Query logs for similar traffic patterns",
          "Identify other potentially affected systems",
          "Document findings"
        ],
        verification: "Complete log analysis report",
        automation_possible: false,
        impact_level: "Low"
      }
    ];

    const shortTermActions = [
      {
        title: "Deploy Enhanced Monitoring",
        description: "Implement additional monitoring for C2 patterns",
        category: "monitoring",
        priority: "MEDIUM",
        estimated_time: "2 hours",
        prerequisites: ["Monitoring tools", "Updated signatures"],
        steps: [
          "Configure C2 detection rules",
          "Set up alerting",
          "Test detection accuracy"
        ],
        verification: "Monitoring rules active and tested",
        automation_possible: true,
        impact_level: "Low"
      }
    ];

    const longTermActions = [
      {
        title: "Security Architecture Review",
        description: "Review and strengthen security architecture",
        category: "prevention",
        priority: "MEDIUM",
        estimated_time: "1 week",
        prerequisites: ["Security team", "Architecture documentation"],
        steps: [
          "Review current security controls",
          "Identify gaps in C2 detection",
          "Implement improvements"
        ],
        verification: "Updated security architecture",
        automation_possible: false,
        impact_level: "Low"
      }
    ];

    return {
      threat_id: `TH-${Date.now()}`,
      threat_type: "Command and Control Communication",
      threat_level: threatLevel,
      confidence_score: score,
      generated_at: new Date(),
      immediate_actions: immediateActions,
      short_term_actions: shortTermActions,
      long_term_actions: longTermActions,
      monitoring_recommendations: [
        "Implement network traffic baselines",
        "Deploy behavioral analysis tools",
        "Regular threat hunting activities"
      ],
      prevention_measures: [
        "Employee security awareness training",
        "Regular security assessments",
        "Network segmentation improvements"
      ],
      estimated_total_time: "4-6 hours immediate, 1-2 weeks complete",
      business_impact_assessment: "Medium impact during containment phase, minimal long-term impact with proper remediation",
      compliance_considerations: [
        "Document incident response actions",
        "Report to relevant authorities if required",
        "Maintain audit trail"
      ]
    };
  }

  static async uploadAndAnalyze(file: File): Promise<{ analysis_id: string; filename: string; report: MockAnalysisReport }> {
    // Simulate upload and analysis delay
    await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 2000));
    
    const analysisId = `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const report = this.generateMockReport(file.name);
    
    return {
      analysis_id: analysisId,
      filename: file.name,
      report
    };
  }
}
