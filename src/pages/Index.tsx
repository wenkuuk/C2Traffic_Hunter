
import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Activity, AlertTriangle, FileSearch } from "lucide-react";

const Index: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
            Advanced C2 Traffic Detection
          </h1>
          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
            Sophisticated network traffic analysis with AI-powered threat detection, 
            behavioral analysis, and comprehensive remediation planning.
          </p>
          <Link to="/c2-detector">
            <Button size="lg" className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3">
              <Shield className="mr-2 h-5 w-5" />
              Start Analysis
            </Button>
          </Link>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          <Card className="text-center">
            <CardHeader>
              <Shield className="h-12 w-12 text-blue-600 mx-auto mb-4" />
              <CardTitle>Advanced Detection</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600">
                Multi-layered detection using signatures, ML, and behavioral analysis
              </p>
            </CardContent>
          </Card>

          <Card className="text-center">
            <CardHeader>
              <Activity className="h-12 w-12 text-green-600 mx-auto mb-4" />
              <CardTitle>Real-time Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600">
                Instant PCAP analysis with comprehensive threat assessment
              </p>
            </CardContent>
          </Card>

          <Card className="text-center">
            <CardHeader>
              <AlertTriangle className="h-12 w-12 text-orange-600 mx-auto mb-4" />
              <CardTitle>Threat Remediation</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600">
                Automated remediation plans with step-by-step response actions
              </p>
            </CardContent>
          </Card>

          <Card className="text-center">
            <CardHeader>
              <FileSearch className="h-12 w-12 text-purple-600 mx-auto mb-4" />
              <CardTitle>Detailed Reports</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600">
                Comprehensive analysis reports with confidence scoring
              </p>
            </CardContent>
          </Card>
        </div>

        <div className="text-center">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">
            Why Choose Our C2 Detection System?
          </h2>
          <div className="max-w-4xl mx-auto text-left">
            <div className="grid md:grid-cols-2 gap-8">
              <div>
                <h3 className="text-lg font-semibold mb-2">Enhanced Accuracy</h3>
                <p className="text-gray-600 mb-4">
                  Our correlation bonus system validates detections across multiple methods, 
                  significantly reducing false positives while maintaining high sensitivity.
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold mb-2">Actionable Intelligence</h3>
                <p className="text-gray-600 mb-4">
                  Every threat detection comes with detailed remediation plans, 
                  including immediate actions, timeline estimates, and business impact assessment.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
