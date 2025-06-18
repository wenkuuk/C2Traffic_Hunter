
import { Shield, ArrowRight, Activity, Search, BarChart3 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useNavigate } from "react-router-dom";

const Index = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <div className="flex justify-center mb-6">
            <Shield className="h-16 w-16 text-blue-600" />
          </div>
          <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
            C2 Traffic Detection
          </h1>
          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
            Enterprise-grade threat detection system using advanced signature analysis, 
            machine learning, and behavioral pattern recognition to identify command and control traffic.
          </p>
          <Button 
            size="lg" 
            className="px-8 py-3 text-lg"
            onClick={() => navigate('/c2-detector')}
          >
            Start Analysis
            <ArrowRight className="ml-2 h-5 w-5" />
          </Button>
        </div>

        <div className="grid md:grid-cols-3 gap-8 mb-16">
          <Card className="text-center border-0 shadow-lg">
            <CardHeader>
              <Search className="h-12 w-12 text-blue-600 mx-auto mb-4" />
              <CardTitle>Signature Detection</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-base">
                Identifies known malicious patterns in domains, paths, user agents, 
                and payload signatures based on threat intelligence.
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="text-center border-0 shadow-lg">
            <CardHeader>
              <Activity className="h-12 w-12 text-green-600 mx-auto mb-4" />
              <CardTitle>ML Feature Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-base">
                Extracts statistical features like entropy, character ratios, 
                and timing patterns to detect suspicious communications.
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="text-center border-0 shadow-lg">
            <CardHeader>
              <BarChart3 className="h-12 w-12 text-purple-600 mx-auto mb-4" />
              <CardTitle>Behavioral Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-base">
                Analyzes communication patterns, beaconing behavior, and anomalies 
                across multiple sessions to identify C2 activity.
              </CardDescription>
            </CardContent>
          </Card>
        </div>

        <div className="bg-white rounded-lg shadow-lg p-8 max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 text-center">
            How It Works
          </h2>
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-3">
                1. Upload PCAP File
              </h3>
              <p className="text-gray-600 mb-4">
                Upload your network capture file (.pcap) containing the traffic you want to analyze.
              </p>
              
              <h3 className="text-lg font-semibold text-gray-900 mb-3">
                2. Multi-Layer Analysis
              </h3>
              <p className="text-gray-600">
                Our system runs signature-based detection, ML feature extraction, 
                and behavioral analysis simultaneously for comprehensive coverage.
              </p>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-3">
                3. Threat Assessment
              </h3>
              <p className="text-gray-600 mb-4">
                Get a detailed threat assessment with scoring from LOW to CRITICAL 
                based on the detected indicators.
              </p>
              
              <h3 className="text-lg font-semibold text-gray-900 mb-3">
                4. Detailed Reports
              </h3>
              <p className="text-gray-600">
                Review comprehensive reports with specific findings, confidence scores, 
                and actionable intelligence for your security team.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
