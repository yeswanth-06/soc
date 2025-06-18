import configparser
import requests
from elasticsearch import Elasticsearch
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

class ThreatIntel:
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('/workspace/config/config.ini')
        
        self.es = Elasticsearch(config['ELASTIC']['URL'])
        self.index = config['ELASTIC']['INDEX']
        self.hive = TheHiveApi(
            config['THEHIVE']['URL'],
            config['THEHIVE']['API_KEY']
        )
    
    def check_ioc(self, ioc, ioc_type):
        """Check indicators of compromise"""
        # Check internal logs first
        log_results = self.es.search(
            index=self.index,
            body={
                "query": {
                    "term": {
                        ioc_type: ioc
                    }
                }
            }
        )
        
        # Check external sources (simplified)
        if ioc_type == "source_ip":
            abuse_score = self.check_abuseipdb(ioc)
            if abuse_score > 50:
                self.create_alert(
                    f"Malicious IP detected: {ioc}",
                    ioc,
                    ioc_type,
                    f"AbuseIPDB score: {abuse_score}"
                )
                return True
        
        return False
    
    def check_abuseipdb(self, ip):
        """Simulated threat intel check"""
        # In production, use real API:
        # response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}")
        # return response.json().get('data', {}).get('abuseConfidenceScore', 0)
        return 75 if ip == "192.168.1.100" else 10
    
    def create_alert(self, title, ioc, ioc_type, description):
        alert = Alert(
            title=title,
            type="external",
            source="SOC Automation",
            description=description,
            artifacts=[
                AlertArtifact(
                    dataType=ioc_type,
                    data=ioc
                )
            ]
        )
        return self.hive.create_alert(alert)

if __name__ == "__main__":
    ti = ThreatIntel()
    ti.check_ioc("192.168.1.100", "source_ip")
