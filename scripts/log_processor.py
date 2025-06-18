import json
import configparser
from datetime import datetime
from elasticsearch import Elasticsearch

class LogProcessor:
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('/workspace/config/config.ini')
        
        self.es = Elasticsearch(config['ELASTIC']['URL'])
        self.index_name = config['ELASTIC']['INDEX']
        
    def create_index(self):
        if not self.es.indices.exists(index=self.index_name):
            self.es.indices.create(
                index=self.index_name,
                body={
                    "mappings": {
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "event_type": {"type": "keyword"},
                            "source_ip": {"type": "ip"},
                            "user": {"type": "keyword"},
                            "details": {"type": "text"}
                        }
                    }
                }
            )
    
    def process_log(self, log_data):
        """Process and store security logs"""
        log_entry = {
            "@timestamp": datetime.utcnow().isoformat(),
            **log_data
        }
        
        try:
            self.es.index(
                index=self.index_name,
                document=log_entry
            )
            return True
        except Exception as e:
            print(f"Error indexing log: {e}")
            return False

if __name__ == "__main__":
    processor = LogProcessor()
    processor.create_index()
    
    test_logs = [
        {"event_type": "auth_fail", "source_ip": "192.168.1.100", "user": "admin"},
        {"event_type": "file_change", "source_ip": "10.0.0.15", "details": "Sensitive file modified"}
    ]
    
    for log in test_logs:
        processor.process_log(log)
