import configparser
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask

class AlertResponder:
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('/workspace/config/config.ini')
        
        self.hive = TheHiveApi(
            config['THEHIVE']['URL'],
            config['THEHIVE']['API_KEY']
        )
    
    def create_case(self, alert_id):
        """Convert alert to investigation case"""
        alert = self.hive.get_alert(alert_id)
        
        case = Case(
            title=f"Investigation: {alert.json()['title']}",
            description=alert.json()['description'],
            tlp=2,
            severity=2
        )
        
        created_case = self.hive.create_case(case)
        
        # Add standard investigation tasks
        tasks = [
            CaseTask(title="Initial Triage", status="Waiting"),
            CaseTask(title="Evidence Collection", status="Waiting"),
            CaseTask(title="Containment", status="Waiting")
        ]
        
        for task in tasks:
            self.hive.create_case_task(created_case.json()['id'], task)
        
        return created_case

if __name__ == "__main__":
    responder = AlertResponder()
    # In production, would get alert ID from TheHive webhook
    responder.create_case("~123456") 
