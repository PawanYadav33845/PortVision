import os
import json
from datetime import datetime

def export_results_to_json(session_data: dict) -> str:
    """
    Serializes network data findings into an indexed, schema-compliant JSON file.
    """
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports"))
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"session_capture_{timestamp_str}.json"
    file_path = os.path.join(reports_dir, filename)
    
    with open(file_path, "w", encoding="utf-8") as json_file:
        json.dump(session_data, json_file, indent=4, ensure_ascii=False)
        
    return file_path