---
 
## Project Goal
- Extract data from server log file using regex.
- Identify dangerous IPs and save in JSON format.
- Analyze log data and save in different formats (txt and csv).
  


---

## **Getting Started**

### **Prerequisites**
- Python 3.7 or later
- A virtual environment (optional but recommended)

### **Setup**

1. Clone the repository:
   ```bash
   git clone https://github.com/SakoAkk/Python-Lab2.git
   cd Python-Lab2
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate    # Windows
   source venv/bin/activate # macOS/Linux
   ```

3. Install dependencies(You can skip this part because there is no requirements.txt file in this project):
   ```bash
   pip install -r requirements.txt
   ```

## **Usage**

Run the script to analyze logs and generate output files:

```bash
python main.py
```

Project Structure Description
```plaintext
main.py: The main Python script for analyzing the log file and extracting results.
server_logs.txt: The log file. This file is used for analysis.
question.txt: Task questions and task details.
requirements.txt: Libraries required for the project to run.
failed_logins.json: List of IPs with more than 5 failed login attempts.
threat_ips.json: List of dangerous IPs.
combined_security_data.json: File that combines failed logins and dangerous IPs.
log_analysis.txt: Text file of log analysis results.
log_analysis.csv: Storage of log data in a table format.

