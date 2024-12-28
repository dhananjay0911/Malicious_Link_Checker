# Malicious_Link_Checker
#Description
The Malicious Link Checker is a Python-based application that allows users to check whether a given URL is malicious or safe. Using the VirusTotal API, it analyzes the input URL against a database of known threats and provides a detailed status report, helping users stay secure online.

#Features
Easy-to-use CLI (Command-Line Interface) for URL checking.
Integration with the VirusTotal API for real-time threat analysis.
Provides a summary of malicious, suspicious, and harmless results.
Lightweight and fast, suitable for testing URLs individually.

#Prerequisites
Ensure the following are installed on your system:

Python 3.7 or higher
Pip (Python Package Installer)
A valid VirusTotal API key (free API keys can be obtained from VirusTotal).

#Installation
Clone the repository:
git clone https://github.com/dhananjay0911/Malicious_Link_Checker.git
cd Malicious-Link-Checker
Install required dependencies:


# pip install -r requirements.txt
Add your VirusTotal API key:

Navigate to the config/config.py file.
Replace "your_api_key_here" with your actual VirusTotal API key.

Usage
Run the script:

python url_checker.py
Enter the URL you want to check:

Enter the URL to check: http://example.com
View the result in the terminal:

The script will display whether the URL is safe, suspicious, or malicious based on VirusTotal's analysis.

#Sample Output
Enter the URL to check: http://testphp.vulnweb.com

Results for URL: http://testphp.vulnweb.com
-------------------------------------------------
Malicious: 5
Suspicious: 2
Harmless: 58

This URL is flagged as MALICIOUS.

Dependencies
The project uses the following Python libraries:

requests: For making HTTP requests to the VirusTotal API.
argparse: For handling command-line arguments.

#To install dependencies:

pip install -r requirements.txt

python code
API_KEY = "your_api_key_here"  # Replace with your VirusTotal API key

API_URL = "https://www.virustotal.com/api/v3/urls"

This script checks the functionality of the url_checker.py file using sample URLs.

#Limitations
API Limit: The free VirusTotal API key has rate limits (e.g., 500 requests per day).
False Positives/Negatives: VirusTotal may flag harmless URLs as malicious or vice versa.

#Future Enhancements
Add a GUI for improved user interaction.
Batch URL checking from a file.
Display results as a detailed HTML report.
Integration with other threat intelligence APIs.
















