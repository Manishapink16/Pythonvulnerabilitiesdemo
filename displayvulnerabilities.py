import os
import requests
from bs4 import BeautifulSoup
import subprocess
import json

# Function to perform Bandit scan and parse results
def run_bandit_scan():
    result = subprocess.run(['bandit', '-r', '.'], capture_output=True, text=True)
    return result.stdout

# Function to fetch code scanning alerts from GitHub
def fetch_code_scanning_alerts(repo_owner, repo_name, severity):
    github_token = os.getenv('SGITHUB_TOKEN')
    headers = {'Authorization': f'token {github_token}'}
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/code-scanning/alerts'
    params = {'state': 'open', 'severity': severity}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch code scanning alerts: {response.status_code}")
        return []

# Function to fetch 'Likelihood of exploitability' from CWE website
def fetch_likelihood_of_exploitability(cwe_id):
    url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Assuming the 'Likelihood of exploitability' is present in a specific div
        likelihood_div = soup.find('div', {'id': 'applicable_platforms'})
        if likelihood_div:
            likelihood = likelihood_div.find_next('div').text.strip()
            return likelihood
    return None

# Main function
def main():
    # Perform Bandit scan and parse results
    bandit_results = run_bandit_scan()

    # Fetch code scanning alerts from GitHub
    code_scanning_alerts = fetch_code_scanning_alerts(repo_owner='Manishapink16', repo_name='Pythonvulnerabilitiesdemo', severity='high')

    # Extract vulnerability details
    vulnerabilities = []
    for alert in code_scanning_alerts:
        vulnerability = {
            'rule_id': alert['rule_id'],
            'file': alert['file'],
            'line': alert['line'],
            'message': alert['message'],
            'likelihood_of_exploitability': fetch_likelihood_of_exploitability(alert['rule_id'])
        }
        vulnerabilities.append(vulnerability)

    # Print list of vulnerabilities with severity High or above AND 'Likelihood of exploitability' High or above
    print("Vulnerabilities with severity High or above AND Likelihood of exploitability High or above:")
    for vulnerability in vulnerabilities:
        if vulnerability['likelihood_of_exploitability'] == 'High':
            print(vulnerability)

if __name__ == "__main__":
    main()
