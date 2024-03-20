import os
import requests
from bs4 import BeautifulSoup

def fetch_code_scanning_alerts(owner, repo, token):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    url = f'https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts'
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def get_likelihood_of_exploitability(cwe_id):
    url = f'https://cwe.mitre.org/data/definitions/{cwe_id}.html'
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')
    likelihood_element = soup.find('span', id='div_Likelihood_of_Exploit')
    if likelihood_element:
        return likelihood_element.text.strip()
    return None

def main():
    owner = 'Manishapink16'  # Replace with your GitHub repository owner
    repo = 'Pythonvulnerabilitiesdemo'  # Replace with your GitHub repository name
    token = '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'  # Retrieve GitHub token from environment variable
    
    try:
        alerts = fetch_code_scanning_alerts(owner, repo, token)
        for alert in alerts:
            severity = alert['rule']['severity']
            if severity in ('HIGH', 'CRITICAL'):
                cwe_id = alert['rule']['description'].split(':')[0].strip()
                likelihood = get_likelihood_of_exploitability(cwe_id)
                if likelihood in ('High', 'Very High'):
                    print(f"Severity: {severity}, CWE ID: {cwe_id}, Likelihood of Exploitability: {likelihood}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
