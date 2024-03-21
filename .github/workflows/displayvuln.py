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
    owner = 'YourOwner'  # Replace with your GitHub repository owner
    repo = 'YourRepo'  # Replace with your GitHub repository name
    token = os.getenv('MAN_GITHUB_TOKEN')  # Retrieve GitHub token from environment variable

    try:
        alerts = fetch_code_scanning_alerts(owner, repo, token)
        for alert in alerts:
            severity = alert.get('rule', {}).get('severity')
            if severity in ('HIGH', 'CRITICAL'):
                cwe_id = alert.get('rule', {}).get('description', '').split(':')[0].strip()
                likelihood = get_likelihood_of_exploitability(cwe_id)
                if likelihood in ('High', 'Very High'):
                    print(f"Severity: {severity}, CWE ID: {cwe_id}, Likelihood of Exploitability: {likelihood}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
