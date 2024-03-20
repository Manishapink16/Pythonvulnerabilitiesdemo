import requests
from bs4 import BeautifulSoup
import json

def fetch_code_scanning_alerts(owner, repo, token):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    url = f'https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts'
    response = requests.get(url, headers=headers)
    return response.json()

def get_likelihood_of_exploitability(cwe_id):
    url = f'https://cwe.mitre.org/data/definitions/{cwe_id}.html'
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        likelihood_element = soup.find('span', id='div_Likelihood_of_Exploit')
        if likelihood_element:
            return likelihood_element.text.strip()
    return None

def main():
    owner = 'YourOwner'  # Replace with your GitHub repository owner
    repo = 'YourRepo'  # Replace with your GitHub repository name
    token = 'YourToken'  # Replace with your GitHub personal access token

    alerts = fetch_code_scanning_alerts(owner, repo, token)
    vulnerabilities = []

    for alert in alerts:
        if alert['rule']['severity'] in ('HIGH', 'CRITICAL'):
            cwe_id = alert['rule']['description'].split(':')[0].strip()
            likelihood = get_likelihood_of_exploitability(cwe_id)
            if likelihood and likelihood in ('High', 'Very High'):
                vulnerabilities.append({
                    'CWE ID': cwe_id,
                    'Severity': alert['rule']['severity'],
                    'Likelihood of Exploitability': likelihood
                })

    # Print vulnerabilities in a readable format
    print("Vulnerabilities with Severity High or above and Likelihood of Exploitability High or above:")
    for vulnerability in vulnerabilities:
        print(vulnerability)

    # Save vulnerabilities to a JSON file
    with open('vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)

if __name__ == "__main__":
    main()
