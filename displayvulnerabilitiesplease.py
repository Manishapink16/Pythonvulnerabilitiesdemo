import requests
from bs4 import BeautifulSoup
import json
print("start")
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
    owner = 'Manishapink16'  # Replace with your GitHub repository owner
    repo = 'Pythonvulnerabilitiesdemo'  # Replace with your GitHub repository name
    token = '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'  # Replace with your GitHub personal access token

    alerts = fetch_code_scanning_alerts(owner, repo, token)
    vulnerabilities = []

    print(alerts)
    alerts_list = alerts

    for alert in alerts_list:
        if alert.get('rule', {}).get('severity') in ('HIGH', 'CRITICAL'):
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
