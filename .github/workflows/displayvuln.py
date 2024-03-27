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

def get_pull_request_number_from_alert(alert, token):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    pr_url = alert.get('pull_request', {}).get('html_url')
    if pr_url:
        pr_number = pr_url.split('/')[-1]
        return pr_number
    return None

def comment_on_pull_request(owner, repo, pr_number, comment, token):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    url = f'https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments'
    data = {'body': comment}
    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()

def main():
    owner = 'Manishapink16'  # Replace with your GitHub repository owner
    repo = 'Pythonvulnerabilitiesdemo'  # Replace with your GitHub repository name
    token = os.getenv('MAN_GITHUB_TOKEN')  # Retrieve GitHub token from environment variable

    try:
        alerts = fetch_code_scanning_alerts(owner, repo, token)
        block_pr = False
        for alert in alerts:
            severity = alert.get('rule', {}).get('severity')
            if severity in ('HIGH', 'CRITICAL'):
                cwe_id = alert.get('rule', {}).get('description', '').split(':')[0].strip()
                likelihood = get_likelihood_of_exploitability(cwe_id)
                if likelihood in ('High', 'Very High'):
                    print(f"Severity: {severity}, CWE ID: {cwe_id}, Likelihood of Exploitability: {likelihood}")
                    pr_number = get_pull_request_number_from_alert(alert, token)
                    if pr_number:
                        block_pr = True
        if block_pr:
            comment_on_pull_request(owner, repo, pr_number, 'Block', token)
        else:
            comment_on_pull_request(owner, repo, pr_number, 'Successful', token)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

