import requests
import json
import sys


def _parse_acr_name(acr_registry_url):
    if not acr_registry_url:
        return None
    registry = acr_registry_url.replace("https://", "").replace("http://", "")
    registry = registry.split("/")[0]
    return registry.split(".")[0] if "." in registry else registry


def _error_detail(response):
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return payload.get("detail") or payload.get("message") or json.dumps(payload)
        return str(payload)
    except ValueError:
        return response.text.strip()


def get_dockerhub_images(arcgis_version, acr_registry_url, acr_identity_client_id, username, password, organization):
    # Authenticate with Docker Hub
    auth_url = "https://hub.docker.com/v2/auth/token"
    auth_payload = {"identifier": username, "secret": password}
    auth_response = requests.post(auth_url, json=auth_payload, timeout=30)
    
    if auth_response.status_code != 200:
        detail = _error_detail(auth_response)
        print(json.dumps({"error": f"Failed to authenticate. Status code: {auth_response.status_code}. Details: {detail}"}))
        sys.exit(1)

    token = auth_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Get list of repositories for the organization
    org_url = f"https://hub.docker.com/v2/repositories/{organization}/"
    all_data = []

    while org_url:
        response = requests.get(org_url, headers=headers, timeout=30)
        if response.status_code != 200:
            detail = _error_detail(response)
            print(json.dumps({"error": f"Failed to retrieve repositories. Status code: {response.status_code}. Details: {detail}"}))
            sys.exit(1)

        repositories = response.json().get('results', [])
        org_url = response.json().get('next', None)

        for repo in repositories:
            repo_name = repo['name']
            tags_url = f"https://hub.docker.com/v2/repositories/{organization}/{repo_name}/tags/"
            repo_tags = []

            while tags_url:
                tags_response = requests.get(tags_url, headers=headers, timeout=30)
                if tags_response.status_code == 200:
                    tags = tags_response.json().get('results', [])
                    tags = [tag for tag in tags if '1234' not in tag['name'] and '-test' not in tag['name']]
                    repo_tags.extend(tags)
                    tags_url = tags_response.json().get('next', None)
                else:
                    detail = _error_detail(tags_response)
                    print(json.dumps({"error": f"Failed to retrieve tags for repository {repo_name}. Status code: {tags_response.status_code}. Details: {detail}"}))
                    sys.exit(1)

            for tag in repo_tags:
                if tag['name'].startswith(arcgis_version):
                    size_mb = tag['full_size'] / (1024 * 1024)
                    data = {
                        'cmd': f"docker pull {acr_registry_url}/{organization}/{repo_name}:{tag['name']}",
                        'displayName': f"Pull Container image to ACR: {repo_name} Version: {tag['name']} Size: {size_mb:.2f}MB",
                        'retries': 20,
                        'retryDelay': 10,
                        'timeout': 7200,
                    }
                    all_data.append(data)

    acr_name = _parse_acr_name(acr_registry_url)
    if not acr_name:
        print(json.dumps({"error": "acr_registry_url is required to build the ACR login step."}))
        sys.exit(1)

    # Derive the registry FQDN (e.g. arcgisk8s.azurecr.io) from the URL
    acr_registry_fqdn = acr_registry_url.replace("https://", "").replace("http://", "").split("/")[0]

    identity_login = "az login --identity --allow-no-subscriptions"

    # Manually construct YAML as a string (without using yaml module)
    yaml_output = f"""version: v1.1.0
steps:
  - cmd: {identity_login}
    displayName: 'Login to Azure with managed identity'
    id: az_login
    keep: true

  - cmd: az acr login --name {acr_name} --expose-token --output tsv --query accessToken > token.txt
    displayName: 'Get ACR access token'
    id: get_token
    when:
      - az_login
    keep: true

  - cmd: bash -c "cat token.txt" | docker login {acr_registry_fqdn} --username 00000000-0000-0000-0000-000000000000 --password-stdin
    displayName: 'Login to ACR with token'
    id: acr_login
    when:
      - get_token
"""

    for entry in all_data:
        yaml_output += f"""
  - cmd: {entry['cmd']}
    displayName: '{entry['displayName']}'
    retries: {entry['retries']}
    retryDelay: {entry['retryDelay']}
    timeout: {entry['timeout']}
    when:
      - acr_login
"""

    # Print JSON with the YAML string
    print(json.dumps({"output_yaml": yaml_output}))

    # Write the YAML string to a file
    # output_file_path = "ksn_output.yaml"
    # with open(output_file_path, "w") as output_file:
    #     output_file.write(yaml_output)

if __name__ == "__main__":
    # Read input from Terraform
    input_data = json.loads(sys.stdin.read())

    acr_registry_url = input_data.get("acr_registry_url")
    acr_identity_client_id = input_data.get("acr_identity_client_id")
    dockerhub_username = input_data.get("dockerhub_username")
    dockerhub_password = input_data.get("dockerhub_password")
    dockerhub_organization = input_data.get("dockerhub_organization", "esridocker")
    arcgis_version = input_data.get("arcgis_version", "11.4")

    get_dockerhub_images(
        arcgis_version, acr_registry_url, acr_identity_client_id,
        dockerhub_username, dockerhub_password, dockerhub_organization
    )
