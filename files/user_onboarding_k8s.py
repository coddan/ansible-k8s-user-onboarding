import os
import yaml
import subprocess
import base64
import json

def run_command(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{stderr}")
    return stdout.strip()

def generate_key_cert(user, group):
    os.makedirs(f"/tmp/certs/{user}", exist_ok=True)
    key_file = f"/tmp/certs/{user}/{user}-key.pem"
    csr_file = f"/tmp/certs/{user}/{user}.csr"
    crt_file = f"/tmp/certs/{user}/{user}.crt"
    
    # Generate private key
    run_command(f"openssl genrsa -out {key_file} 2048")
    
    # Generate CSR
    run_command(f"openssl req -new -key {key_file} -out {csr_file} -subj '/CN={user}/O={group}'")
    
    # Create Kubernetes CSR YAML
    csr_yaml = f"/tmp/certs/{user}/{user}-csr.yaml"
    with open(csr_file, "rb") as f:
        csr_b64 = base64.b64encode(f.read()).decode()
    
    csr_manifest = {
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": {"name": user},
        "spec": {
            "groups": [group],
            "request": csr_b64,
            "signerName": "kubernetes.io/kube-apiserver-client",
            "usages": ["client auth"]
        }
    }
    
    with open(csr_yaml, "w") as f:
        yaml.dump(csr_manifest, f)
    
    # Apply CSR and approve
    run_command(f"kubectl delete csr {user} --ignore-not-found=true")
    run_command(f"kubectl apply -f {csr_yaml}")
    run_command(f"kubectl certificate approve {user}")
    
    # Fetch the signed certificate
    cert = run_command(f"kubectl get csr {user} -o jsonpath='{{.status.certificate}}' | base64 --decode")
    with open(crt_file, "w") as f:
        f.write(cert)
    
    return key_file, crt_file

def generate_kubeconfig(user, key_file, crt_file, namespaces):
    """Generate kubeconfig for the user."""
    kubeconfig = f"/tmp/certs/{user}/kubeconfig"
    cluster_name = run_command("kubectl config view --minify -o jsonpath='{.clusters[0].name}'")
    cluster_server = run_command("kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'")
    ca_cert = run_command("kubectl get configmap -n kube-system kube-root-ca.crt -o jsonpath='{.data.ca\\.crt}' | base64 --wrap=0")
    
    config = {"apiVersion": "v1", "kind": "Config", "clusters": [], "users": [], "contexts": [], "current-context": ""}

    user_entry = {
        "name": user,
        "user": {
            "client-certificate-data": base64.b64encode(open(crt_file, "rb").read()).decode(),
            "client-key-data": base64.b64encode(open(key_file, "rb").read()).decode()
        }
    }

    config["users"].append(user_entry)

    config["clusters"].append({
        "name": cluster_name,
        "cluster": {"server": cluster_server, "certificate-authority-data": ca_cert}
    })

    for namespace in namespaces:
        config["contexts"].append({
            "name": f"{user}@{cluster_name}-{namespace}",
            "context": {"cluster": cluster_name, "user": user, "namespace": namespace}
        })

    config["current-context"] = config["contexts"][0]["name"]

    with open(kubeconfig, "w") as f:
        yaml.dump(config, f)

    print(f"Kubeconfig for {user} updated at {kubeconfig}")

def handle_permissions(user, permissions_list, namespaces):
  
    # Ensure permissions_list is a list of JSON strings
    if not isinstance(permissions_list, list):
        raise ValueError(f"Permissions should be a list of JSON strings, got: {type(permissions_list)}")

    merged_permissions = {}

    for perm in permissions_list:
        try:
            perm_dict = json.loads(perm)  # Parse each JSON string
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in permissions: {perm}") from e

        if not isinstance(perm_dict, dict):
            raise ValueError(f"Parsed permission is not a dictionary: {perm_dict}")

        # Merge permissions
        for resource, verbs in perm_dict.items():
            if resource in merged_permissions:
                merged_permissions[resource].extend(verbs)
                merged_permissions[resource] = list(set(merged_permissions[resource]))  # Remove duplicates
            else:
                merged_permissions[resource] = verbs

    # Apply roles and bindings
    for namespace in namespaces:
        role_yaml = f"/tmp/certs/{user}/{user}-role-{namespace}.yaml"
        rolebinding_yaml = f"/tmp/certs/{user}/{user}-rolebinding-{namespace}.yaml"

        role_data = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {
                "name": f"{user}-role",
                "namespace": namespace
            },
            "rules": []
        }

        for resource, verbs in merged_permissions.items():
            role_data["rules"].append({
                "apiGroups": ["apps"] if resource in ["deployments", "statefulsets", "replicasets"] else [""],
                "resources": [resource],
                "verbs": verbs
        })

        with open(role_yaml, "w") as f:
            yaml.dump(role_data, f)

        rolebinding_data = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": f"{user}-rolebinding",
                "namespace": namespace
            },
            "subjects": [{"kind": "User", "name": user, "apiGroup": "rbac.authorization.k8s.io"}],
            "roleRef": {"kind": "Role", "name": f"{user}-role", "apiGroup": "rbac.authorization.k8s.io"}
        }

        with open(rolebinding_yaml, "w") as f:
            yaml.dump(rolebinding_data, f)

        try:
            run_command(f"kubectl apply -f {role_yaml} -n {namespace}")
            run_command(f"kubectl apply -f {rolebinding_yaml} -n {namespace}")
            print(f"Role and RoleBinding for {user} successfully applied in namespace {namespace}.")
        except RuntimeError as e:
            print(f"Error applying role and rolebinding for {user} in namespace {namespace}: {e}")



def main():
    # Read the environment variables passed by Ansible
    user = os.getenv('USERNAME')
    group = os.getenv('GROUP')
    namespaces = os.getenv('NAMESPACES').split(',')  # Convert the comma-separated string back to a list
    permissions = os.getenv('PERMISSIONS')

    if not all([user, group, namespaces, permissions]):
        print("Missing required environment variables")
        return
    
    try:
        # Ensure permissions is always parsed correctly
        permissions_data = json.loads(permissions)

        if isinstance(permissions_data, dict):  
            # Wrap single dict in a list
            permissions_list = [json.dumps(permissions_data)]
        elif isinstance(permissions_data, list):  
            # Ensure all elements are JSON strings
            permissions_list = [json.dumps(perm) if isinstance(perm, dict) else perm for perm in permissions_data]
        else:
            raise ValueError(f"Unexpected permissions format: {type(permissions_data)}")

    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in PERMISSIONS: {permissions}")
    
    key_file, crt_file = generate_key_cert(user, group)
    generate_kubeconfig(user, key_file, crt_file, namespaces)
    handle_permissions(user, permissions_list, namespaces)
    
    print(f"User {user} setup completed.")

if __name__ == "__main__":
    main()
