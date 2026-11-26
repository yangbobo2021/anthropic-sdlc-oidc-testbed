"""Check the exact IAM example inputs against authentic GitHub OIDC claims."""

from base64 import urlsafe_b64decode
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

ISSUER = "https://token.actions.githubusercontent.com"
PUBLIC_KEYS = (
    "iss", "aud", "sub", "repository", "repository_id", "repository_owner_id", "environment",
    "ref", "ref_protected", "workflow_ref", "job_workflow_ref", "job_workflow_sha", "run_id",
)


def http(url, headers, payload=None):
    if payload is not None:
        headers = {**headers, "Content-Type": "application/json"}
    request = Request(url, data=json.dumps(payload).encode() if payload is not None else None, headers=headers)
    try:
        response = urlopen(request, timeout=18)
    except HTTPError as error:
        response = error
    with response:
        body = response.read()
        return response.status, json.loads(body) if body else {}


def request_token():
    endpoint = urlsplit(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])
    query = parse_qsl(endpoint.query)
    query.append(("audience", os.environ["AUDIENCE"]))
    url = urlunsplit(endpoint._replace(query=urlencode(query)))
    headers = {"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}
    status, reply = http(url, headers)
    assert status == 200
    return reply["value"]


def create_role(name, audience, subject):
    data = {
        "role_type": "jwt", "user_claim": "sub", "bound_subject": subject,
        "bound_audiences": [audience], "token_ttl": 120, "token_explicit_max_ttl": 120,
        "token_no_default_policy": True,
    }
    headers = {"X-Vault-Token": os.environ["BAO_TOKEN"]}
    status, _ = http(os.environ["BAO_ADDR"] + "/v1/auth/jwt/role/" + name, headers, data)
    assert status == 204, status


def verify(token, role):
    status, response = http(
        os.environ["BAO_ADDR"] + "/v1/auth/jwt/login", {}, {"jwt": token, "role": role}
    )
    if status == 200:
        lease = response["auth"]["lease_duration"]
        assert response["auth"]["client_token"] and 0 < lease <= 120
        return {"http": status, "ttl": lease}
    return {"http": status, "errors": response.get("errors", [])}


def main():
    key = Path("probe/trust.json").read_bytes()
    statement = json.loads(key)["Statement"][0]
    exact = statement["Condition"]["StringEquals"]
    issuer_host = urlsplit(ISSUER).netloc
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert statement["Principal"]["Federated"].endswith("oidc-provider/" + issuer_host)
    expected = {claim: exact[f"{issuer_host}:{claim}"] for claim in ("aud", "sub")}

    token = request_token()
    encoded = token.split(".")[1]
    claims = json.loads(urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert claims["iss"] == ISSUER and claims["aud"] == os.environ["AUDIENCE"]
    assert claims["environment"] == os.environ["EXPECTED_ENVIRONMENT"]
    assert claims["repository"] == os.environ["GITHUB_REPOSITORY"]
    assert claims["run_id"] == os.environ["GITHUB_RUN_ID"]
    create_role("control", claims["aud"], claims["sub"])
    create_role("policy", expected["aud"], expected["sub"])
    control, result = verify(token, "control"), verify(token, "policy")
    exact_mismatch = [claim for claim in expected if claims[claim] != expected[claim]]
    record = {
        "case": os.environ["CASE"],
        "claims": {key: claims[key] for key in PUBLIC_KEYS if key in claims},
        "expected": expected,
        "trust_sha256": sha256(key).hexdigest(),
        "checkout": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "mismatch": exact_mismatch, "issuer_control": control, "target": result,
    }
    print("SDLC0080_RECEIPT=" + json.dumps(record, sort_keys=True), flush=True)
    assert control["http"] == 200, control
    if record["case"] == "valid":
        assert not exact_mismatch and result["http"] == 200, record
    else:
        assert exact_mismatch == (["aud"] if record["case"] == "wrong-audience" else ["sub"]), record
        assert result["http"] == 400, result


if __name__ == "__main__":
    main()
