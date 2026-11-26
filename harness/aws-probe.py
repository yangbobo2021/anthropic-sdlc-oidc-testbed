#!/usr/bin/env python3
"""Exercise real GitHub OIDC, AWS STS and S3 without printing credentials."""

import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

ISSUER = "https://token.actions.githubusercontent.com"
AUDIENCE = "sts.amazonaws.com"
PROBE = ".github/workflows/sdlc0080-aws-probe.yml"
CONTEXT = "production"


def fetch_token(audience):
    source = urlsplit(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])
    query = [pair for pair in parse_qsl(source.query) if pair[0] != "audience"]
    query.append(("audience", audience))
    target = urlunsplit(source._replace(query=urlencode(query)))
    headers = {"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}
    with urlopen(Request(target, headers=headers), timeout=20) as response:
        return json.load(response)["value"]


def claim_summary(token, audience):
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    repository = os.environ["GITHUB_REPOSITORY"]
    owner, name = repository.split("/")
    workflow = f"{repository}/{PROBE}@refs/heads/main"
    expected = (
        f"repo:{owner}@{os.environ['GITHUB_REPOSITORY_OWNER_ID']}/"
        f"{name}@{os.environ['GITHUB_REPOSITORY_ID']}:environment:{CONTEXT}:job_workflow_ref:{workflow}"
    )
    checks = {
        "iss": ISSUER, "aud": audience, "sub": expected, "ref": "refs/heads/main",
        "repository": repository, "environment": CONTEXT, "job_workflow_ref": workflow,
        "run_id": os.environ["GITHUB_RUN_ID"], "sha": os.environ["GITHUB_SHA"],
        "job_workflow_sha": os.environ["GITHUB_SHA"],
    }
    for name, expected_value in checks.items():
        if str(claims.get(name)) != expected_value:
            raise SystemExit(f"Issued claim mismatch: {name}")
    return checks


def aws(service, command, arguments, credentials=None):
    region = os.environ["SANDBOX_AWS_REGION"]
    if not re.fullmatch(r"(?:us|af|ap|ca|eu|il|me|mx|sa)-[a-z]+-[1-9][0-9]*", region):
        raise SystemExit("Expected a commercial AWS region")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
    environment.update(
        AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
        AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="", AWS_MAX_ATTEMPTS="2",
    )
    if credentials:
        environment.update(AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                           AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
                           AWS_SESSION_TOKEN=credentials["SessionToken"])
    endpoint_service = "s3" if service == "s3api" else service
    result = subprocess.run(
        ["aws", "--no-cli-pager", "--region", region, "--output", "json",
         "--endpoint-url", f"https://{endpoint_service}.{region}.amazonaws.com",
         "--cli-connect-timeout", "10", "--cli-read-timeout", "20", service, command, *arguments],
        env=environment, capture_output=True, text=True, check=False, timeout=120,
    )
    response_code = re.search(r"An error occurred \(([A-Za-z0-9]+)\)", result.stderr)
    return result, response_code[1] if response_code else "unclassified"


def assume(role, token_file):
    return aws("sts", "assume-role-with-web-identity", [
        "--no-sign-request", "--role-arn", role, "--duration-seconds", "900",
        "--role-session-name", f"sdlc-{os.environ['GITHUB_RUN_ID']}",
        "--web-identity-token", f"file://{token_file}",
    ])


def require_denied(result, code, reason, accepted_codes):
    if result.returncode == 0 or code not in accepted_codes:
        raise SystemExit(f"{reason}: expected AWS denial, received exit={result.returncode}, code={code}")
    return code


def validate_cli_operations():
    operations = [
        ("sts", "assume-role-with-web-identity", {"RoleArn", "WebIdentityToken"}),
        ("s3api", "put-object", {"Bucket", "Key", "Body"}),
    ]
    for service, command, fields in operations:
        result = subprocess.run(
            ["aws", "--no-cli-pager", service, command, "--generate-cli-skeleton", "input"],
            capture_output=True, text=True, check=False, timeout=20,
        )
        if result.returncode != 0 or not fields.issubset(json.loads(result.stdout)):
            raise SystemExit(f"AWS CLI could not validate {service} {command}")
    # The CLI omits skeletons for streaming-output commands such as GetObject.
    help_result = subprocess.run(
        ["aws", "--no-cli-pager", "s3api", "get-object", "help"],
        env={**os.environ, "MANPAGER": "cat", "PAGER": "cat", "GROFF_NO_SGR": "1"},
        capture_output=True, text=True, check=False, timeout=20,
    )
    help_text = re.sub(r".\x08", "", help_result.stdout)
    if help_result.returncode != 0 or not all(term in help_text for term in ("--bucket", "--key", "outfile")):
        raise SystemExit(f"AWS CLI could not inspect s3api get-object help, exit={help_result.returncode}")
    return subprocess.check_output(["aws", "--version"], text=True, timeout=20).strip()


def main():
    token = fetch_token(AUDIENCE)
    claims = claim_summary(token, AUDIENCE)
    report = {"phase": os.environ["PROBE_PHASE"], "claims": claims}
    if report["phase"] == "preflight":
        report["aws_cli"] = validate_cli_operations()
        print(json.dumps(report))
        return
    if report["phase"] != "aws":
        raise SystemExit("Expected preflight or aws phase")

    probe_role = os.environ["SANDBOX_PROBE_ROLE"]
    if claims["sub"] != os.environ["SANDBOX_PROBE_SUBJECT"]:
        raise SystemExit("Live GitHub subject differs from the deployed stack")
    bucket = os.environ["SANDBOX_BUCKET"]
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        path = temp / "token"
        path.write_text(token)
        positive, code = assume(probe_role, path)
        if positive.returncode != 0:
            raise SystemExit(f"Matching token was rejected by AWS STS: {code}")
        response = json.loads(positive.stdout)
        credentials = response["Credentials"]
        account, role_name = probe_role.split(":")[4], probe_role.rsplit("/", 1)[1]
        expected_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/sdlc-{claims['run_id']}"
        if (response["AssumedRoleUser"]["Arn"] != expected_arn
                or response["SubjectFromWebIdentityToken"] != claims["sub"]
                or response["Audience"] != AUDIENCE):
            raise SystemExit("AWS STS returned an unexpected subject, audience or role")
        report["sts"] = {"assumed_role": expected_arn, "expiration": credentials["Expiration"]}

        denials = {}
        for axis in ("REPOSITORY", "ENVIRONMENT", "WORKFLOW", "REF"):
            negative, code = assume(os.environ[f"SANDBOX_WRONG_{axis}_ROLE"], path)
            denials[axis.lower()] = require_denied(negative, code, axis, {"AccessDenied"})
        wrong_audience = "https://example.invalid/sdlc0080"
        wrong_token = fetch_token(wrong_audience)
        claim_summary(wrong_token, wrong_audience)
        path.write_text(wrong_token)
        negative, code = assume(probe_role, path)
        denials["audience"] = require_denied(
            negative, code, "audience", {"AccessDenied", "InvalidIdentityToken"},
        )
        report["sts_denials"] = denials

        receipt = temp / "receipt.json"
        receipt.write_text(json.dumps({"run_id": claims["run_id"], "sha": claims["sha"]}) + "\n")
        suffix = f"{claims['run_id']}-{os.environ['GITHUB_RUN_ATTEMPT']}.json"
        key = f"deployment-receipts/{suffix}"
        target = temp / "result.json"
        put, code = aws("s3api", "put-object", ["--bucket", bucket, "--key", key, "--body", str(receipt)],
                        credentials)
        if put.returncode != 0:
            raise SystemExit(f"Authorized S3 PutObject failed: {code}")
        read, code = aws("s3api", "get-object", ["--bucket", bucket, "--key", key, str(target)],
                         credentials)
        if read.returncode != 0 or target.read_bytes() != receipt.read_bytes():
            raise SystemExit(f"Authorized S3 GetObject or payload check failed: {code}")
        deny, code = aws("s3api", "put-object", [
            "--bucket", bucket, "--key", f"unrelated/{suffix}", "--body", str(receipt),
        ], credentials)
        report["s3"] = {"write_and_read": key, "out_of_scope_write":
                        require_denied(deny, code, "unrelated prefix", {"AccessDenied"})}
    print(json.dumps(report))


if __name__ == "__main__":
    main()
