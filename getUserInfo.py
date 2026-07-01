from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import uuid
from typing import Any

import requests
import urllib3
from flask import Flask, jsonify, redirect, request, session, url_for
from flask_session import Session
from requests_oauthlib import OAuth2Session


app = Flask(__name__)
app.config.from_object("config")

app.config["SESSION_TYPE"] = "filesystem"
Session(app)

logging.basicConfig(level=logging.INFO)

SCOPE_ITERATIONS: list[list[str]] = [
    ["openid"],
    ["openid", "profile"],
    ["openid", "email"],
    ["openid", "phone"],
    ["openid", "address"],
    ["openid", "profile", "email", "phone", "address"],
]


def get_tls_verify_setting() -> bool | str:
    """
    Input:
        None
    Output:
        bool | str: TLS verification setting for requests-compatible calls.
    Description:
        Return the configured TLS verification behavior. Supports either a boolean
        or a CA bundle path from config.py.
    """
    verify_value = app.config.get("TLS_VERIFY", True)

    if verify_value is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return verify_value


def generate_code_verifier() -> str:
    """
    Input:
        None
    Output:
        str: PKCE code verifier.
    Description:
        Generate a random PKCE code verifier for the authorization code flow.
    """
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode("utf-8")


def generate_code_challenge(code_verifier: str) -> str:
    """
    Input:
        code_verifier (str): PKCE code verifier.
    Output:
        str: PKCE S256 code challenge.
    Description:
        Derive the PKCE S256 code challenge from the supplied verifier.
    """
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def normalize_scope(scope_value: str | list[str] | None) -> list[str]:
    """
    Input:
        scope_value (str | list[str] | None): Scope value from a request,
            token response, or metadata source.
    Output:
        list[str]: Ordered list of unique scope values.
    Description:
        Normalize scope input into a stable ordered list while preserving the
        first occurrence of each scope.
    """
    if scope_value is None:
        return []

    if isinstance(scope_value, list):
        raw_scopes = scope_value
    else:
        raw_scopes = str(scope_value).strip().split()

    seen: set[str] = set()
    result: list[str] = []

    for scope in raw_scopes:
        normalized = scope.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)

    return result


def scope_key(scopes: list[str]) -> str:
    """
    Input:
        scopes (list[str]): Scope list.
    Output:
        str: Canonical space-delimited scope key.
    Description:
        Convert a scope list into the canonical key used in workflow state and
        reporting.
    """
    return " ".join(normalize_scope(scopes))


def get_well_known_url() -> str:
    """
    Input:
        None
    Output:
        str: OpenID Provider configuration endpoint URL.
    Description:
        Build the .well-known OpenID configuration URL from OAUTH_URL_BASE in
        config.py.
    """
    base_url = str(app.config["OAUTH_URL_BASE"]).rstrip("/")
    return f"{base_url}/.well-known/openid-configuration"


def fetch_oidc_metadata(force_refresh: bool = False) -> dict[str, Any]:
    """
    Input:
        force_refresh (bool): Whether to bypass the session cache and re-read the
            metadata document.
    Output:
        dict[str, Any]: Parsed OpenID Provider metadata.
    Description:
        Retrieve the OpenID Provider metadata from the .well-known endpoint and
        cache it in the server-side session for reuse during the current report.
    """
    if not force_refresh:
        cached = session.get("oidc_metadata")
        if isinstance(cached, dict) and cached:
            return cached

    response = requests.get(
        get_well_known_url(),
        timeout=30,
        verify=get_tls_verify_setting(),
    )
    response.raise_for_status()

    metadata = response.json()
    session["oidc_metadata"] = metadata
    session.modified = True

    return metadata


def get_oauth_endpoints() -> dict[str, str]:
    """
    Input:
        None
    Output:
        dict[str, str]: Required discovered OIDC endpoints.
    Description:
        Return the authorization, token, userinfo, and issuer values from the
        OpenID Provider metadata document.
    """
    metadata = fetch_oidc_metadata()

    required_keys = [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "issuer",
    ]
    missing = [key for key in required_keys if key not in metadata]
    if missing:
        raise KeyError(f"Missing keys in OpenID metadata: {', '.join(missing)}")

    return {
        "authorization_endpoint": metadata["authorization_endpoint"],
        "token_endpoint": metadata["token_endpoint"],
        "userinfo_endpoint": metadata["userinfo_endpoint"],
        "issuer": metadata["issuer"],
    }


def get_oauth_client(scopes: list[str], state_value: str | None = None) -> OAuth2Session:
    """
    Input:
        scopes (list[str]): Requested scopes for the current OAuth flow.
        state_value (str | None): Optional OAuth state value.
    Output:
        OAuth2Session: Configured OAuth client.
    Description:
        Create an OAuth2Session bound to the configured client ID, redirect URI,
        requested scopes, and optional caller-supplied state value.
    """
    return OAuth2Session(
        client_id=app.config["OAUTH_CLIENT_ID"],
        redirect_uri=app.config["REDIRECT_URL"],
        scope=scopes,
        state=state_value,
    )


def initialize_report_workflow() -> dict[str, Any]:
    """
    Input:
        None
    Output:
        dict[str, Any]: Initialized workflow state.
    Description:
        Create a new server-side workflow object used to coordinate the chained
        UserInfo tests across all scope combinations.
    """
    workflow = {
        "report_id": str(uuid.uuid4()),
        "iterations": SCOPE_ITERATIONS,
        "current_index": 0,
        "results": {},
        "oauth_transactions": {},
        "processed_states": {},
    }
    session["userinfo_scope_report_workflow"] = workflow
    session.modified = True
    return workflow


def get_report_workflow() -> dict[str, Any] | None:
    """
    Input:
        None
    Output:
        dict[str, Any] | None: Active workflow state or None.
    Description:
        Load the current workflow from the server-side session.
    """
    workflow = session.get("userinfo_scope_report_workflow")
    return workflow if isinstance(workflow, dict) else None


def save_report_workflow(workflow: dict[str, Any]) -> None:
    """
    Input:
        workflow (dict[str, Any]): Updated workflow state.
    Output:
        None
    Description:
        Persist the workflow back into the server-side session store.
    """
    session["userinfo_scope_report_workflow"] = workflow
    session.modified = True


def clear_report_workflow() -> None:
    """
    Input:
        None
    Output:
        None
    Description:
        Remove the active workflow and cached metadata from the session.
    """
    session.pop("userinfo_scope_report_workflow", None)
    session.pop("oidc_metadata", None)
    session.modified = True


def build_oauth_state_payload(report_id: str, iteration_index: int, scopes: list[str]) -> str:
    """
    Input:
        report_id (str): Workflow correlation identifier.
        iteration_index (int): Current test iteration index.
        scopes (list[str]): Requested scopes for this iteration.
    Output:
        str: Base64url-encoded application state payload.
    Description:
        Serialize application workflow metadata into an opaque OAuth state value.
    """
    payload = {
        "report_id": report_id,
        "iteration_index": iteration_index,
        "scope_key": scope_key(scopes),
    }
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def parse_oauth_state_payload(state_value: str) -> dict[str, Any]:
    """
    Input:
        state_value (str): Base64url-encoded application state payload.
    Output:
        dict[str, Any]: Parsed application workflow metadata.
    Description:
        Decode the workflow data previously embedded in the OAuth state value.
    """
    padded = state_value + ("=" * (-len(state_value) % 4))
    decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
    return json.loads(decoded)


def start_iteration(workflow: dict[str, Any]) -> Any:
    """
    Input:
        workflow (dict[str, Any]): Active workflow state.
    Output:
        flask.Response: Redirect to the authorization endpoint.
    Description:
        Start the current scope iteration by generating PKCE values, storing the
        transaction state, and redirecting the browser to PingFederate.
    """
    endpoints = get_oauth_endpoints()

    iteration_index = workflow["current_index"]
    scopes = workflow["iterations"][iteration_index]
    requested_scope_key = scope_key(scopes)

    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    oauth_state = build_oauth_state_payload(workflow["report_id"], iteration_index, scopes)

    oauth_client = get_oauth_client(scopes=scopes, state_value=oauth_state)
    authorization_url, _ = oauth_client.authorization_url(
        endpoints["authorization_endpoint"],
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    workflow["oauth_transactions"][oauth_state] = {
        "iteration_index": iteration_index,
        "requested_scopes": scopes,
        "requested_scope_key": requested_scope_key,
        "code_verifier": code_verifier,
    }
    save_report_workflow(workflow)

    logging.info(
        "Starting UserInfo iteration %s for report_id=%s with scopes=%s",
        iteration_index,
        workflow["report_id"],
        requested_scope_key,
    )

    return redirect(authorization_url)


def fetch_userinfo(access_token: str) -> dict[str, Any]:
    """
    Input:
        access_token (str): OAuth bearer access token.
    Output:
        dict[str, Any]: Parsed UserInfo response JSON.
    Description:
        Call the discovered UserInfo endpoint with the supplied bearer token and
        return the response body as JSON.
    """
    endpoints = get_oauth_endpoints()

    oauth_client = OAuth2Session(
        token={
            "access_token": access_token,
            "token_type": "Bearer",
        }
    )
    response = oauth_client.get(
        endpoints["userinfo_endpoint"],
        timeout=30,
        verify=get_tls_verify_setting(),
    )
    response.raise_for_status()

    return response.json()


def compute_analysis(results: dict[str, Any]) -> dict[str, Any]:
    """
    Input:
        results (dict[str, Any]): Per-scope UserInfo results.
    Output:
        dict[str, Any]: Differential analysis of scope-released claims.
    Description:
        Compare each UserInfo result to the openid baseline and calculate which
        claims first appear when additional scopes are requested.
    """
    baseline_key = "openid"
    baseline_claims = set(results.get(baseline_key, {}).get("userinfo_claims", {}).keys())

    analysis: dict[str, Any] = {
        "baseline_scope": baseline_key,
        "independent_scope_analysis": {},
        "claims_only_seen_in_full_scope_set": {},
    }

    for test_key in sorted(results.keys()):
        if test_key == baseline_key:
            continue

        current_claims = set(results[test_key].get("userinfo_claims", {}).keys())
        added_claim_names = sorted(current_claims - baseline_claims)
        added_claim_values = {
            claim: results[test_key]["userinfo_claims"][claim]
            for claim in added_claim_names
        }

        analysis["independent_scope_analysis"][test_key] = {
            "new_claim_names_vs_openid": added_claim_names,
            "new_claim_values_vs_openid": added_claim_values,
        }

    full_key = "openid profile email phone address"
    if full_key in results:
        full_claims = set(results[full_key].get("userinfo_claims", {}).keys())
        other_claims: set[str] = set()

        for test_key, test_value in results.items():
            if test_key == full_key:
                continue
            other_claims |= set(test_value.get("userinfo_claims", {}).keys())

        only_in_full = sorted(full_claims - other_claims)
        analysis["claims_only_seen_in_full_scope_set"] = {
            "scope_tested": full_key,
            "claim_names": only_in_full,
            "claim_values": {
                claim: results[full_key]["userinfo_claims"][claim]
                for claim in only_in_full
            },
        }

    return analysis


def build_final_report(workflow: dict[str, Any]) -> dict[str, Any]:
    """
    Input:
        workflow (dict[str, Any]): Completed workflow state.
    Output:
        dict[str, Any]: Final report payload.
    Description:
        Build the final report including discovered OIDC metadata, per-run
        UserInfo payloads, and the differential scope analysis.
    """
    metadata = fetch_oidc_metadata()

    return {
        "report_id": workflow["report_id"],
        "well_known_url": get_well_known_url(),
        "discovered_metadata": {
            "issuer": metadata.get("issuer"),
            "authorization_endpoint": metadata.get("authorization_endpoint"),
            "token_endpoint": metadata.get("token_endpoint"),
            "userinfo_endpoint": metadata.get("userinfo_endpoint"),
            "scopes_supported": metadata.get("scopes_supported"),
            "claims_supported": metadata.get("claims_supported"),
        },
        "iterations_expected": [scope_key(scopes) for scopes in workflow["iterations"]],
        "iterations_completed": sorted(workflow["results"].keys()),
        "runs": workflow["results"],
        "analysis": compute_analysis(workflow["results"]),
        "notes": [
            "This report is based on the OpenID Connect UserInfo endpoint rather than JWT claim inspection.",
            "Claims are inferred by differential testing against the openid baseline.",
            "Duplicate callback hits are handled idempotently after completion.",
        ],
    }


@app.route("/")
def index() -> Any:
    """
    Input:
        None
    Output:
        flask.Response: Redirect to the report start route.
    Description:
        Send the browser to the UserInfo scope comparison workflow.
    """
    return redirect(url_for("report_start"))


@app.route("/report/start")
def report_start() -> Any:
    """
    Input:
        None
    Output:
        flask.Response: Redirect to the first authorization request.
    Description:
        Refresh OIDC metadata, initialize a new comparison workflow, and launch
        the first scope iteration.
    """
    fetch_oidc_metadata(force_refresh=True)
    workflow = initialize_report_workflow()
    return start_iteration(workflow)


@app.route(app.config["REDIRECT_URI"])
def callback() -> Any:
    """
    Input:
        None
    Output:
        flask.Response: Redirect to the next iteration or return the final report.
    Description:
        Handle the authorization response, exchange the code for tokens, call the
        UserInfo endpoint, store the results for this iteration, and continue the
        chained workflow until all configured scope combinations are complete.
    """
    workflow = get_report_workflow()
    if workflow is None:
        return "No active UserInfo scope report workflow found in session", 400

    state_value = request.args.get("state")
    if not state_value:
        return "Missing OAuth state parameter", 400

    try:
        state_payload = parse_oauth_state_payload(state_value)
    except Exception as exc:
        logging.error("Failed to parse OAuth state payload: %s", exc, exc_info=True)
        return "Invalid OAuth state parameter", 400

    if state_payload.get("report_id") != workflow.get("report_id"):
        return "OAuth state does not match the active workflow", 400

    tx = workflow.get("oauth_transactions", {}).get(state_value)
    if tx is None:
        if state_value in workflow.get("processed_states", {}):
            logging.info(
                "Received duplicate callback for already processed state in report_id=%s",
                workflow.get("report_id"),
            )
            return jsonify(build_final_report(workflow))

        if len(workflow.get("results", {})) == len(workflow.get("iterations", [])):
            logging.info(
                "Received duplicate callback after workflow completion for report_id=%s",
                workflow.get("report_id"),
            )
            return jsonify(build_final_report(workflow))

        return "OAuth transaction state not found in workflow", 400

    iteration_index = tx["iteration_index"]
    requested_scopes = tx["requested_scopes"]
    requested_scope_key = tx["requested_scope_key"]

    endpoints = get_oauth_endpoints()
    oauth_client = get_oauth_client(scopes=requested_scopes, state_value=state_value)

    try:
        token_response = oauth_client.fetch_token(
            endpoints["token_endpoint"],
            authorization_response=request.url,
            client_secret=app.config["OAUTH_CLIENT_SECRET"],
            code_verifier=tx["code_verifier"],
            verify=get_tls_verify_setting(),
        )
    except Exception as exc:
        logging.error(
            "Token fetch failed for scopes=%s: %s",
            requested_scope_key,
            exc,
            exc_info=True,
        )
        return f"Token fetch failed for scopes: {requested_scope_key}", 500

    access_token = token_response.get("access_token")
    if not access_token:
        return f"No access token returned for scopes: {requested_scope_key}", 500

    try:
        userinfo = fetch_userinfo(access_token)
    except Exception as exc:
        logging.error(
            "UserInfo call failed for scopes=%s: %s",
            requested_scope_key,
            exc,
            exc_info=True,
        )
        return f"UserInfo call failed for scopes: {requested_scope_key}", 500

    workflow["results"][requested_scope_key] = {
        "iteration_index": iteration_index,
        "requested_scopes": requested_scopes,
        "requested_scope_key": requested_scope_key,
        "token_response_metadata": {
            "token_type": token_response.get("token_type"),
            "expires_in": token_response.get("expires_in"),
            "scope": token_response.get("scope"),
        },
        "userinfo_claims": userinfo,
    }

    workflow["processed_states"][state_value] = {
        "iteration_index": iteration_index,
        "requested_scope_key": requested_scope_key,
    }
    workflow["oauth_transactions"].pop(state_value, None)
    workflow["current_index"] = iteration_index + 1
    save_report_workflow(workflow)

    logging.info(
        "Completed UserInfo iteration %s for report_id=%s with scopes=%s",
        iteration_index,
        workflow["report_id"],
        requested_scope_key,
    )

    if workflow["current_index"] < len(workflow["iterations"]):
        return start_iteration(workflow)

    return jsonify(build_final_report(workflow))


@app.route("/report/view")
def report_view() -> Any:
    """
    Input:
        None
    Output:
        flask.Response: Current report JSON or an incomplete status.
    Description:
        Return the current workflow report if all scope iterations are complete,
        otherwise return the current completion state.
    """
    workflow = get_report_workflow()
    if workflow is None:
        return "No completed UserInfo scope report workflow found in session", 400

    expected_count = len(workflow["iterations"])
    actual_count = len(workflow["results"])

    if actual_count != expected_count:
        return jsonify(
            {
                "status": "incomplete",
                "expected_iterations": expected_count,
                "completed_iterations": actual_count,
                "completed_scope_keys": sorted(workflow["results"].keys()),
            }
        ), 409

    return jsonify(build_final_report(workflow))


@app.route("/report/reset")
def report_reset() -> Any:
    """
    Input:
        None
    Output:
        flask.Response: JSON confirmation.
    Description:
        Clear the current report workflow and cached metadata from the session so
        a new run can start cleanly.
    """
    clear_report_workflow()
    return jsonify({"status": "reset"})


if __name__ == "__main__":
    app.run(
        ssl_context=("cert.pem", "key.pem"),
        host="0.0.0.0",
        port=443,
        debug=True,
    )