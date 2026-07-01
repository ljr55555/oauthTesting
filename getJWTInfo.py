from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import uuid
from typing import Any

import jwt
from flask import Flask, jsonify, redirect, request, session, url_for
from flask_session import Session
from jwt.exceptions import PyJWTError
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
    ["openid", "profile", "email"],
]


def generate_code_verifier() -> str:
    """
    Input:
        None
    Output:
        str: PKCE code verifier.
    Description:
        Generate a random PKCE code verifier suitable for the authorization code
        flow with PKCE.
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
        scope_value (str | list[str] | None): Scope representation from config,
            query string, token response, or decoded JWT.
    Output:
        list[str]: Normalized ordered list of unique scopes.
    Description:
        Normalize scope input into a stable list preserving first occurrence order.
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
        scope = scope.strip()
        if not scope or scope in seen:
            continue
        seen.add(scope)
        result.append(scope)

    return result


def scope_key(scopes: list[str]) -> str:
    """
    Input:
        scopes (list[str]): Scope list.
    Output:
        str: Space-delimited normalized scope key.
    Description:
        Convert a scope list into the canonical key used throughout the report.
    """
    return " ".join(normalize_scope(scopes))


def get_oauth_client(scopes: list[str], state_value: str | None = None) -> OAuth2Session:
    """
    Input:
        scopes (list[str]): Requested scopes for this OAuth flow.
        state_value (str | None): Optional caller-provided OAuth state.
    Output:
        OAuth2Session: Configured OAuth2 client.
    Description:
        Create an OAuth2Session bound to the configured client, redirect URI, and
        requested scopes for a single test iteration.
    """
    return OAuth2Session(
        client_id=app.config["OAUTH_CLIENT_ID"],
        redirect_uri=app.config["REDIRECT_URL"],
        scope=scopes,
        state=state_value,
    )


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    """
    Input:
        token (str): JWT string.
    Output:
        dict[str, Any]: Decoded JWT payload.
    Description:
        Decode a JWT without signature verification for inspection and reporting.
        This is for diagnostics only and must not be used for trust decisions.
    """
    return jwt.decode(token, options={"verify_signature": False})


def get_protocol_claims() -> set[str]:
    """
    Input:
        None
    Output:
        set[str]: Protocol and token metadata claim names.
    Description:
        Return claims that are treated as token metadata rather than user
        attributes for report classification purposes.
    """
    return {
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "azp",
        "typ",
        "client_id",
        "scope",
        "scp",
        "sid",
        "auth_time",
        "acr",
        "amr",
    }


def extract_attribute_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """
    Input:
        claims (dict[str, Any]): Decoded JWT payload.
    Output:
        dict[str, Any]: Non-protocol claims considered candidate scope-released
            attributes.
    Description:
        Remove protocol and token metadata claims so report diffs focus on
        identity and profile attributes.
    """
    protocol_claims = get_protocol_claims()
    return {key: value for key, value in claims.items() if key not in protocol_claims}


def initialize_report_workflow() -> dict[str, Any]:
    """
    Input:
        None
    Output:
        dict[str, Any]: Initialized workflow state.
    Description:
        Create the server-side state object used to orchestrate the chained OAuth
        test iterations and collect results.
    """
    workflow = {
        "report_id": str(uuid.uuid4()),
        "iterations": SCOPE_ITERATIONS,
        "current_index": 0,
        "results": {},
        "oauth_transactions": {},
    }
    session["scope_report_workflow"] = workflow
    session.modified = True
    return workflow


def get_report_workflow() -> dict[str, Any] | None:
    """
    Input:
        None
    Output:
        dict[str, Any] | None: Current workflow state or None if absent.
    Description:
        Fetch the current server-side workflow state from the session.
    """
    workflow = session.get("scope_report_workflow")
    return workflow if isinstance(workflow, dict) else None


def save_report_workflow(workflow: dict[str, Any]) -> None:
    """
    Input:
        workflow (dict[str, Any]): Updated workflow state.
    Output:
        None
    Description:
        Persist updated workflow state into the server-side session store.
    """
    session["scope_report_workflow"] = workflow
    session.modified = True


def clear_report_workflow() -> None:
    """
    Input:
        None
    Output:
        None
    Description:
        Remove the current report workflow state from the session.
    """
    session.pop("scope_report_workflow", None)
    session.modified = True


def build_oauth_state_payload(report_id: str, iteration_index: int, scopes: list[str]) -> str:
    """
    Input:
        report_id (str): Workflow correlation identifier.
        iteration_index (int): Current iteration index.
        scopes (list[str]): Requested scopes for this iteration.
    Output:
        str: Serialized opaque OAuth state payload.
    Description:
        Serialize correlation metadata into the OAuth state parameter so the
        callback can bind the authorization response to the correct iteration.
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
        state_value (str): Serialized OAuth state payload.
    Output:
        dict[str, Any]: Parsed correlation metadata.
    Description:
        Deserialize the OAuth state payload used to correlate callbacks to report
        workflow iterations.
    """
    padded = state_value + ("=" * (-len(state_value) % 4))
    decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
    return json.loads(decoded)


def start_iteration(workflow: dict[str, Any]) -> Any:
    """
    Input:
        workflow (dict[str, Any]): Active report workflow state.
    Output:
        flask.Response: Redirect to PingFederate authorize endpoint for the next
            iteration.
    Description:
        Start the current scope iteration by generating PKCE material, building
        OAuth state, recording transaction metadata, and redirecting to the
        authorization endpoint.
    """
    iteration_index = workflow["current_index"]
    scopes = workflow["iterations"][iteration_index]
    requested_scope_key = scope_key(scopes)

    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    oauth_state = build_oauth_state_payload(workflow["report_id"], iteration_index, scopes)

    oauth_client = get_oauth_client(scopes=scopes, state_value=oauth_state)
    authorization_url, _ = oauth_client.authorization_url(
        app.config["OAUTH_AUTHORIZE_URL"],
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
        "Starting iteration %s for report_id=%s with scopes=%s",
        iteration_index,
        workflow["report_id"],
        requested_scope_key,
    )
    return redirect(authorization_url)


def compute_scope_differences(results: dict[str, Any]) -> dict[str, Any]:
    """
    Input:
        results (dict[str, Any]): Per-scope collected run data.
    Output:
        dict[str, Any]: Derived scope attribution and set comparisons.
    Description:
        Compare baseline and expanded scope results to identify which claims first
        appear when profile or email is added.
    """
    baseline_key = "openid"
    profile_key = "openid profile"
    email_key = "openid email"
    full_key = "openid profile email"

    baseline_claims = set(results.get(baseline_key, {}).get("attribute_claims", {}).keys())
    profile_claims = set(results.get(profile_key, {}).get("attribute_claims", {}).keys())
    email_claims = set(results.get(email_key, {}).get("attribute_claims", {}).keys())
    full_claims = set(results.get(full_key, {}).get("attribute_claims", {}).keys())

    profile_only_vs_openid = sorted(profile_claims - baseline_claims)
    email_only_vs_openid = sorted(email_claims - baseline_claims)
    claims_only_in_full = sorted(full_claims - (baseline_claims | profile_claims | email_claims))

    profile_values = {
        claim: results[profile_key]["attribute_claims"][claim]
        for claim in profile_only_vs_openid
        if profile_key in results
    }
    email_values = {
        claim: results[email_key]["attribute_claims"][claim]
        for claim in email_only_vs_openid
        if email_key in results
    }
    full_only_values = {
        claim: results[full_key]["attribute_claims"][claim]
        for claim in claims_only_in_full
        if full_key in results
    }

    return {
        "baseline_scope": baseline_key,
        "profile_added_to_openid": {
            "scope_tested": profile_key,
            "new_claim_names": profile_only_vs_openid,
            "new_claim_values": profile_values,
        },
        "email_added_to_openid": {
            "scope_tested": email_key,
            "new_claim_names": email_only_vs_openid,
            "new_claim_values": email_values,
        },
        "claims_only_seen_when_profile_and_email_are_both_present": {
            "scope_tested": full_key,
            "claim_names": claims_only_in_full,
            "claim_values": full_only_values,
        },
    }


def build_final_report(workflow: dict[str, Any]) -> dict[str, Any]:
    """
    Input:
        workflow (dict[str, Any]): Completed report workflow state.
    Output:
        dict[str, Any]: Final structured report payload.
    Description:
        Build the final report containing all iteration outputs and the derived
        differential analysis across the tested scope combinations.
    """
    results = workflow["results"]
    return {
        "report_id": workflow["report_id"],
        "iterations_expected": [scope_key(scopes) for scopes in workflow["iterations"]],
        "iterations_completed": sorted(results.keys()),
        "runs": results,
        "analysis": compute_scope_differences(results),
        "notes": [
            "Claims are inferred by differential testing, not by intrinsic claim provenance embedded in the token.",
            "This report inspects JWT contents without signature verification for diagnostics only.",
        ],
    }


@app.route("/")
def index() -> Any:
    """
    Input:
        None
    Output:
        flask.Response: Redirect to the report workflow initializer.
    Description:
        Send the browser to the chained scope-comparison workflow.
    """
    return redirect(url_for("report_start"))


@app.route("/report/start")
def report_start() -> Any:
    """
    Input:
        None
    Output:
        flask.Response: Redirect to the first PingFederate authorization request.
    Description:
        Initialize a fresh chained test workflow and launch the first scope
        iteration.
    """
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
        Handle the OAuth callback, exchange the code for tokens, decode the access
        token, persist iteration results, and drive the workflow forward until all
        scope combinations have been tested.
    """
    workflow = get_report_workflow()
    if workflow is None:
        return "No active scope report workflow found in session", 400

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
        return "OAuth transaction state not found in workflow", 400

    iteration_index = tx["iteration_index"]
    requested_scopes = tx["requested_scopes"]
    requested_scope_key = tx["requested_scope_key"]

    oauth_client = get_oauth_client(scopes=requested_scopes, state_value=state_value)

    try:
        token_response = oauth_client.fetch_token(
            app.config["OAUTH_TOKEN_URL"],
            authorization_response=request.url,
            client_secret=app.config["OAUTH_CLIENT_SECRET"],
            code_verifier=tx["code_verifier"],
            verify=False,
        )
    except Exception as exc:
        logging.error("Token fetch failed for scopes=%s: %s", requested_scope_key, exc, exc_info=True)
        return f"Token fetch failed for scopes: {requested_scope_key}", 500

    access_token = token_response.get("access_token")
    if not access_token:
        return f"No access token returned for scopes: {requested_scope_key}", 500

    try:
        decoded_access_token = decode_jwt_unverified(access_token)
    except PyJWTError as exc:
        logging.error("JWT decode failed for scopes=%s: %s", requested_scope_key, exc, exc_info=True)
        return f"Token decode failed for scopes {requested_scope_key}: {exc}", 500

    workflow["results"][requested_scope_key] = {
        "iteration_index": iteration_index,
        "requested_scopes": requested_scopes,
        "requested_scope_key": requested_scope_key,
        "granted_scopes_from_token_response": normalize_scope(token_response.get("scope")),
        "granted_scopes_from_access_token": normalize_scope(
            decoded_access_token.get("scope") or decoded_access_token.get("scp")
        ),
        "token_response_metadata": {
            "token_type": token_response.get("token_type"),
            "expires_in": token_response.get("expires_in"),
            "scope": token_response.get("scope"),
        },
        "decoded_access_token": decoded_access_token,
        "attribute_claims": extract_attribute_claims(decoded_access_token),
    }

    workflow["oauth_transactions"].pop(state_value, None)
    workflow["current_index"] = iteration_index + 1
    save_report_workflow(workflow)

    logging.info(
        "Completed iteration %s for report_id=%s with scopes=%s",
        iteration_index,
        workflow["report_id"],
        requested_scope_key,
    )

    if workflow["current_index"] < len(workflow["iterations"]):
        return start_iteration(workflow)

    return redirect(url_for("report_view"))


@app.route("/report/view")
def report_view() -> Any:
    """
    Input:
        None
    Output:
        flask.Response: JSON report of all collected scope test results.
    Description:
        Render the final multi-iteration differential scope report after all
        authorization flows have completed.
    """
    workflow = get_report_workflow()
    if workflow is None:
        return "No completed scope report workflow found in session", 400

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
        Clear the current workflow state from the session so a new report can be
        started cleanly.
    """
    clear_report_workflow()
    return jsonify({"status": "reset"})


if __name__ == "__main__":
    app.run(ssl_context=("cert.pem", "key.pem"), host="0.0.0.0", port=443, debug=True)