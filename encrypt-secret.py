#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from urllib.parse import parse_qs
from urllib.parse import urlparse


class RequestValues:
    code: str | None = None


class GetHandler(BaseHTTPRequestHandler):
    last_request: RequestValues | None = None

    def do_GET(self):
        parsed_path = urlparse(self.path)
        parsed_query = parse_qs(parsed_path.query)
        cl = parsed_query.get("code")

        if cl is None or len(cl) == 0:
            close = "<p>Sorry the request failed, please try again.</p>"
            # self.close_connection = True
            self.send_response(500)
            self.end_headers()
            self.wfile.write(close.encode("utf-8"))
            return

        GetHandler.last_request = RequestValues()
        GetHandler.last_request.code = cl[0]
        close = "<p>We got the token, please close this window.</p>"
        # self.close_connection = True
        self.send_response_only(200)
        self.end_headers()
        self.wfile.write(close.encode("utf-8"))


def get_id_token(
    client_id: str, client_secret: str, aud: str, auth_code: str, addr: str, port: int
) -> str:
    url = "https://oauth2.googleapis.com/token"
    data = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": auth_code,
            "redirect_uri": f"http://{addr}:{port}",
            "grant_type": "authorization_code",
            "audience": aud,
        }
    ).encode()
    req = urllib.request.Request(url, data=data)
    try:
        resp = urllib.request.urlopen(req)
    except urllib.error.URLError as e:
        print(
            f"Exception thrown when requesting ID token: {e}", file=sys.stderr
        )
        raise SystemExit("Failed to get a ID token.")
    else:
        data = json.load(resp)
        return data["id_token"]


def encrypt_data(origin: str, token: str, value: str) -> str:
    url = f"https://{origin}/go/api/admin/encrypt"
    data = {"value": value}
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.go.cd.v1+json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        resp = urllib.request.urlopen(req, json.dumps(data).encode("utf-8"))
    except urllib.error.URLError as e:
        print(f"Exception thrown when encrypting data: {e}", file=sys.stderr)
        raise SystemExit("Failed to encrypt data.")
    else:
        data = json.load(resp)
        return data["encrypted_value"]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("value", help="The value to encrypt")
    parser.add_argument(
        "--gocd-server",
        default="deploy.getsentry.net",
        help="The GoCD server to encrypt data with (i.e. deploy.getsentry.net).",
    )
    parser.add_argument("--client-id", help="The OAuth client ID for IAP.")
    parser.add_argument(
        "--client-secret", help="The OAuth client secret for IAP."
    )
    parser.add_argument("--audience", help="The IAP client ID.")
    args = parser.parse_args(argv)

    client_id = args.client_id
    client_secret = args.client_secret
    audience = args.audience

    httpd = HTTPServer(("localhost", 8000), GetHandler)
    [_, port] = httpd.server_address

    url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&response_type=code&scope=openid%20email&access_type=offline&redirect_uri=http://localhost:{port}&cred_ref=true"
    webbrowser.open(url)

    httpd.handle_request()

    if GetHandler.last_request is None or GetHandler.last_request.code is None:
        raise SystemExit("Failed to get code from request.")

    id_token = get_id_token(
        client_id,
        client_secret,
        audience,
        GetHandler.last_request.code,
        "localhost",
        port,
    )

    ed = encrypt_data(args.gocd_server, id_token, args.value)
    print(f"\n\n\tInput:       {args.value}\n\tEncrypted:   {ed}\n\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
