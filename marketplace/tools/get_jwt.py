#!/usr/bin/env python3

"""Prints a marketplace JWT for a user of the marketplace database.

The marketplace issues tokens through its web app only, and the token subject is
the numeric account id rather than the user name. This logs in, reads the account
id off the account page, and asks for the token, so that only the user name is
needed. The legacy get-jwt.sh wrapper delegates to this implementation. It uses
the standard library only, so that it runs outside the bazel environment.

Usage: marketplace/tools/get_jwt.py <user> [--password PASSWORD | --password-env NAME] [--url URL]
                                    [--sub-account SCOPE]
Example: marketplace/tools/get_jwt.py alice
         marketplace/tools/get_jwt.py alice --url https://127.0.0.1:8888 \
             --sub-account hummbwtester
"""

import argparse
import glob
import http.cookiejar
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_PASSWORD = "1234"
# Where the marketplace listens when the topology does not say otherwise.
FALLBACK_ADDR = "127.0.0.1:8888"

# api_addr = "127.0.0.1:8888" in gen/AS*/marketplace.toml.
API_ADDR_RE = re.compile(r'^api_addr\s*=\s*"(?P<addr>.*)"', re.MULTILINE)
# <div style="display:none" id="main-account-id">3</div> in account.html.
MAIN_ACCOUNT_RE = re.compile(r'id="main-account-id">(?P<id>\d+)<')
# onclick="requestJWT('4','hummbwtester')" in account.html.
SUB_ACCOUNT_RE = r"requestJWT\('(?P<id>\d+)','%s'\)"


class MarketplaceError(Exception):
    """An expected failure, reported without a traceback."""


class Marketplace:
    """A browser session with the marketplace web app, holding its login cookie."""

    def __init__(self, url: str):
        self.url = url.rstrip("/")
        # The certificate is self-signed for marketplace.local and cannot be
        # verified, which is what curl -k did.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.browser = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        )

    def get(self, path: str) -> str:
        return self._open(path, None)

    def post(self, path: str, **form) -> str:
        return self._open(path, urllib.parse.urlencode(form).encode())

    def _open(self, path: str, data) -> str:
        try:
            with self.browser.open(self.url + path, data) as response:
                return response.read().decode()
        except urllib.error.HTTPError as e:
            raise MarketplaceError("%s%s: %d %s" % (self.url, path, e.code, e.reason))
        except urllib.error.URLError as e:
            raise MarketplaceError("cannot reach %s: %s" % (self.url, e.reason))


def marketplaceURL(gen_dir: str) -> str:
    """The address the marketplace of the generated topology was configured with."""
    for toml in sorted(glob.glob(os.path.join(gen_dir, "AS*", "marketplace.toml"))):
        try:
            with open(toml) as f:
                match = API_ADDR_RE.search(f.read())
        except OSError:
            continue
        if match:
            return "https://" + match.group("addr")
    return "https://" + FALLBACK_ADDR


def accountID(page: str, user: str, scope: str) -> str:
    """The id of the account the token is for, read off the account page."""
    main = MAIN_ACCOUNT_RE.search(page)
    # An unauthenticated /account redirects to the login page, so a missing main
    # account id means the credentials were rejected.
    if not main:
        raise MarketplaceError("could not log in as %s (wrong password?)" % user)
    if not scope:
        return main.group("id")
    sub = re.search(SUB_ACCOUNT_RE % re.escape(scope), page)
    if not sub:
        raise MarketplaceError('%s has no sub account "%s"' % (user, scope))
    return sub.group("id")


def main(args) -> None:
    password = args.password
    if args.password_env:
        password = os.environ.get(args.password_env)
        if not password:
            raise MarketplaceError("password environment variable %s is not set" % args.password_env)
    url = args.url or marketplaceURL(args.gen_dir)
    marketplace = Marketplace(url)
    marketplace.post("/login", username=args.user, password=password)
    page = marketplace.get("/account")
    account = accountID(page, args.user, args.sub_account)
    print(marketplace.post("/account/token", id=account))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Prints a JWT for a marketplace account. The token is issued by the "
                    "marketplace web app, which is logged into with the given credentials."
    )
    parser.add_argument(
        "user",
        help="Name of the marketplace user to log in as."
    )
    password = parser.add_mutually_exclusive_group()
    password.add_argument(
        "--password",
        default=DEFAULT_PASSWORD,
        help="Password of that user (default: %s)." % DEFAULT_PASSWORD
    )
    password.add_argument(
        "--password-env",
        help="Name of the environment variable containing the user's password."
    )
    parser.add_argument(
        "--url",
        help="Base URL of the marketplace web app "
             "(default: the api_addr of the marketplace in --gen-dir)."
    )
    parser.add_argument(
        "--sub-account",
        default="",
        help="Scope of a sub account to get the token for, e.g. hummbwtester "
             "(default: the main account of the user)."
    )
    parser.add_argument(
        "--gen-dir",
        default="gen",
        help="Path to the generated topology, read when --url is not given (default: gen)."
    )

    try:
        main(parser.parse_args())
    except MarketplaceError as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
