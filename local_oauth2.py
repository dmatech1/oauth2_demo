# TODO: Track the precise origin of every token we hold.  Some tokens 
# are opaque and don't provide much useful information otherwise.

# TODO: Write functions for supplying a configuration for various services
# This includes ".well-known/openid-configuration" for general sites, 
# configuration for specific Azure tenants, and sites like Twitter
# that don't support OIDC at all.

# https://www.linkedin.com/oauth/.well-known/openid-configuration
# https://id.twitch.tv/oauth2/.well-known/openid-configuration
# https://accounts.google.com/.well-known/openid-configuration
# https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
# https://login.microsoftonline.com/azure.dmatech.org/v2.0/.well-known/openid-configuration


import typing
import json
import hashlib
import http.server
import urllib.parse
import logging
import socket
import os
import re
import base64
import html
import webbrowser

import requests.auth

# The only non-stock component I'm going to use.  Everyone uses this instead of "urllib.request".
import requests

log = logging.getLogger(__name__)

# See: https://developer.okta.com/docs/reference/api/oidc/

class JsonWebToken(typing.NamedTuple):
    """
    Representation of a JSON Web Token.  This class does no validation of the signature.

    See: https://datatracker.ietf.org/doc/html/rfc7519 "JSON Web Token (JWT)"
    See: https://datatracker.ietf.org/doc/html/rfc7517 "JSON Web Jey (JWK)"
    See: https://jwt.io/
    See: https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validate-the-signature
    """
    header: dict
    payload: dict
    signature: bytes
    
    @classmethod
    def parse(cls, token):
        """Parse a JWT triplet."""
        token_parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(token_parts[0] + "==").decode("utf-8"))
        payload = json.loads(base64.urlsafe_b64decode(token_parts[1] + "==").decode("utf-8"))
        signature = base64.urlsafe_b64decode(token_parts[2] + "==")
        return cls(header, payload, signature)
    
class PKCEPair(typing.NamedTuple):
    """
    Class for generating and containing a PKCE verifier and challenge.

    See: https://datatracker.ietf.org/doc/html/rfc7636
    See: https://oauth.net/2/pkce/
    """
    code_challenge_method   : str
    code_verifier           : str
    code_challenge          : str

    @classmethod
    def create(cls, code_challenge_method : str = "S256"):
        """
        Create a PKCE code verifier and challenge.
        """

        if code_challenge_method == "S256":
            # Create "code_verifier" value for PKCE.
            # See also: https://github.com/oauthlib/oauthlib/blob/master/oauthlib/oauth2/rfc6749/clients/base.py#L468
            code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
            code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

            # Create "code_challenge" value for PKCE based on the "code_verifier".
            # See also: https://github.com/oauthlib/oauthlib/blob/master/oauthlib/oauth2/rfc6749/clients/base.py#L504
            code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
            code_challenge = code_challenge.replace("=", "")
        else:
            raise ValueError("invalid code_challenge_method")
        
        return cls(code_challenge_method, code_verifier, code_challenge)


def _create_state() -> str:
    """
    Create "state" value to prevent CSRF.
    There aren't really specifications for this, so just use a random base64 string.
    If I were more adventurous, I could digitally sign some actual data and check
    the signature instead of just using a nonce.

    See: https://datatracker.ietf.org/doc/html/rfc6749#page-26
    """
    return base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")

class AuthCodeHttpServerError(Exception):
    pass

class AuthCodeHttpServer(http.server.HTTPServer):
    """
    Simple local HTTP server 

    See: https://github.com/python/cpython/blob/main/Lib/http/server.py
    See: https://github.com/python/cpython/blob/main/Lib/socketserver.py
    """

    def __init__(self, *args, **kwargs):
        """
        Simple HTTP server for catching OAuth2 redirects.  Be sure to pass in two kwargs:

        session: The OAuth2 session
        redirect_uri: The unmodified redirect_uri value associated with this instance.
        """

        # Store "session" and "redirect_uri" before calling the superclass constructor.
        self.parent : 'OAuth2Auth' = kwargs.pop("parent")
        self.redirect_uri : str = kwargs.pop("redirect_uri")

        super(AuthCodeHttpServer, self).__init__(*args, **kwargs)

        # These default to None until we actually get the values.
        self.path : typing.Optional[str] = None
        self.code : typing.Optional[str] = None
        self.state : typing.Optional[str] = None
        
    def server_bind(self):
        # Prevent anything else from using the port in question for the short duration of this
        # HTTP server.  This reduces the chance of it being intercepted by some other program
        # running locally.
        #
        # See: https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
        # See: https://bugs.python.org/issue41135
        # See: https://stackoverflow.com/questions/51090637/running-a-python-web-server-twice-on-the-same-port-on-windows-no-port-already
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        AuthCodeHttpServer.allow_reuse_address = False
        super(AuthCodeHttpServer, self).server_bind()

    @classmethod
    def create_server(cls, parent: 'OAuth2Auth', redirect_uris: typing.Iterable[str], any_host : bool = False):
        """
        Create an HTTP server on the first port available given a list of redirect targets.
        
        It will have three jobs:
        1. Catch the "state" and "code" values from the redirect after login.
        2. Instruct the session to complete the login by fetching the tokens.
        3. Display the results to the user.  I have to display something, so I should make it useful.
        """
        for redirect_uri in redirect_uris:
            split_uri = urllib.parse.urlsplit(redirect_uri)

            if (any_host or split_uri.hostname == "localhost" or split_uri.hostname == "127.0.0.1"):
                # For each redirect, try creating a AuthCodeHttpServer on that port.
                try:
                    httpd = AuthCodeHttpServer(('', split_uri.port), AuthCodeHttpHandler, redirect_uri=redirect_uri, session=session)
                    return httpd
                except OSError as e:
                    # Handle the special case of being unable to listen on a port.
                    if e.winerror == 10048 or e.errno == 98:
                        # [WinError 10048] Only one usage of each socket address (protocol/network address/port) is normally permitted
                        # This port is already in use by something.  Try the next one.
                        pass
                    else:
                        raise
        
        # All ports are unavailable.
        raise AuthCodeHttpServerError("Unable to listen on any redirect_uri ports.")

class AuthCodeHttpHandler(http.server.BaseHTTPRequestHandler):
    """Simple request handler for parsing the GET request made after OAuth2 completion."""
    
    # Override the type of this so that code completion will work properly.
    server: AuthCodeHttpServer

    def do_GET(self):
        # Pretty much all of the information we need is in the query string
        # component of "self.path".  This is a GET request, and we don't care
        # about any of the headers.  But we should at least verify that this
        # isn't a completely bogus (or possibly malicious) request by checking
        # a few things (like the path and "state" values).

        parsed_url = urllib.parse.urlparse(self.path)
        parsed_qs = urllib.parse.parse_qs(parsed_url.query)

        # parsed_url.netloc

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        self.server.path = self.path

        # Parse out the "code" and "state".
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        self.server.code = q["code"][0]
        self.server.state = q["state"][0]

        # Return a message to the client.  This can include specific information about
        # session and token, or it can be a simple message.  If we really want to do
        # this, we'll need to wait until after the token is fetched.

        self.wfile.write("""You may close this window.""".encode("UTF-8"))

class OAuth2Auth(requests.auth.AuthBase):
    """
    An OAuth2 session allowing:

    1. A single refresh token (optional) that can be stored via "keyring".
    2. An OIDC ID token (optional).
    3. One or more access tokens.  Each access token might be scoped to a specific set of APIs.

    At a minimum, you have sites like Twitter that might only give you a single access token,
    no ID token at all, and a refresh token only optionally.

    At a maximum, you have sites like Microsoft Azure (which have multiple audiences and identity tokens).
    The existing "msal" library does this with "acquire_token_interactive" and "acquire_token_silent"
    in the "msal.PublicClientApplication" class.

    I'm not really interested in simultaneously juggling two refresh tokens to multiple unrelated
    sites (or multiple accounts on the same site).  For that, just use two "OAuth2Auth" instances.
    """


    def __init__(self, config, client_id : str, client_secret: str, *args, **kwargs):
        self.config = config
        self.client_id = client_id
        self.client_secret = client_secret

    def _fetch_tokens(self, handler : AuthCodeHttpHandler):
        pass

    def create_authorize_url(self, **kwargs):
        # Start with sane defaults given the configuration.
        params = {
            "client_id": self.client_id
        }

        params.update(kwargs)

        # Anything passed as a list of strings should be turned into a 
        # space-delimited single sting.
        ret_val = self.config["authorization_endpoint"]

        for i, (k, v) in enumerate(params.items()):
            if isinstance(v, str) or isinstance(v, bytes):
                item = v
            elif isinstance(v, list) or isinstance(v, set) or isinstance(v, typing.Generator) or isinstance(v, tuple):
                item = " ".join(str(a) for a in v)
            elif v is None:
                continue
            else:
                item = str(v)
            
            clause = ("?" if i == 0 else "&") + k + "=" + urllib.parse.quote_plus(item)
            ret_val += clause

        return ret_val            

    def authorization_code_grant(self, scopes : typing.Iterable[str], use_pkce : bool = True, **kwargs):
        """
        The typical web-based authentication that involves:
        1. Sending the user's user-agent to the resource owner via the "...".
        2. The user logging in, performing any necessary approvals, and being
           redirected to "redirect_uri" with the authorization code.
        3. The client (this class) exchanging the authorization code for a
           longer-lived access token, (optionally) a much longer-lived refresh
           token, and (optionally) and ID token.

        See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
        """

        # Find a redirect_uri that will actually work locally given available ports.
        with AuthCodeHttpServer.create_server(self, ["http://127.0.0.1:80"]) as httpd:
            # Construct the full authorization URI using "authorization_endpoint".
            pass

            # Send the user there.
            pass

            # Process requests until we get the state and code.
            httpd.timeout = 120
            httpd.handle_request()

            # Now fetch the actual tokens given the code using "token_endpoint".
            pass


    def refresh_token_grant(self, **kwargs):
        """
        See: https://datatracker.ietf.org/doc/html/rfc6749#section-6
        """
        pass

    def implicit_grant(self, **kwargs):
        """
        See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
        """
        pass

    def client_credentials_grant(self, **kwargs):
        """
        See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
        """
        pass
        
    def __call__(self, r):
        """
        Given the request, identify the access token to use (if any).
        If necessary, refresh that token or fetch it if it's for a new audience.
        In most cases, this can be done with a simple "startswith" test, although
        services like "Azure Key Vault" require something like a regular expression.
        """

        assert r.url is not None

        access_token = "foo"
        r.headers["Authorization"] = "Bearer " + access_token
        return r
