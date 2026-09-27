# ─────────────────────────────────────────────────────────────────────────────
# api/views.py — Authentication Gauntlet Lab
#
# Wrap-Up Comparison Table (Reporter fills this in at the end of the lab):
#
# +-------------------+------------+-----------+-------------------+----------+
# | Method            | Stateful?  | DB Lookup?| Credentials sent  | Safe on  |
# |                   |            |           | every request?    | HTTP?    |
# +-------------------+------------+-----------+-------------------+----------+
# | Basic Auth        |   No       |   Yes     |       Yes         |   No     |
# | Session Auth      |   Yes      |   Yes     |       No          |   No     |
# | Opaque Token Auth |   No       |   Yes     |       No          |   No     |
# | JWT               |   No       |   No      |       No          |   No     |
# +-------------------+------------+-----------+-------------------+----------+
#
# ─────────────────────────────────────────────────────────────────────────────

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
    TokenAuthentication,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Basic Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def basic_auth_view(request):
    # Extract the raw Authorization header from request.META and print it
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    print(f"Incoming Header: {auth_header}")

    # Reporter — Phase 1 challenge answers:
    #
    # Q1 answer (header format after Base64 decoding):
    #   The decoded string from YWRtaW46YWRtaW4xMjM= is exactly: admin:admin123
    #   Format is username:password — a colon-separated pair of plain credentials.
    #
    # Q2 answer (is Basic Auth safe over HTTP?):
    #   Even though credentials are Base64-encoded rather than plain-text, Base64
    #   is NOT encryption — anyone who intercepts the HTTP traffic can instantly
    #   decode the header and read the username and password in clear.
    #
    # Synthesis Challenge — Replay attack:
    #   The attacker simply copies the EXACT header the client sent and replays it:
    #       Authorization: Basic YWRtaW46YWRtaW4xMjM=
    #   This works because Base64 is reversible encoding, not encryption. The server
    #   cannot distinguish a replayed header from a legitimate one. This proves that
    #   Base64 encoding provides ZERO security — it only makes credentials slightly
    #   less human-readable at a glance.

    return Response({"message": "Check your terminal!"})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Session Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
def session_auth_view(request):
    # Reporter — Phase 2 challenge answers:
    #
    # Q1 answer (effect of deleting the sessionid cookie):
    #   Deleting the cookie immediately logs you out and redirects to the login page.
    #   This happens because the cookie is a pointer to a session record stored in
    #   the server's database (django_session table). Without the cookie the browser
    #   has no way to identify itself to the server, and the server therefore treats
    #   the request as unauthenticated — even though the session record still exists
    #   in the database.
    #
    # Synthesis answer (session hijacking):
    #   Re-adding the original sessionid value immediately restores the logged-in
    #   session, proving that anyone who possesses the sessionid cookie value can
    #   impersonate the user without ever knowing their password.
    #   This is called session hijacking: an attacker who sniffs or steals the
    #   sessionid (e.g. via XSS, network interception, or a compromised device)
    #   can place it in their own browser and gain full access to the victim's
    #   account for as long as that server-side session record remains valid.

    return Response({"message": "Session authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Token Authentication (Opaque)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def token_auth_view(request):
    # Reporter — Phase 3 challenge answers:
    #
    # Q1 answer (HTTP status code for a tampered token):
    #   401 Unauthorized — the server looks the token up in its authtoken_token table,
    #   finds no match, and rejects the request.
    #
    # Q2 answer (password hashing algorithm):
    #   The output starts with the prefix  pbkdf2_sha256  which means Django uses
    #   PBKDF2 with the SHA-256 hash function and a random salt to store passwords.
    #   admin123 is never stored as-is because storing plain-text passwords would
    #   expose every user's credentials if the database were ever compromised.
    #
    # Synthesis answer (token revocation — opaque vs JWT):
    #   To permanently invalidate a stolen opaque token, an administrator (or an
    #   automated process) must delete that specific row from the authtoken_token
    #   table; the token owner cannot revoke it themselves without a dedicated API.
    #   A JWT cannot be revoked the same way because it is never stored in a
    #   database — the only levers are a very short expiry time or maintaining a
    #   server-side deny-list of revoked token IDs (which re-introduces statefulness).

    return Response({"message": "Token authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — JSON Web Tokens (JWT)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def jwt_protected_view(request):
    # Reporter — Phase 4 challenge answers:    # Team Challenge:
    # Besides exp, the JWT payload also includes user_id — that's the identifying
    # field baked in alongside the expiry.
    #
    # The server validates the token without a DB lookup by recomputing the
    # signature from the header + payload using its secret key and comparing it
    # to the token's signature. If they match, it trusts the payload.

    # Synthesis Challenge:
    # Tampering with user_id and re-sending the token returns 401 Unauthorized.
    #
    # Even though the tampered token is still well formed JSON/base64, editing
    # the payload invalidates the signature because the signature was computed
    # over the original header + payload with the server's secret key.
    #
    # On verification, the server recomputes the signature and it no longer
    # matches, so the token is rejected regardless of how valid the JSON inside looks.

    return Response({"message": "JWT authenticated.", "user": request.user.username})
