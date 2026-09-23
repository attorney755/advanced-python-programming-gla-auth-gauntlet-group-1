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
    # Q1 answer (effect of deleting the sessionid cookie):
    # Synthesis answer (how session hijacking works):

    return Response({"message": "Session authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Token Authentication (Opaque)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def token_auth_view(request):
    # Reporter — Phase 3 challenge answers:
    # Q1 answer (HTTP status code for a tampered token):
    # Q2 answer (password hashing algorithm):
    # Synthesis answer (token revocation — opaque vs JWT):

    return Response({"message": "Token authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — JSON Web Tokens (JWT)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def jwt_protected_view(request):
    # Reporter — Phase 4 challenge answers:
    # Q1 answer (fields found in the decoded JWT payload):
    # Q2 answer (how the server validates a JWT without a database lookup):
    # Synthesis answer (tampered JWT result and explanation):

    return Response({"message": "JWT authenticated.", "user": request.user.username})
