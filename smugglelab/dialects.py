"""Named HTTP dialect presets modelled on real implementations.

These are *behavioural* approximations, not copies of any vendor code: each
preset only sets the divergence flags a proxy or server is known to differ on.
The interesting pairs are documented in ``PAIRS`` at the bottom.
"""

from __future__ import annotations

from .httpdialect import Dialect

# ---------------------------------------------------------------------------
# front-end proxies (load balancers / reverse proxies)
# ---------------------------------------------------------------------------

NGINX = Dialect(
    name="nginx",
    description="Strict-ish reverse proxy: rejects bare LF in the head, normalises "
    "obs-fold, takes the last Content-Length, prefers TE over CL and rewrites the "
    "head when forwarding.",
    accept_bare_lf=False,
    reject_bare_cr=True,
    allow_ws_before_colon=False,
    allow_obs_fold=True,
    trim_ows=True,
    te_with_cl="chunked_wins",
    te_requires_chunked_last=True,
    te_unknown_policy="reject",
    cl_duplicate_policy="last",
    cl_allow_comma=True,
    chunk_ext_policy="strip",
    forward_mode="normalize",
)

HAPROXY = Dialect(
    name="haproxy",
    description="Full-featured proxy: decodes chunked bodies and re-frames with "
    "Content-Length, so downstream never sees the original TE header.",
    accept_bare_lf=False,
    reject_bare_cr=True,
    allow_ws_before_colon=False,
    allow_obs_fold=False,
    te_with_cl="reject",
    te_requires_chunked_last=True,
    cl_duplicate_policy="reject",
    cl_allow_comma=False,
    chunk_ext_policy="strip",
    forward_mode="normalize",
)

APACHE_PROXY = Dialect(
    name="apache",
    description="mod_proxy: tolerates whitespace before the colon, keeps duplicate "
    "Content-Length (first wins), and forwards the original header block.",
    accept_bare_lf=False,
    reject_bare_cr=True,
    allow_ws_before_colon=True,
    allow_obs_fold=True,
    te_with_cl="chunked_wins",
    te_requires_chunked_last=False,
    te_unknown_policy="reject",
    cl_duplicate_policy="first",
    cl_allow_comma=False,
    chunk_ext_policy="strip",
    forward_mode="raw",
)

ENVOY = Dialect(
    name="envoy",
    description="Modern L7 proxy: rejects bare LF, rejects TE+CL, re-frames "
    "bodies with Content-Length when it can.",
    accept_bare_lf=False,
    reject_bare_cr=True,
    allow_ws_before_colon=False,
    allow_obs_fold=False,
    te_with_cl="reject",
    te_requires_chunked_last=True,
    cl_duplicate_policy="reject",
    cl_allow_comma=False,
    chunk_ext_policy="strip",
    forward_mode="normalize",
)

# A deliberately sloppy middlebox: the classic source of smuggling bugs.
LOOSE_PROXY = Dialect(
    name="loose-proxy",
    description="Legacy appliance: accepts bare LF, whitespace before ':', "
    "first-wins duplicate CL, and forwards bytes verbatim.",
    accept_bare_lf=True,
    reject_bare_cr=False,
    allow_ws_before_colon=True,
    allow_obs_fold=True,
    te_with_cl="chunked_wins",
    te_requires_chunked_last=False,
    te_unknown_policy="reject",
    cl_duplicate_policy="first",
    cl_allow_comma=False,
    cl_allow_ows=True,
    chunk_allow_ws=True,
    chunk_allow_0x=True,
    chunk_ext_policy="strip",
    forward_mode="raw",
)

# A load balancer that trusts Content-Length over Transfer-Encoding.  Paired with
# an origin that prefers Transfer-Encoding this is the classic CL.TE desync.
LEGACY_LB = Dialect(
    name="legacy-lb",
    description="Load balancer that obeys Content-Length when both framing "
    "headers are present, keeps the first duplicate CL, and forwards verbatim.",
    accept_bare_lf=False,
    reject_bare_cr=True,
    allow_ws_before_colon=False,
    allow_obs_fold=True,
    te_with_cl="cl_wins",
    te_requires_chunked_last=True,
    cl_duplicate_policy="first",
    cl_allow_comma=False,
    chunk_ext_policy="strip",
    forward_mode="raw",
)

# ---------------------------------------------------------------------------
# back-end origins
# ---------------------------------------------------------------------------


def _origin(name: str, description: str, **kw) -> Dialect:
    return Dialect(name=name, description=description, **kw)


PYTHON_ORIGIN = _origin(
    "python-origin",
    "Back end built on the firewall's own parser: strict RFC framing, rejects "
    "TE+CL, last duplicate CL wins.",
    te_with_cl="reject",
    cl_duplicate_policy="last",
    chunk_ext_policy="strip",
)

NODE_ORIGIN = _origin(
    "node-origin",
    "Node-style origin: prefers Content-Length over Transfer-Encoding when both "
    "are present (the historical Node.js rule), first duplicate CL wins, and "
    "strips whitespace before ':' when it reposts.",
    allow_ws_before_colon=True,
    te_with_cl="cl_wins",
    cl_duplicate_policy="first",
    chunk_ext_policy="strip",
)

GO_ORIGIN = _origin(
    "go-origin",
    "Go net/http style origin: rejects TE+CL, allows chunk extensions, strict on "
    "duplicate Content-Length.",
    te_with_cl="reject",
    cl_duplicate_policy="reject",
    chunk_ext_policy="strip",
)

JAVA_ORIGIN = _origin(
    "java-origin",
    "Servlet-container style origin: lenient request-line whitespace, last CL "
    "wins, accepts obs-fold and chunk extensions.",
    request_line_allow_extra_ws=True,
    request_line_allow_tab=True,
    allow_obs_fold=True,
    te_with_cl="chunked_wins",
    cl_duplicate_policy="last",
    chunk_ext_policy="strip",
)

LEGACY_ORIGIN = _origin(
    "legacy-origin",
    "Ancient CGI-style origin: accepts bare LF, whitespace before ':', "
    "first duplicate CL wins, and tolerates ' 5' chunk sizes.",
    accept_bare_lf=True,
    reject_bare_cr=False,
    allow_ws_before_colon=True,
    te_with_cl="chunked_wins",
    cl_duplicate_policy="first",
    chunk_allow_ws=True,
    chunk_allow_0x=True,
    chunk_ext_policy="strip",
)

# A hop that only reads the first Transfer-Encoding header and ignores the
# rest.  Paired with a hop that reads all of them, this is a TE.TE desync.
TE_FIRST_ONLY = _origin(
    "te-first-only",
    "Reads only the first Transfer-Encoding header and ignores any that follow.",
    te_first_header_only=True,
    te_unknown_policy="ignore",
    te_with_cl="chunked_wins",
    cl_duplicate_policy="last",
)

# A hop that cannot make sense of a Transfer-Encoding list and quietly falls
# back to Content-Length instead of rejecting.  This is the other half of many
# real TE.TE bugs.
TE_FALLBACK = _origin(
    "te-fallback",
    "When Transfer-Encoding is present but unusable, falls back to "
    "Content-Length instead of rejecting the message.",
    te_unusable_falls_back_to_cl=True,
    te_with_cl="chunked_wins",
    cl_duplicate_policy="last",
)

ALL_DIALECTS = {
    d.name: d
    for d in (
        NGINX,
        LEGACY_LB,
        HAPROXY,
        APACHE_PROXY,
        ENVOY,
        LOOSE_PROXY,
        PYTHON_ORIGIN,
        NODE_ORIGIN,
        GO_ORIGIN,
        JAVA_ORIGIN,
        LEGACY_ORIGIN,
        TE_FIRST_ONLY,
        TE_FALLBACK,
    )
}

FRONT_DIALECTS = {
    d.name: d for d in (NGINX, HAPROXY, APACHE_PROXY, ENVOY, LOOSE_PROXY, LEGACY_LB)
}
BACK_DIALECTS = {
    d.name: d
    for d in (
        PYTHON_ORIGIN, NODE_ORIGIN, GO_ORIGIN, JAVA_ORIGIN, LEGACY_ORIGIN,
        TE_FIRST_ONLY, TE_FALLBACK,
    )
}


def get_dialect(name: str) -> Dialect:
    try:
        return ALL_DIALECTS[name]
    except KeyError:
        raise KeyError(f"unknown dialect {name!r}; known: {sorted(ALL_DIALECTS)}") from None
