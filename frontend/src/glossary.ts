// Short, plain-language definitions for the jargon that shows up in the trace.
// Rendered as tooltips by <GlossaryTooltip>.

export const GLOSSARY: Record<string, string> = {
  authorization_code:
    "A short-lived, single-use value the authorization server hands back through the browser. It is not a token; the client swaps it for one over the back channel.",
  code: "The authorization code — a single-use value exchanged for an access token.",
  access_token:
    "A credential the client presents to the resource server to access the API on the user's behalf. Here it is a signed JWT.",
  redirect_uri:
    "The exact, pre-registered URL the authorization server is allowed to send the response to. Must match what was registered.",
  state:
    "An opaque value the client generates and the server echoes back, binding the response to the browser session that started the flow (anti-CSRF).",
  bearer:
    "A token type where merely possessing the token is enough to use it — like cash. Anyone who holds it can present it.",
  scope:
    "The subset of access the client requests and the user consents to (e.g. reading a profile).",
  client_credentials:
    "The client's own identity proof at the token endpoint. For a confidential client this is a secret sent over the back channel.",
  jwt: "JSON Web Token: a signed set of claims. The signature lets a verifier trust the contents without calling the issuer.",
  jwks: "JSON Web Key Set: the authorization server's published public keys, used to verify the tokens it signs.",
  consent:
    "The user's explicit approval for the client to access the requested scope.",
  aud: "Audience — the intended recipient of the token. The resource server rejects tokens not addressed to it.",
  iss: "Issuer — who minted the token. The resource server checks it matches the trusted authorization server.",
  code_verifier:
    "PKCE: a high-entropy secret the client generates per request and keeps. It is sent only over the back channel at the token exchange, so an attacker who captures the code cannot produce it.",
  code_challenge:
    "PKCE: the S256 hash of the code_verifier, sent on the authorization request. The token endpoint later requires a verifier that hashes to this, binding the code to the client instance that started the flow.",
  pkce: "Proof Key for Code Exchange (RFC 7636): binds an authorization code to a per-request verifier, defeating code interception/injection. Mandatory in OAuth 2.1.",
  public_client_id:
    "The client_id of a public client (a native app or SPA with no secret). It is not confidential, so possessing it grants no authority — which is why PKCE, not client authentication, is what stops a stolen code here.",
};

export function hasGlossary(term: string): boolean {
  return term in GLOSSARY;
}
