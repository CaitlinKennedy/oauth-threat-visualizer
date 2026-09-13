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
};

export function hasGlossary(term: string): boolean {
  return term in GLOSSARY;
}
