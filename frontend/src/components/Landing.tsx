interface Props {
  onStart: () => void;
  onPlayground: () => void;
}

// The landing screen: one-sentence orientation, then get out of the way. Two
// CTAs — a guided start (plum, so it never competes with cobalt "active"), and
// the Playground, which opens the run view with the config popover already open.
export function Landing({ onStart, onPlayground }: Props) {
  return (
    <div className="landing">
      <header className="landing-head">
        <span className="landing-wordmark">OAuth Threat Visualizer</span>
      </header>

      <div className="landing-hero">
        <div className="landing-hero-inner">
          <h1 className="landing-h1">
            See how OAuth works and how malicious actors try to break in.
          </h1>
          <p className="landing-sub">
            A step by step real exchange across the app, the identity provider,
            the API, and an attacker. Flip a defense on and watch the same attack
            fail.
          </p>
          <div className="landing-cta-row">
            <button className="btn-cta" onClick={onStart}>
              ▶ New to OAuth? Start here
            </button>
            <button className="btn-cta-soft" onClick={onPlayground}>
              Playground
              <span className="soft-tail">— configure it yourself →</span>
            </button>
          </div>
        </div>
      </div>

      <footer className="landing-foot">
        Every attack runs only against this tool&apos;s own contained actors. The
        victim is a synthetic bundled account.
      </footer>
    </div>
  );
}
