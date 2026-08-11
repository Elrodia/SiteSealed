import { useEffect, useId, useState } from "react";

const SPECIMEN_ID = "SR-2026-08-0147-A3";

const pipeline = [
  {
    number: "01",
    title: "Capture",
    detail: "In-app camera, device attestation, satellite position and trusted time context.",
    meta: "Lens",
    icon: "camera",
  },
  {
    number: "02",
    title: "Hash",
    detail: "The file and its capture manifest receive a SHA-256 digest on the device.",
    meta: "Local",
    icon: "hash",
  },
  {
    number: "03",
    title: "Qualify",
    detail: "A qualified trust service provider returns an RFC 3161 timestamp token.",
    meta: "eIDAS",
    icon: "certificate",
  },
  {
    number: "04",
    title: "Batch",
    detail: "Digests enter a Merkle tree without exposing any sibling record.",
    meta: "Merkle",
    icon: "tree",
  },
  {
    number: "05",
    title: "Anchor",
    detail: "The Merkle root is committed to a public chain for neutral verification.",
    meta: "Public",
    icon: "anchor",
  },
];

const principles = [
  ["01", "Proof over storage", "Proofs remain independently verifiable even if SiteSealed disappears."],
  ["02", "Verifiable by the adversary", "The opposing party can check a record with public information and open tooling."],
  ["03", "Dual rail, always", "Qualified time supplies the statutory rail; a public chain supplies the neutral rail."],
  ["04", "Capture is sacred", "Live captures are sealed on-device; imported files remain a separate, visible class."],
  ["05", "Honest scope", "Reports distinguish what is proven, what is attested and what is not claimed."],
  ["06", "Privacy by architecture", "Originals remain client-encrypted. Only hashes need to leave the client's control."],
  ["07", "Fees on value", "Verification stays free; revenue comes from sealing capacity and report generation."],
];

const roadmap = [
  {
    phase: "Phase 0",
    window: "2026",
    title: "Validation",
    text: "Practitioner interviews, working mockup, QTSP terms and a clear kill-or-continue decision.",
    current: true,
  },
  {
    phase: "Phase 1",
    window: "2027",
    title: "Genesis",
    text: "Capture app, sealing service, public verification portal and the first hundred sealed projects.",
  },
  {
    phase: "Phase 2",
    window: "2028-30",
    title: "Standard",
    text: "Field-platform API, insurer pilots and professional recognition of the report format.",
  },
  {
    phase: "Phase 3",
    window: "2031-37",
    title: "Layer",
    text: "Invisible sealing inside third-party tools: proof infrastructure for the built environment.",
  },
];

const problemSignals = [
  {
    label: "Fragmented",
    text: "Project records live across phones, inboxes, private platforms and paper minutes.",
  },
  {
    label: "Contestable",
    text: "Ordinary file dates can be edited, regenerated or selectively disclosed after the event.",
  },
  {
    label: "Asymmetric",
    text: "The party with the strongest archive can dominate the argument, regardless of the merits.",
  },
];

function Icon({ name, size = 20 }) {
  const paths = {
    arrow: (
      <>
        <path d="M5 12h14" />
        <path d="m13 6 6 6-6 6" />
      </>
    ),
    external: (
      <>
        <path d="M7 17 17 7" />
        <path d="M8 7h9v9" />
      </>
    ),
    camera: (
      <>
        <path d="M4 7.5h3l1.4-2h7.2l1.4 2h3v11H4z" />
        <circle cx="12" cy="13" r="3.2" />
      </>
    ),
    hash: (
      <>
        <path d="M9 3 7 21M17 3l-2 18M4 9h16M3 15h16" />
      </>
    ),
    certificate: (
      <>
        <path d="M6 3h12v11H6z" />
        <path d="m9 14-1 7 4-2 4 2-1-7" />
        <path d="m9 8 2 2 4-4" />
      </>
    ),
    tree: (
      <>
        <circle cx="12" cy="5" r="2" />
        <circle cx="6" cy="19" r="2" />
        <circle cx="18" cy="19" r="2" />
        <path d="M12 7v5M6 17v-3h12v3" />
      </>
    ),
    anchor: (
      <>
        <circle cx="12" cy="5" r="2" />
        <path d="M12 7v13M5 13H2c1 5 4 8 10 8s9-3 10-8h-3" />
        <path d="m8 10 4 3 4-3" />
      </>
    ),
    shield: (
      <>
        <path d="M12 3 20 6v5c0 5-3.2 8.4-8 10-4.8-1.6-8-5-8-10V6z" />
        <path d="m8.5 12 2.2 2.2 4.8-5" />
      </>
    ),
    download: (
      <>
        <path d="M12 3v12" />
        <path d="m7 10 5 5 5-5M4 21h16" />
      </>
    ),
    copy: (
      <>
        <rect x="8" y="8" width="12" height="12" rx="2" />
        <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
      </>
    ),
    check: (
      <>
        <path d="m5 12 4 4L19 6" />
      </>
    ),
    lock: (
      <>
        <rect x="5" y="10" width="14" height="11" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3" />
      </>
    ),
    menu: (
      <>
        <path d="M4 7h16M4 12h16M4 17h16" />
      </>
    ),
    close: (
      <>
        <path d="m6 6 12 12M18 6 6 18" />
      </>
    ),
  };

  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}

function Brand({ compact = false }) {
  return (
    <a className={`brand${compact ? " brand--compact" : ""}`} href="#top" aria-label="SiteSealed home">
      <img src="/icon-192.svg" alt="" width="42" height="42" />
      <span className="brand__name">SITESEALED</span>
    </a>
  );
}

function Header({ onVerify }) {
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setMenuOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    document.body.classList.toggle("menu-open", menuOpen);
    return () => {
      window.removeEventListener("keydown", closeOnEscape);
      document.body.classList.remove("menu-open");
    };
  }, [menuOpen]);

  const close = () => setMenuOpen(false);
  const verify = () => {
    close();
    onVerify();
  };

  return (
    <header className="site-header">
      <div className="container header__inner">
        <Brand />
        <nav className={`nav${menuOpen ? " nav--open" : ""}`} aria-label="Primary navigation">
          <a href="#method" onClick={close}>How it works</a>
          <a href="#proof" onClick={close}>Dual rail</a>
          <a href="#principles" onClick={close}>Principles</a>
          <a href="#roadmap" onClick={close}>Roadmap</a>
          <a href="/documents/SiteSealed_Whitepaper_v1.0_Genesis.pdf" onClick={close}>Whitepaper</a>
          <button className="button button--small button--amber nav__cta" type="button" onClick={verify}>
            Verify a record <Icon name="arrow" size={16} />
          </button>
        </nav>
        <button
          className="menu-toggle"
          type="button"
          aria-label={menuOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((open) => !open)}
        >
          <Icon name={menuOpen ? "close" : "menu"} size={24} />
        </button>
      </div>
    </header>
  );
}

function HeroSeal() {
  return (
    <div className="hero-seal" aria-label="Illustration of a SiteSealed record carrying two independent proofs">
      <div className="hero-seal__topbar">
        <span><i /> LIVE CAPTURE</span>
        <span>SR-2026-08-0147-A3</span>
      </div>

      <div className="capture-window">
        <div className="capture-window__grid" />
        <div className="capture-window__focus"><span>SS</span></div>
        <span className="capture-window__coordinate coordinate--one">50.6412 N</span>
        <span className="capture-window__coordinate coordinate--two">5.5710 E</span>
        <div className="capture-window__meta">
          <span>DEVICE ATTESTED</span>
          <span>DRIFT &lt; 0.4 S</span>
        </div>
      </div>

      <div className="manifest-strip">
        <span>SHA-256</span>
        <code>9f86d081884c...f00a08</code>
        <b>SEALED</b>
      </div>

      <div className="proof-rails-mini">
        <div className="proof-rail-mini proof-rail-mini--green">
          <span>RAIL A</span>
          <strong>Qualified time</strong>
          <small>eIDAS / RFC 3161</small>
        </div>
        <div className="proof-rail-mini proof-rail-mini--amber">
          <span>RAIL B</span>
          <strong>Public anchor</strong>
          <small>Merkle inclusion</small>
        </div>
      </div>

      <div className="seal-status">
        <span className="seal-status__mark"><Icon name="check" size={18} /></span>
        <span><small>PROOF BUNDLE</small><strong>Independently checkable</strong></span>
        <span className="seal-status__pulse" />
      </div>
    </div>
  );
}

function SectionHeading({ eyebrow, title, copy, align = "left", inverse = false }) {
  return (
    <div className={`section-heading section-heading--${align}${inverse ? " section-heading--inverse" : ""}`}>
      <p className="eyebrow">{eyebrow}</p>
      <h2>{title}</h2>
      {copy && <p className="section-heading__copy">{copy}</p>}
    </div>
  );
}

function Verifier() {
  const inputId = useId();
  const [recordId, setRecordId] = useState("");
  const [status, setStatus] = useState("idle");
  const [result, setResult] = useState(null);
  const [message, setMessage] = useState("");
  const [copied, setCopied] = useState(false);

  const verify = async (event) => {
    event.preventDefault();
    setStatus("loading");
    setResult(null);
    setMessage("");
    setCopied(false);

    try {
      const response = await fetch("/api/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ recordId }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.message || "Verification failed.");
      setResult(payload);
      setStatus("success");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Verification failed.");
      setStatus("error");
    }
  };

  const useSpecimen = () => {
    setRecordId(SPECIMEN_ID);
    setStatus("idle");
    setMessage("");
    setResult(null);
    document.getElementById(inputId)?.focus();
  };

  const copyHash = async () => {
    if (!result?.record?.sha256) return;
    await navigator.clipboard.writeText(result.record.sha256);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="verifier-shell">
      <div className="verifier-shell__header">
        <span className="verifier-shell__icon"><Icon name="shield" size={24} /></span>
        <div>
          <span>PUBLIC VERIFICATION PORTAL</span>
          <strong>Genesis specimen</strong>
        </div>
        <span className="specimen-pill">SIMULATED</span>
      </div>

      <form className="verify-form" onSubmit={verify} noValidate>
        <label htmlFor={inputId}>SiteSealed record ID</label>
        <div className="verify-form__row">
          <input
            id={inputId}
            type="text"
            autoComplete="off"
            spellCheck="false"
            value={recordId}
            onChange={(event) => setRecordId(event.target.value)}
            placeholder="SR-YYYY-MM-0000-XX"
            aria-describedby={`${inputId}-hint`}
          />
          <button className="button button--amber" type="submit" disabled={status === "loading"}>
            {status === "loading" ? "Checking..." : "Check both rails"}
            {status !== "loading" && <Icon name="arrow" size={17} />}
          </button>
        </div>
        <div className="verify-form__hint" id={`${inputId}-hint`}>
          <span>No account required.</span>
          <button type="button" onClick={useSpecimen}>Use specimen ID</button>
        </div>
      </form>

      <div className="verifier-response" aria-live="polite">
        {status === "idle" && (
          <div className="verifier-idle">
            <span className="verifier-idle__line" />
            <p>Enter the specimen ID to run a live request against the Node verification API.</p>
          </div>
        )}

        {status === "loading" && (
          <div className="verifier-loading">
            <span /><span /><span />
            <p>Checking qualified token and Merkle inclusion...</p>
          </div>
        )}

        {status === "error" && (
          <div className="verifier-error" role="alert">
            <strong>Record not verified</strong>
            <p>{message}</p>
          </div>
        )}

        {status === "success" && result && (
          <div className="verified-result">
            <div className="verified-result__title">
              <span><Icon name="check" size={22} /></span>
              <div>
                <small>SPECIMEN CHECK PASSED</small>
                <h3>{result.record.recordId}</h3>
              </div>
              <em>Both rails present</em>
            </div>

            <div className="verified-result__rails">
              <article className="verified-rail verified-rail--green">
                <span>RAIL A / QUALIFIED TIME</span>
                <strong>{result.record.qualifiedRail.provider}</strong>
                <p>{result.record.qualifiedRail.status}</p>
              </article>
              <article className="verified-rail verified-rail--amber">
                <span>RAIL B / PUBLIC ANCHOR</span>
                <strong>{result.record.chainRail.chain}</strong>
                <p>Block {result.record.chainRail.block} - {result.record.chainRail.status}</p>
              </article>
            </div>

            <div className="verified-result__hash">
              <span>SHA-256</span>
              <code>{result.record.sha256}</code>
              <button type="button" onClick={copyHash} aria-label="Copy specimen hash">
                <Icon name={copied ? "check" : "copy"} size={16} /> {copied ? "Copied" : "Copy"}
              </button>
            </div>

            <p className="verified-result__disclaimer">
              <strong>Honest scope:</strong> {result.scope.doesNotProve}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function App() {
  const scrollToVerifier = () => {
    document.getElementById("verify")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Header onVerify={scrollToVerifier} />

      <main id="main-content">
        <section className="hero" id="top">
          <div className="hero__mesh" aria-hidden="true" />
          <div className="container hero__inner">
            <div className="hero__copy">
              <div className="phase-tag"><span>GENESIS</span> PHASE 0 / VALIDATION</div>
              <h1>Construction records that can <em>verify themselves.</em></h1>
              <p className="hero__lede">
                SiteSealed is a neutral proof layer designed to bind every site capture to qualified time and a public-chain anchor - before a dispute begins.
              </p>
              <div className="hero__actions">
                <button className="button button--amber" type="button" onClick={scrollToVerifier}>
                  Verify the specimen <Icon name="arrow" size={18} />
                </button>
                <a className="button button--ghost" href="/documents/SiteSealed_Whitepaper_v1.0_Genesis.pdf">
                  Read the whitepaper <Icon name="external" size={17} />
                </a>
              </div>
              <div className="hero__trustline">
                <span><Icon name="lock" size={16} /> Client-encrypted originals</span>
                <span><Icon name="shield" size={16} /> Adversary-verifiable proofs</span>
              </div>
            </div>
            <HeroSeal />
          </div>
          <div className="container hero__foot">
            <p>Every record sealed the moment it&apos;s made.</p>
            <span>SCROLL TO THE PROOF LAYER</span>
          </div>
        </section>

        <section className="problem section" id="problem">
          <div className="container problem__grid">
            <SectionHeading
              eyebrow="01 / The evidentiary gap"
              title="The dispute is often decided by the archive, not the event."
              copy="Construction creates vast amounts of documentation, yet very little of it is independently provable when timing and integrity are challenged."
            />
            <div className="problem__signals">
              {problemSignals.map((signal, index) => (
                <article className="signal-card" key={signal.label}>
                  <span>0{index + 1}</span>
                  <div>
                    <h3>{signal.label}</h3>
                    <p>{signal.text}</p>
                  </div>
                </article>
              ))}
            </div>
          </div>
          <div className="container principle-quote">
            <span>THE INVERSION</span>
            <p>Produce proof when the fact is cheap to record, not years later when it is expensive to reconstruct.</p>
          </div>
        </section>

        <section className="method section" id="method">
          <div className="container">
            <SectionHeading
              eyebrow="02 / Lens to ledger"
              title="Five steps. One sealed record."
              copy="The system uses mature primitives in a capture workflow designed to remain nearly invisible on site."
              align="center"
            />
            <div className="pipeline">
              {pipeline.map((step, index) => (
                <article className="pipeline-step" key={step.title}>
                  <div className="pipeline-step__top">
                    <span>{step.number}</span>
                    <Icon name={step.icon} size={25} />
                  </div>
                  <h3>{step.title}</h3>
                  <p>{step.detail}</p>
                  <small>{step.meta}</small>
                  {index < pipeline.length - 1 && <i className="pipeline-step__connector" aria-hidden="true" />}
                </article>
              ))}
            </div>
            <div className="offline-note">
              <span><Icon name="anchor" size={20} /></span>
              <p><strong>Offline is a first-class case.</strong> Captures can be hashed and queued locally; the report then discloses both attested capture time and qualified sealing time.</p>
            </div>
          </div>
        </section>

        <section className="dual-rail section" id="proof">
          <div className="dual-rail__mesh" aria-hidden="true" />
          <div className="container">
            <SectionHeading
              eyebrow="03 / The dual-rail principle"
              title="One record. Two independent anchors."
              copy="Each rail covers the other's weakness. Neither is treated as sufficient on its own."
              align="center"
              inverse
            />
            <div className="rails">
              <article className="rail-card rail-card--green">
                <div className="rail-card__number">A</div>
                <div className="rail-card__body">
                  <span>STATUTORY RAIL</span>
                  <h3>eIDAS qualified timestamp</h3>
                  <p>A qualified RFC 3161 token is designed to carry a presumption of time accuracy and data integrity in EU proceedings.</p>
                  <ul>
                    <li><Icon name="check" size={15} /> Supervised trust provider</li>
                    <li><Icon name="check" size={15} /> Legally recognised time</li>
                    <li><Icon name="check" size={15} /> Independent token validation</li>
                  </ul>
                </div>
              </article>

              <div className="rails__record">
                <span className="rails__line rails__line--top" />
                <div className="rails__record-seal">SS</div>
                <strong>SEALED<br />RECORD</strong>
                <small>Both proofs attached</small>
                <span className="rails__line rails__line--bottom" />
              </div>

              <article className="rail-card rail-card--amber">
                <div className="rail-card__number">B</div>
                <div className="rail-card__body">
                  <span>NEUTRAL RAIL</span>
                  <h3>Public-chain anchor</h3>
                  <p>A Merkle root on a public blockchain is designed to be jurisdiction-neutral and checkable without SiteSealed.</p>
                  <ul>
                    <li><Icon name="check" size={15} /> Public consensus</li>
                    <li><Icon name="check" size={15} /> Logarithmic inclusion proof</li>
                    <li><Icon name="check" size={15} /> No sibling data revealed</li>
                  </ul>
                </div>
              </article>
            </div>
            <p className="rails__honesty">A hash proves existence and integrity - not that the world in front of the lens was unstaged.</p>
          </div>
        </section>

        <section className="report section" id="report">
          <div className="container report__grid">
            <div className="report-preview">
              <div className="report-preview__bar">
                <span>EVIDENCE REPORT / SPECIMEN</span>
                <span>1 PAGE</span>
              </div>
              <a href="/documents/SiteSealed_EvidenceReport_SPECIMEN.pdf" aria-label="Open the specimen Evidence Report PDF">
                <img
                  src="/specimen-preview.webp"
                  alt="Preview of the simulated SiteSealed Evidence Report showing a construction-site image, capture manifest and dual proof rails"
                  width="900"
                  height="1165"
                  loading="lazy"
                />
              </a>
              <span className="report-preview__stamp">SPECIMEN</span>
            </div>

            <div className="report__copy">
              <SectionHeading
                eyebrow="04 / The artefact"
                title="A court-ready format that explains its own limits."
                copy="The Evidence Report brings the capture manifest, the two proof rails and a fixed scope statement into one portable document."
              />
              <div className="report-points">
                <div><span>01</span><p><strong>Project and record</strong> Context, operator, device and record class.</p></div>
                <div><span>02</span><p><strong>Capture manifest</strong> File fingerprint, attested time, mode and position.</p></div>
                <div><span>03</span><p><strong>Dual proof bundle</strong> Qualified timestamp token and public Merkle inclusion path.</p></div>
                <div><span>04</span><p><strong>Honest scope</strong> A plain-language boundary between proof, attestation and ordinary evidence.</p></div>
              </div>
              <a className="button button--navy" href="/documents/SiteSealed_EvidenceReport_SPECIMEN.pdf">
                Download the specimen <Icon name="download" size={17} />
              </a>
              <p className="microcopy">All names, identifiers, providers and proof data in the specimen are simulated.</p>
            </div>
          </div>
        </section>

        <section className="verify section" id="verify">
          <div className="container verify__grid">
            <div className="verify__copy">
              <SectionHeading
                eyebrow="05 / Open verification"
                title="A proof held by one side is a claim. A proof checkable by the other is evidence."
                copy="The Genesis demo below makes a real API request and returns the simulated proof bundle. Production cryptographic checks remain part of Phase 1."
                inverse
              />
              <div className="verify__promise">
                <Icon name="lock" size={20} />
                <p><strong>Free verification, forever.</strong><br />No account, paywall or vendor permission in the production design.</p>
              </div>
            </div>
            <Verifier />
          </div>
        </section>

        <section className="principles section" id="principles">
          <div className="container">
            <SectionHeading
              eyebrow="06 / Founding principles"
              title="The specification may evolve. These seven rules do not."
              copy="Part I of the Genesis whitepaper defines the non-negotiable boundary of the project."
            />
            <div className="principles__grid">
              {principles.map(([number, title, text]) => (
                <article className="principle-card" key={number}>
                  <span>{number}</span>
                  <h3>{title}</h3>
                  <p>{text}</p>
                </article>
              ))}
            </div>
            <div className="scope-statement">
              <div className="scope-statement__label">FIXED SCOPE STATEMENT</div>
              <blockquote>
                “This report proves that the listed files existed in exactly this form no later than the certified time, that they have not been altered since, and that they were captured through an attested device and account at the recorded coordinates.”
              </blockquote>
              <p>It does not, by itself, prove who or what is depicted, nor that the depicted scene was unstaged.</p>
            </div>
          </div>
        </section>

        <section className="roadmap section" id="roadmap">
          <div className="container">
            <SectionHeading
              eyebrow="07 / Trajectory"
              title="First earn the right to be built. Then become the layer."
              copy="The roadmap begins with practitioner validation before production engineering."
              align="center"
            />
            <div className="roadmap__line">
              {roadmap.map((item) => (
                <article className={`roadmap-card${item.current ? " roadmap-card--current" : ""}`} key={item.phase}>
                  <div className="roadmap-card__dot" />
                  <div className="roadmap-card__meta"><span>{item.phase}</span><time>{item.window}</time></div>
                  <h3>{item.title}</h3>
                  <p>{item.text}</p>
                  {item.current && <em>CURRENT</em>}
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="closing">
          <div className="closing__grid" aria-hidden="true" />
          <div className="container closing__inner">
            <div>
              <span className="eyebrow">THE NEUTRAL PROOF LAYER</span>
              <h2>Stop reconstructing.<br /><em>Start sealing.</em></h2>
            </div>
            <div className="closing__actions">
              <button className="button button--amber" type="button" onClick={scrollToVerifier}>
                Verify the specimen <Icon name="arrow" size={18} />
              </button>
              <a className="button button--ghost" href="/documents/SiteSealed_Whitepaper_v1.0_Genesis.pdf">
                Founding whitepaper <Icon name="download" size={17} />
              </a>
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        <div className="container footer__top">
          <div className="footer__brand">
            <Brand compact />
            <p>A neutral proof layer for the construction industry.</p>
          </div>
          <div className="footer__links">
            <div>
              <strong>Explore</strong>
              <a href="#method">How it works</a>
              <a href="#proof">Dual rail</a>
              <a href="#principles">Principles</a>
            </div>
            <div>
              <strong>Documents</strong>
              <a href="/documents/SiteSealed_Whitepaper_v1.0_Genesis.pdf">Whitepaper v1.0</a>
              <a href="/documents/SiteSealed_EvidenceReport_SPECIMEN.pdf">Evidence Report specimen</a>
            </div>
            <div>
              <strong>Status</strong>
              <span>Genesis / Phase 0</span>
              <span>Validation prototype</span>
            </div>
          </div>
        </div>
        <div className="container footer__bottom">
          <span>© {new Date().getFullYear()} SiteSealed Project</span>
          <span>Every record sealed the moment it&apos;s made.</span>
          <a href="#top">Back to top ↑</a>
        </div>
      </footer>
    </>
  );
}

export default App;
