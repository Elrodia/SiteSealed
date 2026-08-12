import { useEffect, useId, useRef, useState } from "react";
import {
  buildManifest,
  createEncryptedUploadHeaders,
  createPrivateRecoveryKit,
  createRecoveryToken,
  createRandomUuid,
  createSealRequest,
  encryptManifest,
  encryptOriginal,
  formatBytes,
  MAX_FILE_BYTES,
  sha256File,
  verifyPublicProofArtifacts,
} from "./sealing.js";

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
    title: "Timestamp",
    detail: "The alpha requests an RFC 3161 test token from Evidency sandbox; production qualification remains a separate gate.",
    meta: "Sandbox",
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
  ["06", "Privacy by architecture", "Plaintext originals remain client-controlled; private storage receives only client-encrypted ciphertext."],
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
    upload: (
      <>
        <path d="M12 16V4" />
        <path d="m7 9 5-5 5 5" />
        <path d="M5 14v6h14v-6" />
      </>
    ),
    file: (
      <>
        <path d="M6 3h8l4 4v14H6z" />
        <path d="M14 3v5h5M9 13h6M9 17h6" />
      </>
    ),
    key: (
      <>
        <circle cx="8" cy="15" r="4" />
        <path d="m11 12 8-8M15 8l2 2M17 6l2 2" />
      </>
    ),
    alert: (
      <>
        <path d="M12 3 2.5 20h19z" />
        <path d="M12 9v5M12 17.5h.01" />
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
      <img src="/icon-192.svg?v=20260812" alt="" width="42" height="42" />
      <span className="brand__name">SITESEALED</span>
    </a>
  );
}

function Header({ onSeal, onVerify }) {
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
  const seal = () => {
    close();
    onSeal();
  };

  return (
    <header className="site-header">
      <div className="container header__inner">
        <Brand />
        <nav className={`nav${menuOpen ? " nav--open" : ""}`} aria-label="Primary navigation">
          <a href="#method" onClick={close}>How it works</a>
          <a href="#seal" onClick={close}>Create a receipt</a>
          <a href="#proof" onClick={close}>Dual rail</a>
          <a href="#principles" onClick={close}>Principles</a>
          <a href="/documents/SiteSealed_Whitepaper_v1.0_Genesis.pdf" onClick={close}>Whitepaper</a>
          <button className="button button--small button--amber nav__cta" type="button" onClick={seal}>
            Create an alpha receipt <Icon name="arrow" size={16} />
          </button>
          <button className="nav__verify" type="button" onClick={verify}>Verify</button>
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
        <span><i /> TARGET CAPTURE</span>
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
        <b>SPECIMEN</b>
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
        <span><small>TARGET PROOF BUNDLE</small><strong>Independently checkable</strong></span>
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

function downloadBlob(fileName, blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function downloadJson(fileName, value) {
  downloadBlob(
    fileName,
    new Blob([`${JSON.stringify(value, null, 2)}\n`], {
      type: "application/json",
    }),
  );
}

async function readApiJson(response) {
  const text = await response.text();
  if (!text) {
    throw new Error(`The SiteSealed API returned an empty response (${response.status}).`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`The SiteSealed API returned an unreadable response (${response.status}).`);
  }
}

function recordIdFromPath() {
  const match = window.location.pathname.match(/^\/verify\/([^/]+)\/?$/i);
  if (!match) return "";
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return "";
  }
}

function SealingWorkbench({ onVerify }) {
  const fileInputId = useId();
  const projectInputId = useId();
  const descriptionInputId = useId();
  const [file, setFile] = useState(null);
  const [projectReference, setProjectReference] = useState("");
  const [description, setDescription] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [recoveryKit, setRecoveryKit] = useState(null);
  const [backupStatus, setBackupStatus] = useState("idle");
  const [submissionId, setSubmissionId] = useState(() => createRandomUuid());
  const preparedAttemptRef = useRef(null);

  const selectFile = (event) => {
    const nextFile = event.target.files?.[0] ?? null;
    setFile(nextFile);
    setStatus("idle");
    setMessage("");
    setResult(null);
    setRecoveryKit(null);
    setBackupStatus("idle");
    preparedAttemptRef.current = null;
    setSubmissionId(createRandomUuid());
  };

  const seal = async (event) => {
    event.preventDefault();
    setMessage("");
    setResult(null);
    setRecoveryKit(null);
    setBackupStatus("idle");

    if (!file) {
      setStatus("error");
      setMessage("Select a file to create an integrity receipt.");
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setStatus("error");
      setMessage("This v1.4 alpha workflow accepts files up to 25 MB.");
      return;
    }
    if (!acknowledged) {
      setStatus("error");
      setMessage("Confirm that this is an imported file, not an attested live capture.");
      return;
    }

    try {
      let attempt = preparedAttemptRef.current;
      const attemptMatches =
        attempt?.file === file &&
        attempt?.projectReference === projectReference &&
        attempt?.description === description;
      let activeSubmissionId = submissionId;

      if (!attemptMatches) {
        if (attempt) {
          activeSubmissionId = createRandomUuid();
          setSubmissionId(activeSubmissionId);
        }
        setStatus("hashing");
        const recordSha256 = await sha256File(file);
        const manifest = buildManifest(file, { projectReference, description });

        setStatus("encrypting");
        const encrypted = await encryptManifest(manifest);
        const encryptedOriginal = await encryptOriginal(file, encrypted.recoveryKey);
        const recoveryToken = await createRecoveryToken();
        attempt = {
          file,
          projectReference,
          description,
          submissionId: activeSubmissionId,
          recordSha256,
          manifest,
          encrypted,
          encryptedOriginal,
          recoveryToken,
        };
        preparedAttemptRef.current = attempt;
      } else {
        activeSubmissionId = attempt.submissionId;
      }

      const {
        recordSha256,
        manifest,
        encrypted,
        encryptedOriginal,
        recoveryToken,
      } = attempt;

      setStatus("uploading");
      const uploadResponse = await fetch(
        `/api/storage/uploads/${encodeURIComponent(activeSubmissionId)}`,
        {
          method: "PUT",
          headers: createEncryptedUploadHeaders({
            recordSha256,
            encryptedOriginal,
            recoveryTokenSha256: recoveryToken.sha256,
          }),
          body: encryptedOriginal.ciphertext,
        },
      );
      const uploadPayload = await readApiJson(uploadResponse);
      if (!uploadResponse.ok) {
        throw new Error(
          uploadPayload.message || "The encrypted original could not be stored.",
        );
      }

      const requestBody = createSealRequest({
        recordSha256,
        manifestSha256: encrypted.manifestSha256,
        envelope: encrypted.envelope,
        encryptedObject: uploadPayload.encryptedObject,
        submissionId: activeSubmissionId,
      });

      setStatus("recording");
      const response = await fetch("/api/records", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(requestBody),
      });
      const payload = await readApiJson(response);
      if (!response.ok) throw new Error(payload.message || "The receipt could not be created.");

      const kit = createPrivateRecoveryKit({
        manifest,
        envelope: encrypted.envelope,
        recoveryKey: encrypted.recoveryKey,
        encryptedObject: uploadPayload.encryptedObject,
        recoveryToken: recoveryToken.token,
        serverResponse: payload,
      });
      setRecoveryKit(kit);
      setResult(payload);
      setStatus("success");
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "The receipt could not be created.");
    }
  };

  const downloadRecoveryKit = () => {
    if (!recoveryKit || !result) return;
    downloadJson(
      `SiteSealed_${result.record.recordId}_PRIVATE-recovery-kit.json`,
      recoveryKit,
    );
  };

  const downloadEncryptedBackup = async () => {
    const retrieval = recoveryKit?.encryptedOriginal?.retrieval;
    if (!retrieval || !result) return;
    setBackupStatus("loading");
    try {
      const response = await fetch(retrieval.url, {
        method: retrieval.method,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(retrieval.requestBody),
      });
      if (!response.ok) {
        const payload = await readApiJson(response);
        throw new Error(payload.message || "The encrypted backup could not be retrieved.");
      }
      downloadBlob(
        `SiteSealed_${result.record.recordId}_encrypted-original.ssenc`,
        await response.blob(),
      );
      setBackupStatus("success");
    } catch (error) {
      setBackupStatus(
        error instanceof Error ? error.message : "The encrypted backup could not be retrieved.",
      );
    }
  };

  const progressLabel = {
    hashing: "Hashing the file locally...",
    encrypting: "Encrypting the manifest and original locally...",
    uploading: "Sending only encrypted ciphertext to the private Bucket...",
    recording: "Binding the MySQL receipt and PostgreSQL audit event...",
  }[status];

  return (
    <div className="sealing-workbench">
      <div className="sealing-workbench__header">
        <span className="sealing-workbench__icon"><Icon name="shield" size={25} /></span>
        <div>
          <span>V1.4 ALPHA WORKFLOW</span>
          <strong>Create an imported-file alpha receipt</strong>
        </div>
        <span className="development-pill">DUAL RAIL ASYNC</span>
      </div>

      <div className="privacy-rail" aria-label="Privacy guarantees">
        <span><Icon name="file" size={17} /><b>Original</b> encrypted before upload</span>
        <span><Icon name="lock" size={17} /><b>Manifest</b> AES-256-GCM encrypted</span>
        <span><Icon name="key" size={17} /><b>Key</b> never sent</span>
      </div>

      <form className="seal-form" onSubmit={seal} noValidate>
        <div className="seal-form__grid">
          <div className="file-picker">
            <input
              id={fileInputId}
              type="file"
              onChange={selectFile}
              aria-describedby={`${fileInputId}-hint`}
            />
            <label htmlFor={fileInputId}>
              <span><Icon name="upload" size={28} /></span>
              {file ? (
                <>
                  <strong>{file.name}</strong>
                  <small>{formatBytes(file.size)} - click to replace</small>
                </>
              ) : (
                <>
                  <strong>Select a construction record</strong>
                  <small>Photo, PDF or other file - maximum 25 MB</small>
                </>
              )}
            </label>
            <p id={`${fileInputId}-hint`}>Only hashes and AES-256-GCM ciphertext leave this browser.</p>
          </div>

          <div className="seal-form__context">
            <label htmlFor={projectInputId}>Project reference <span>encrypted</span></label>
            <input
              id={projectInputId}
              type="text"
              maxLength="120"
              value={projectReference}
              onChange={(event) => setProjectReference(event.target.value)}
              placeholder="e.g. RBP-C-2026"
            />
            <label htmlFor={descriptionInputId}>Private note <span>encrypted</span></label>
            <textarea
              id={descriptionInputId}
              maxLength="500"
              rows="3"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Optional context kept inside the encrypted manifest"
            />
          </div>
        </div>

        <label className="seal-acknowledgement">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          <span>
            <strong>I understand this is an imported-file alpha receipt.</strong>
            It is not a live capture or qualified eIDAS timestamp. Any Evidency sandbox token is test-only; Ethereum anchoring happens asynchronously.
          </span>
        </label>

        <div className="seal-form__submit">
          <button
            className="button button--amber"
            type="submit"
            disabled={["hashing", "encrypting", "uploading", "recording"].includes(status)}
          >
            {progressLabel || "Hash, encrypt and record"}
            {!progressLabel && <Icon name="arrow" size={17} />}
          </button>
          <p>Anonymous v1.4 alpha limit: 20 receipts per IP and hour, coordinated through Redis.</p>
        </div>
      </form>

      <div className="seal-response" aria-live="polite">
        {["hashing", "encrypting", "uploading", "recording"].includes(status) && (
          <div className="seal-progress">
            <span /><span /><span />
            <p>{progressLabel}</p>
          </div>
        )}

        {status === "error" && (
          <div className="seal-error" role="alert">
            <Icon name="alert" size={21} />
            <div><strong>Seal not created</strong><p>{message}</p></div>
          </div>
        )}

        {status === "success" && result && (
          <div className="seal-success">
            <div className="seal-success__title">
              <span><Icon name="check" size={22} /></span>
              <div>
                <small>V1.4 ALPHA RECEIPT CREATED / EXTERNAL RAILS QUEUED</small>
                <h3>{result.record.recordId}</h3>
              </div>
              <em>{result.storage?.persistent ? "S3 + MySQL + PostgreSQL persisted" : "Memory only - not persistent"}</em>
            </div>
            <div className="seal-success__facts">
              <div><span>FILE SHA-256</span><code>{result.record.sha256}</code></div>
              <div><span>SERVER RECEIPT TIME</span><strong>{new Date(result.record.receivedAt).toLocaleString()}</strong></div>
              <div><span>PRIVATE STORAGE</span><strong>Client-encrypted original - proof artefacts attach asynchronously</strong></div>
            </div>
            <div className="seal-success__warning">
              <Icon name="key" size={19} />
              <p><strong>Download the private recovery kit now.</strong> It contains the only copy of the AES key and must remain confidential.</p>
            </div>
            <div className="seal-success__actions">
              <button className="button button--navy" type="button" onClick={downloadRecoveryKit}>
                Private recovery kit <Icon name="download" size={16} />
              </button>
              <button
                className="button button--outline"
                type="button"
                onClick={downloadEncryptedBackup}
                disabled={backupStatus === "loading"}
              >
                {backupStatus === "loading" ? "Retrieving..." : "Encrypted S3 backup"}
                <Icon name="download" size={16} />
              </button>
              <a className="button button--outline" href={result.links.receiptPdf}>
                PDF receipt <Icon name="download" size={16} />
              </a>
              <a className="button button--outline" href={result.links.publicBundle}>
                Public bundle <Icon name="download" size={16} />
              </a>
              <button className="text-action" type="button" onClick={() => onVerify(result.record.recordId)}>
                Verify this record <Icon name="arrow" size={15} />
              </button>
            </div>
            {backupStatus !== "idle" && backupStatus !== "loading" && (
              <p className={`seal-success__retrieval${backupStatus === "success" ? " seal-success__retrieval--success" : ""}`}>
                {backupStatus === "success"
                  ? "Encrypted backup retrieved and integrity-checked."
                  : backupStatus}
              </p>
            )}
          </div>
        )}
      </div>
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
      const payload = await readApiJson(response);
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

function VerifierV12({ requestedRecord }) {
  const inputId = useId();
  const compareInputId = useId();
  const pathRecordId = useRef(recordIdFromPath());
  const lastAutomaticRequest = useRef("");
  const [recordId, setRecordId] = useState(pathRecordId.current);
  const [comparisonFile, setComparisonFile] = useState(null);
  const [status, setStatus] = useState("idle");
  const [result, setResult] = useState(null);
  const [message, setMessage] = useState("");
  const [fileCheck, setFileCheck] = useState({ state: "NOT_CHECKED", digest: null });
  const [copied, setCopied] = useState(false);

  const runVerification = async (candidate, fileToCheck = comparisonFile) => {
    const normalized = String(candidate ?? "").trim().toUpperCase().replace(/\s+/g, "");
    if (!normalized) {
      setStatus("error");
      setMessage("Enter a SiteSealed record ID.");
      return;
    }

    setStatus("loading");
    setResult(null);
    setMessage("");
    setCopied(false);
    setFileCheck({ state: fileToCheck ? "HASHING" : "NOT_CHECKED", digest: null });

    try {
      const response = await fetch(`/api/verify/${encodeURIComponent(normalized)}`);
      const payload = await readApiJson(response);
      if (!response.ok) throw new Error(payload.message || "Verification failed.");

      let nextFileCheck = { state: "NOT_CHECKED", digest: null };
      if (fileToCheck) {
        const digest = await sha256File(fileToCheck);
        nextFileCheck = {
          state: digest === payload.record.sha256 ? "MATCH" : "MISMATCH",
          digest,
        };
      }

      const clientProofCheck = payload.specimen
        ? { state: "SIMULATED_NOT_CHECKED" }
        : await verifyPublicProofArtifacts(payload.record);

      setRecordId(normalized);
      setResult({ ...payload, clientProofCheck });
      setFileCheck(nextFileCheck);
      setStatus("success");
      window.history.replaceState({}, "", `/verify/${encodeURIComponent(normalized)}`);
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Verification failed.");
      setFileCheck({ state: "NOT_CHECKED", digest: null });
    }
  };

  useEffect(() => {
    const automaticId = requestedRecord?.id || pathRecordId.current;
    const requestKey = requestedRecord
      ? `${requestedRecord.id}:${requestedRecord.nonce}`
      : automaticId;
    if (!automaticId || lastAutomaticRequest.current === requestKey) return;
    lastAutomaticRequest.current = requestKey;
    setRecordId(automaticId);
    runVerification(automaticId, null);
  }, [requestedRecord?.id, requestedRecord?.nonce]);

  const verify = (event) => {
    event.preventDefault();
    runVerification(recordId, comparisonFile);
  };

  const useSpecimen = () => {
    setRecordId(SPECIMEN_ID);
    setStatus("idle");
    setMessage("");
    setResult(null);
    setFileCheck({ state: "NOT_CHECKED", digest: null });
    document.getElementById(inputId)?.focus();
  };

  const copyHash = async () => {
    if (!result?.record?.sha256) return;
    await navigator.clipboard.writeText(result.record.sha256);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  const resultTitle = result?.specimen
    ? "SPECIMEN RECORD FOUND"
    : result?.clientProofCheck?.state === "FAIL"
      ? "PUBLIC PROOF FAILED LOCAL CHECK"
      : fileCheck.state === "MATCH"
        ? "LOCAL FILE MATCH VERIFIED"
        : fileCheck.state === "MISMATCH"
          ? "LOCAL FILE DOES NOT MATCH"
          : "V1.4 ALPHA RECEIPT FOUND";

  const qualifiedRailReady = Boolean(
    result?.specimen ||
      (["SANDBOX_TOKEN_ISSUED", "TOKEN_ISSUED"].includes(
        result?.record?.qualifiedRail?.state,
      ) &&
        result?.record?.qualifiedRail?.signatureVerification === "VALID" &&
        result?.record?.qualifiedRail?.certificateChainVerification ===
          "VALID_TO_PINNED_SANDBOX_ROOT"),
  );
  const chainRailReady = Boolean(
    result?.specimen ||
      ["SUBMITTED", "CONFIRMED", "FINALIZED"].includes(
        result?.record?.chainRail?.state,
      ),
  );
  const chainRailFailed = ["FAILED_ON_CHAIN", "INVALID_ON_CHAIN"].includes(
    result?.record?.chainRail?.state,
  );
  const externalStateLabel = result?.specimen
    ? "SIMULATED"
    : chainRailFailed
      ? "MAINNET ANCHOR REJECTED"
      : result?.alphaComplete
        ? "ALPHA DUAL RAIL COMPLETE"
        : result?.record?.chainRail?.state === "FINALIZED"
          ? "MAINNET FINALIZED / QTSP PENDING"
          : qualifiedRailReady
            ? "SANDBOX VERIFIED / MAINNET PENDING"
            : result?.record?.qualifiedRail?.state === "SANDBOX_TOKEN_ISSUED"
              ? "SANDBOX TOKEN / VERIFICATION PENDING"
            : "EXTERNAL RAILS QUEUED";

  return (
    <div className="verifier-shell verifier-shell--v12">
      <div className="verifier-shell__header">
        <span className="verifier-shell__icon"><Icon name="shield" size={24} /></span>
        <div>
          <span>PUBLIC VERIFICATION PORTAL</span>
          <strong>Receipt and local-file checker</strong>
        </div>
        <span className="live-pill">V1.4 ALPHA</span>
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
            placeholder="SR-YYYYMMDD-..."
            aria-describedby={`${inputId}-hint`}
          />
          <button className="button button--amber" type="submit" disabled={status === "loading"}>
            {status === "loading" ? "Checking..." : "Verify receipt"}
            {status !== "loading" && <Icon name="arrow" size={17} />}
          </button>
        </div>
        <div className="verify-form__hint" id={`${inputId}-hint`}>
          <span>No account required.</span>
          <button type="button" onClick={useSpecimen}>Use specimen ID</button>
        </div>

        <div className="local-file-check">
          <div>
            <span><Icon name="file" size={18} /></span>
            <p><strong>Optional: select the original file.</strong><br />Its hash is recalculated locally and the file is never uploaded.</p>
          </div>
          <input
            id={compareInputId}
            type="file"
            onChange={(event) => setComparisonFile(event.target.files?.[0] ?? null)}
          />
          <label htmlFor={compareInputId}>
            {comparisonFile ? `${comparisonFile.name} (${formatBytes(comparisonFile.size)})` : "Choose local file"}
          </label>
        </div>
      </form>

      <div className="verifier-response" aria-live="polite">
        {status === "idle" && (
          <div className="verifier-idle">
            <span className="verifier-idle__line" />
            <p>Look up a receipt, then optionally prove byte-for-byte integrity with a local file.</p>
          </div>
        )}

        {status === "loading" && (
          <div className="verifier-loading">
            <span /><span /><span />
            <p>{fileCheck.state === "HASHING" ? "Recalculating the local SHA-256 digest..." : "Reading the persisted receipt..."}</p>
          </div>
        )}

        {status === "error" && (
          <div className="verifier-error" role="alert">
            <strong>Record not verified</strong>
            <p>{message}</p>
          </div>
        )}

        {status === "success" && result && (
          <div className={`verified-result${fileCheck.state === "MISMATCH" || result.clientProofCheck?.state === "FAIL" ? " verified-result--mismatch" : ""}`}>
            <div className="verified-result__title">
              <span><Icon name={fileCheck.state === "MISMATCH" || result.clientProofCheck?.state === "FAIL" ? "alert" : "check"} size={22} /></span>
              <div>
                <small>{resultTitle}</small>
                <h3>{result.record.recordId}</h3>
              </div>
              <em>{externalStateLabel}</em>
            </div>

            {!result.specimen && (
              <div className={`local-match local-match--${fileCheck.state.toLowerCase()}`}>
                <Icon
                  name={fileCheck.state === "MISMATCH" ? "alert" : fileCheck.state === "MATCH" ? "check" : "file"}
                  size={20}
                />
                <div>
                  <strong>
                    {fileCheck.state === "MATCH"
                      ? "Byte-for-byte match"
                      : fileCheck.state === "MISMATCH"
                        ? "Hash mismatch"
                        : "File integrity not checked"}
                  </strong>
                  <p>
                    {fileCheck.state === "MATCH"
                      ? "The selected file recalculates to the recorded SHA-256 digest."
                      : fileCheck.state === "MISMATCH"
                        ? "The selected file is not the same byte sequence as the recorded digest."
                        : "Select the independently held original above and run verification again."}
                  </p>
                </div>
              </div>
            )}

            {!result.specimen && (
              <div className={`local-match local-match--${result.clientProofCheck?.state === "FAIL" ? "mismatch" : result.clientProofCheck?.state === "PASS" ? "match" : "not_checked"}`}>
                <Icon name={result.clientProofCheck?.state === "FAIL" ? "alert" : "tree"} size={20} />
                <div>
                  <strong>
                    {result.clientProofCheck?.state === "PASS"
                      ? "Receipt proof artefacts recalculated in this browser"
                      : result.clientProofCheck?.state === "FAIL"
                        ? "Public proof bundle failed local recalculation"
                        : "Receipt digest valid; public anchor not attached yet"}
                  </strong>
                  <p>
                    Evidence digest: {result.clientProofCheck?.evidenceDigest} · Merkle inclusion: {result.clientProofCheck?.merkleInclusion} · Ethereum calldata: {result.clientProofCheck?.transactionBinding}
                  </p>
                </div>
              </div>
            )}

            <div className="verified-result__rails">
              <article className={`verified-rail verified-rail--green${qualifiedRailReady ? "" : " verified-rail--pending"}`}>
                <span>RAIL A / RFC 3161 TIME</span>
                <strong>{result.record.qualifiedRail.provider}</strong>
                <p>{result.record.qualifiedRail.status}</p>
              </article>
              <article className={`verified-rail verified-rail--amber${chainRailFailed ? " verified-rail--failed" : chainRailReady ? "" : " verified-rail--pending"}`}>
                <span>RAIL B / ETHEREUM MAINNET</span>
                <strong>{result.record.chainRail.chain}</strong>
                <p>{result.record.chainRail.block ? `Block ${result.record.chainRail.block} - ` : ""}{result.record.chainRail.status}</p>
              </article>
            </div>

            <div className="verified-result__hash">
              <span>RECORDED FILE SHA-256</span>
              <code>{result.record.sha256}</code>
              <button type="button" onClick={copyHash} aria-label="Copy recorded SHA-256 hash">
                <Icon name={copied ? "check" : "copy"} size={16} /> {copied ? "Copied" : "Copy"}
              </button>
            </div>

            {!result.specimen && (
              <div className="verified-result__audit">
                <span>POSTGRESQL OPERATIONAL AUDIT / INTERNAL APPLICATION LAYER</span>
                {result.operationalAudit?.state === "RECORDED" ? (
                  <>
                    <strong>
                      Event sequence {result.operationalAudit.event.sequence} - hash chain valid
                    </strong>
                    <code>{result.operationalAudit.event.eventSha256}</code>
                  </>
                ) : (
                  <strong>
                    {result.operationalAudit?.state === "NOT_RECORDED_LEGACY"
                      ? "Legacy receipt - no append-only audit event"
                      : "Operational audit temporarily unavailable"}
                  </strong>
                )}
                <p>This database event is not an eIDAS timestamp or a public-chain anchor.</p>
              </div>
            )}

            {!result.specimen && (
              <div className="verified-result__downloads">
                <a href={`/api/records/${encodeURIComponent(result.record.recordId)}/report.pdf`}>
                  PDF receipt <Icon name="download" size={15} />
                </a>
                <a href={`/api/records/${encodeURIComponent(result.record.recordId)}/bundle`}>
                  Public proof bundle <Icon name="download" size={15} />
                </a>
                {result.record.qualifiedRail?.token && (
                  <a href={`/api/records/${encodeURIComponent(result.record.recordId)}/timestamp.tsr`}>
                    RFC 3161 token <Icon name="download" size={15} />
                  </a>
                )}
                {result.record.chainRail?.anchor && (
                  <a
                    href={`https://etherscan.io/tx/${encodeURIComponent(result.record.chainRail.anchor)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Ethereum transaction <Icon name="external" size={15} />
                  </a>
                )}
              </div>
            )}

            <p className="verified-result__disclaimer">
              <strong>Honest scope:</strong> {result.scope.doesNotProve}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function InfrastructureStatus() {
  const [health, setHealth] = useState(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    let controller = null;
    const refresh = () => {
      controller?.abort();
      controller = new AbortController();
      fetch("/api/health", { signal: controller.signal, cache: "no-store" })
        .then(async (response) => {
          if (!response.ok) throw new Error("Health endpoint unavailable");
          return response.json();
        })
        .then((payload) => {
          if (!active) return;
          setHealth(payload);
          setFailed(false);
        })
        .catch((error) => {
          if (active && error.name !== "AbortError") setFailed(true);
        });
    };
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") refresh();
    };
    refresh();
    const interval = window.setInterval(refresh, 30_000);
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      active = false;
      controller?.abort();
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  const services = [
    {
      name: "MySQL",
      role: "Receipt registry",
      data: health?.database,
    },
    {
      name: "S3",
      role: "Encrypted objects",
      data: health?.objectStorage,
    },
    {
      name: "PostgreSQL",
      role: "Append-only audit",
      data: health?.auditDatabase,
    },
    {
      name: "Redis",
      role: "Distributed guard + cache",
      data: health?.coordination,
    },
    {
      name: "Evidency",
      role: "Sandbox RFC 3161 adapter",
      data: health?.qualifiedTimestamp,
    },
    {
      name: "Ethereum",
      role: "Mainnet Merkle anchor",
      data: health?.publicChainAnchor,
    },
  ];

  return (
    <div className="infrastructure-status" aria-live="polite">
      <div className="infrastructure-status__heading">
        <div>
          <span>V1.4 ALPHA.7 / SIX RUNTIME ROLES</span>
          <strong>Private storage, internal audit and two external proof rails.</strong>
        </div>
        <small className={failed ? "is-error" : health ? "is-online" : ""}>
          {failed ? "STATUS UNAVAILABLE" : health ? "API ONLINE" : "CHECKING"}
        </small>
      </div>
      <div className="infrastructure-status__grid">
        {services.map((service) => {
          const status = service.data?.status;
          const connected = ["connected", "operational", "finalized"].includes(status);
          const ready = [
            "configured",
            "dry_run_ready",
            "dry_run_no_eligible_record",
            "submitted",
            "confirmed",
          ].includes(status);
          const errored = status === "error";
          const local = service.data?.mode === "memory";
          const label = status === "operational"
            ? "ON"
            : status === "finalized"
              ? "FINALIZED"
              : status === "confirmed"
                ? "CONFIRMED"
                : status === "submitted"
                  ? "SUBMITTED"
            : status === "connected"
              ? "ONLINE"
              : status === "configured"
                ? "READY"
                : status === "dry_run_ready" || status === "dry_run_no_eligible_record"
                  ? "DRY RUN"
                  : errored
                    ? "ERROR"
            : local
              ? "LOCAL"
              : status === "not_configured"
                ? "OFF"
                : "...";
          const indicatorClass = connected
            ? "is-online"
            : ready
              ? "is-ready"
              : errored
                ? "is-error"
                : local
                  ? "is-local"
                  : "";
          return (
            <div
              className="infrastructure-node"
              key={service.name}
              title={service.data?.message ?? undefined}
            >
              <i className={indicatorClass} />
              <div>
                <strong>{service.name}</strong>
                <span>{service.role}</span>
              </div>
              <small>{label}</small>
            </div>
          );
        })}
      </div>
      <p>
        Evidency sandbox is test-only and never qualified. Ethereum writes are opt-in,
        use real ETH and run in the separate hourly Railway worker.
      </p>
    </div>
  );
}

function App() {
  const [verificationTarget, setVerificationTarget] = useState(null);

  const scrollToSeal = () => {
    document.getElementById("seal")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const scrollToVerifier = (recordIdToVerify) => {
    if (recordIdToVerify) {
      setVerificationTarget({ id: recordIdToVerify, nonce: Date.now() });
    }
    document.getElementById("verify")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Header onSeal={scrollToSeal} onVerify={scrollToVerifier} />

      <main id="main-content">
        <section className="hero" id="top">
          <div className="hero__mesh" aria-hidden="true" />
          <div className="container hero__inner">
            <div className="hero__copy">
              <div className="phase-tag"><span>V1.4 ALPHA</span> EVIDENCY SANDBOX + ETHEREUM MAINNET</div>
              <h1>Construction records that can <em>verify themselves.</em></h1>
              <p className="hero__lede">
                Create a real SHA-256 integrity receipt and client-encrypted backup, then queue an Evidency sandbox RFC 3161 test token and an hourly Merkle anchor on Ethereum mainnet. Sandbox time has no legal effect, so final “sealed” status stays disabled.
              </p>
              <div className="hero__actions">
                <button className="button button--amber" type="button" onClick={scrollToSeal}>
                  Create an alpha receipt <Icon name="arrow" size={18} />
                </button>
                <button className="button button--ghost" type="button" onClick={() => scrollToVerifier()}>
                  Verify a record <Icon name="shield" size={17} />
                </button>
                <a className="button button--ghost" href="/documents/SiteSealed_Whitepaper_v1.0_Genesis.pdf">
                  Read the whitepaper <Icon name="external" size={17} />
                </a>
              </div>
              <div className="hero__trustline">
                <span><Icon name="lock" size={16} /> Client-side encrypted original</span>
                <span><Icon name="shield" size={16} /> Exportable RFC 3161 + Merkle artefacts</span>
              </div>
            </div>
            <HeroSeal />
          </div>
          <div className="container hero__foot">
            <p>Every alpha receipt states exactly which proofs exist.</p>
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
              title="Five steps. One explicit proof state."
              copy="The target system uses mature primitives while the alpha labels every unavailable or test-only capability."
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
                  <span>ALPHA ADAPTER / TEST ONLY</span>
                  <h3>Evidency sandbox RFC 3161</h3>
                  <p>The alpha sends only the evidence digest, then verifies the returned CMS signature, ESSCertIDv2 signer binding and certificate path to a release-pinned sandbox root. The sandbox cannot provide qualified legal effect.</p>
                  <ul>
                    <li><Icon name="check" size={15} /> Digest-only API request</li>
                    <li><Icon name="check" size={15} /> Independent signature + chain gate</li>
                    <li><Icon name="check" size={15} /> Exportable timestamp token</li>
                    <li><Icon name="alert" size={15} /> Not qualified; no legal use</li>
                  </ul>
                </div>
              </article>

              <div className="rails__record">
                <span className="rails__line rails__line--top" />
                <div className="rails__record-seal">SS</div>
                <strong>ALPHA<br />RECEIPT</strong>
                <small>State machine, never overclaimed</small>
                <span className="rails__line rails__line--bottom" />
              </div>

              <article className="rail-card rail-card--amber">
                <div className="rail-card__number">B</div>
                <div className="rail-card__body">
                  <span>FINAL PUBLIC RAIL / OPT-IN WRITES</span>
                  <h3>Ethereum mainnet anchor</h3>
                  <p>The hourly worker batches evidence digests, writes the Merkle root into transaction calldata and records an inclusion path for each receipt.</p>
                  <ul>
                    <li><Icon name="check" size={15} /> Chain ID 1 enforced</li>
                    <li><Icon name="check" size={15} /> Signed transaction persisted first</li>
                    <li><Icon name="check" size={15} /> Finality rechecked from public RPC</li>
                  </ul>
                </div>
              </article>
            </div>
            <p className="rails__honesty">Alpha-complete means sandbox token plus finalized mainnet anchor. It still does not mean eIDAS-qualified, live-captured or factually true.</p>
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

        <section className="seal-workflow section" id="seal">
          <div className="container">
            <div className="seal-workflow__intro">
              <SectionHeading
                eyebrow="05 / First real workflow"
                title="Hash locally. Encrypt locally. Record only what is necessary."
                copy="This v1.4 alpha creates a persistent imported-file receipt, issues test timestamps through the Evidency sandbox adapter and batches evidence digests for a real Ethereum mainnet anchor, while keeping the whitepaper's final legal threshold visibly out of reach."
              />
              <div className="seal-workflow__boundary">
                <span><Icon name="alert" size={18} /> CURRENT BOUNDARY</span>
                <p><strong>Implemented in alpha:</strong> SHA-256, client-side AES-256-GCM, private S3 ciphertext, MySQL receipts, PostgreSQL append-only audit, Redis coordination, Evidency sandbox RFC 3161 requests with independent CMS signature and pinned-chain validation, domain-separated Merkle proofs, Ethereum mainnet transactions, public lookup and dynamic PDF/bundle exports.</p>
                <p><strong>Still not production-qualified:</strong> Evidency production contract and production trust policy, certificate revocation validation, in-app camera attestation, identity, device trust, GNSS and a formal security review.</p>
              </div>
            </div>
            <InfrastructureStatus />
            <SealingWorkbench onVerify={scrollToVerifier} />
          </div>
        </section>

        <section className="verify section" id="verify">
          <div className="container verify__grid">
            <div className="verify__copy">
              <SectionHeading
                eyebrow="06 / Open verification"
                title="A proof held by one side is a claim. A proof checkable by the other is evidence."
                copy="Look up any v1.4 alpha receipt, inspect each external rail independently and optionally recalculate the original file's SHA-256 entirely in your browser."
                inverse
              />
              <div className="verify__promise">
                <Icon name="lock" size={20} />
                <p><strong>Free verification, forever.</strong><br />No account, paywall or vendor permission in the production design.</p>
              </div>
            </div>
            <VerifierV12 requestedRecord={verificationTarget} />
          </div>
        </section>

        <section className="principles section" id="principles">
          <div className="container">
            <SectionHeading
              eyebrow="07 / Founding principles"
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
              eyebrow="08 / Trajectory"
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
              <button className="button button--amber" type="button" onClick={scrollToSeal}>
                Create an alpha receipt <Icon name="arrow" size={18} />
              </button>
              <button className="button button--ghost" type="button" onClick={() => scrollToVerifier()}>
                Verify a record <Icon name="shield" size={17} />
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
              <span>Genesis v1.4 alpha.7 MVP</span>
              <span>Evidency sandbox test rail</span>
              <span>Ethereum mainnet final rail</span>
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
