import { useState } from "react";
import { Cloud, Monitor, ZoomIn, ZoomOut, X } from "lucide-react";

const COLORS = {
  headerBg: "#12172B",
  pageBg: "#F3F5F9",
  cardBorder: "#E3E7F0",
  textPrimary: "#171B2E",
  textMuted: "#666E82",
  ice: "#CADCFC",
  cloud: "#1E2761",
  cloudBg: "#EAECF6",
  endpoint: "#0F6B72",
  endpointBg: "#E5F1F1",
  critical: "#B3261E",
};

const FONT_DISPLAY = "Georgia, 'Times New Roman', serif";
const FONT_BODY = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif";
const FONT_MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

const EVENTS = [
  { id: 1, time: "14:02", minutesFromStart: 0, source: "cloud", critical: true,
    title: "Impossible-travel sign-in", technique: "T1078.004",
    detail: "High-risk sign-in for j.rivera from 45.155.205.233 (Bucharest, RO), 38 minutes after a benign US-based sign-in. MFA satisfied by a token claim rather than a fresh prompt \u2014 consistent with adversary-in-the-middle (AiTM) session-token theft." },
  { id: 2, time: "14:05", minutesFromStart: 3, source: "cloud", critical: false,
    title: "MFA method registered", technique: "T1556.006",
    detail: "Attacker registers a new Microsoft Authenticator method on the compromised account \u2014 durable identity persistence that survives a later password reset." },
  { id: 3, time: "14:06", minutesFromStart: 4, source: "cloud", critical: true,
    title: "Privileged Role Administrator granted", technique: "T1098.003",
    detail: "j.rivera self-assigns the Privileged Role Administrator role, enabling assignment of any role up to Global Administrator." },
  { id: 4, time: "14:08", minutesFromStart: 6, source: "cloud", critical: false,
    title: "OAuth consent granted", technique: "T1528",
    detail: "Illicit application consent to \u201ceM Client\u201d: Mail.Read, offline_access, IMAP.AccessAsUser.All. The offline_access refresh token survives password reset and session revocation." },
  { id: 5, time: "14:12", minutesFromStart: 10, source: "endpoint", critical: true,
    title: "RDP logon to WKSTN-07", technique: "T1021.001",
    detail: "Type-10 (RemoteInteractive) logon to WKSTN-07.insecurebank.local from the same external IP, 45.155.205.233 \u2014 the cloud-to-endpoint hand-off." },
  { id: 6, time: "14:18", minutesFromStart: 16, source: "endpoint", critical: true,
    title: "Mimikatz executed \u2014 LSASS dumped", technique: "T1003.001",
    detail: "A renamed binary (svc-host.exe, OriginalFileName mimikatz.exe) runs sekurlsa::logonpasswords and opens lsass.exe \u2014 in-memory credential theft, launched via encoded PowerShell." },
  { id: 7, time: "14:19", minutesFromStart: 17, source: "endpoint", critical: false,
    title: "C2 beacon established", technique: "T1071",
    detail: "Outbound connection from WKSTN-07 (10.20.7.41) to 45.155.205.233:443 \u2014 the same IP used for the initial sign-in and RDP logon." },
  { id: 8, time: "14:20", minutesFromStart: 18, source: "endpoint", critical: true,
    title: "DCSync replication (\u00d72)", technique: "T1003.006",
    detail: "Two Windows Security 4662 events on DC1 carrying DS-Replication-Get-Changes and -Get-Changes-All rights, requested by j.rivera \u2014 not a domain-controller machine account. Full AD credential database, including krbtgt, should be treated as exposed." },
];

const ZOOM_LEVELS = [1, 1.5, 2.2];

export default function AttackTimeline() {
  const [selected, setSelected] = useState(EVENTS[EVENTS.length - 1]);
  const [zoomIdx, setZoomIdx] = useState(0);

  const pxPerMinute = 46 * ZOOM_LEVELS[zoomIdx];
  const trackWidth = Math.max(700, EVENTS[EVENTS.length - 1].minutesFromStart * pxPerMinute + 160);

  const sourceLabel = (s) => (s === "cloud" ? "Cloud" : "Endpoint");
  const sourceColor = (s) => (s === "cloud" ? COLORS.cloud : COLORS.endpoint);
  const sourceBg = (s) => (s === "cloud" ? COLORS.cloudBg : COLORS.endpointBg);

  return (
    <div style={{ minHeight: "100%", background: COLORS.pageBg, fontFamily: FONT_BODY }}>
      <div style={{ background: COLORS.headerBg, padding: "20px 28px" }}>
        <div style={{ fontFamily: FONT_DISPLAY, color: "#fff", fontSize: 22, fontWeight: 700 }}>
          Attack Progression Timeline
        </div>
        <div style={{ color: COLORS.ice, fontSize: 13, marginTop: 3 }}>
          j.rivera cloud-to-endpoint compromise \u2014 2026-07-19, 14:02\u201314:20 UTC (18-minute window)
        </div>
      </div>

      <div style={{ maxWidth: 1000, margin: "0 auto", padding: "28px 24px 40px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
          <div style={{ display: "flex", gap: 18, alignItems: "center" }}>
            <LegendDot color={COLORS.cloud} label="Cloud" />
            <LegendDot color={COLORS.endpoint} label="Endpoint" />
            <span style={{ fontSize: 12, color: COLORS.textMuted, display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 10, height: 10, borderRadius: "50%", border: `2px solid ${COLORS.critical}`, display: "inline-block", boxSizing: "border-box" }} />
              High-severity marker
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 12, color: COLORS.textMuted, marginRight: 4 }}>Zoom</span>
            <IconBtn onClick={() => setZoomIdx((z) => Math.max(0, z - 1))} disabled={zoomIdx === 0}><ZoomOut size={15} /></IconBtn>
            <IconBtn onClick={() => setZoomIdx((z) => Math.min(ZOOM_LEVELS.length - 1, z + 1))} disabled={zoomIdx === ZOOM_LEVELS.length - 1}><ZoomIn size={15} /></IconBtn>
          </div>
        </div>

        <div style={{ background: "#fff", border: `1px solid ${COLORS.cardBorder}`, borderRadius: 10, padding: "32px 24px 24px", marginBottom: 20, overflowX: "auto" }}>
          <div style={{ position: "relative", width: trackWidth, height: 150 }}>
            <div style={{ position: "absolute", left: 20, right: 20, top: 70, height: 3, background: COLORS.cardBorder, borderRadius: 2 }} />
            {EVENTS.map((ev, i) => {
              const x = 20 + ev.minutesFromStart * pxPerMinute;
              const above = i % 2 === 0;
              const isSelected = selected?.id === ev.id;
              return (
                <div key={ev.id} style={{ position: "absolute", left: x, top: 0, width: 1 }}>
                  <div style={{ position: "absolute", left: -0.5, width: 1, top: above ? 40 : 73, height: 30, background: COLORS.cardBorder }} />
                  <button
                    onClick={() => setSelected(ev)}
                    style={{
                      position: "absolute", top: 62, left: -9, width: 18, height: 18, borderRadius: "50%",
                      background: sourceColor(ev.source), cursor: "pointer",
                      border: ev.critical ? `3px solid ${COLORS.critical}` : "3px solid #fff",
                      boxShadow: isSelected ? `0 0 0 4px ${sourceBg(ev.source)}` : "0 1px 3px rgba(0,0,0,0.2)",
                      padding: 0,
                    }}
                    aria-label={`${ev.time} ${ev.title}`}
                  />
                  <div
                    onClick={() => setSelected(ev)}
                    style={{ position: "absolute", top: above ? 0 : 108, left: -60, width: 150, cursor: "pointer", textAlign: "center" }}
                  >
                    <div style={{ fontFamily: FONT_MONO, fontSize: 12, fontWeight: 700, color: isSelected ? sourceColor(ev.source) : COLORS.textPrimary }}>
                      {ev.time}
                    </div>
                    <div style={{ fontSize: 11, color: COLORS.textMuted, lineHeight: 1.25, marginTop: 2 }}>
                      {ev.title}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ fontSize: 11.5, color: COLORS.textMuted, marginBottom: 20 }}>
          Node position reflects actual elapsed time \u2014 note the dense cluster from 14:18\u201314:20 versus the wider gaps earlier. A pre-incident baseline sign-in (13:24) and an unrelated single-source event (14:30) were evaluated and correctly excluded from this incident on correlation grounds; not plotted here.
        </div>

        {selected && (
          <div style={{ background: "#fff", border: `1px solid ${COLORS.cardBorder}`, borderRadius: 10, padding: 22, position: "relative" }}>
            <button
              onClick={() => setSelected(null)}
              style={{ position: "absolute", top: 16, right: 16, background: "none", border: "none", cursor: "pointer", color: COLORS.textMuted }}
              aria-label="Close details"
            >
              <X size={16} />
            </button>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{
                display: "inline-flex", alignItems: "center", gap: 5, padding: "3px 10px", borderRadius: 999,
                background: sourceBg(selected.source), color: sourceColor(selected.source), fontSize: 12, fontWeight: 600,
              }}>
                {selected.source === "cloud" ? <Cloud size={12} strokeWidth={2.5} /> : <Monitor size={12} strokeWidth={2.5} />}
                {sourceLabel(selected.source)}
              </span>
              <span style={{ fontFamily: FONT_MONO, fontSize: 12, color: COLORS.textMuted }}>{selected.time} UTC</span>
              <span style={{ fontFamily: FONT_MONO, fontSize: 12, fontWeight: 700, color: COLORS.textPrimary, marginLeft: "auto" }}>
                {selected.technique}
              </span>
            </div>
            <div style={{ fontFamily: FONT_DISPLAY, fontSize: 18, fontWeight: 700, color: COLORS.textPrimary, marginBottom: 8 }}>
              {selected.title}
            </div>
            <div style={{ fontSize: 13.5, color: COLORS.textPrimary, lineHeight: 1.55 }}>
              {selected.detail}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function LegendDot({ color, label }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#666E82" }}>
      <span style={{ width: 10, height: 10, borderRadius: "50%", background: color, display: "inline-block" }} />
      {label}
    </span>
  );
}

function IconBtn({ children, onClick, disabled }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        display: "flex", alignItems: "center", justifyContent: "center",
        width: 28, height: 28, borderRadius: 6, border: `1px solid ${COLORS.cardBorder}`,
        background: disabled ? "#F5F6F8" : "#fff", color: disabled ? "#C3C7D1" : COLORS.textPrimary,
        cursor: disabled ? "default" : "pointer",
      }}
    >
      {children}
    </button>
  );
}
