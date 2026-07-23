import { useState, useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { ShieldCheck, ShieldAlert, Filter } from "lucide-react";

const COLORS = {
  navy: "#1E2761",
  ice: "#CADCFC",
  headerBg: "#12172B",
  pageBg: "#F3F5F9",
  cardBorder: "#E3E7F0",
  textPrimary: "#171B2E",
  textMuted: "#666E82",
  covered: "#1E7A4C",
  coveredBg: "#E8F3EC",
  gap: "#B3261E",
  gapBg: "#FCEBEA",
  partial: "#9A6B00",
  partialBg: "#FBF1DC",
};

const FONT_DISPLAY = "Georgia, 'Times New Roman', serif";
const FONT_BODY = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif";
const FONT_MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

const TECHNIQUES = [
  { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", status: "gap", coverage: 0, evidence: "Impossible-travel sign-in \u2014 event 1" },
  { id: "T1556.006", name: "Modify Authentication Process: MFA", status: "gap", coverage: 0, evidence: "Attacker-registered MFA method \u2014 event 2" },
  { id: "T1098.003", name: "Account Manipulation: Additional Cloud Roles", status: "gap", coverage: 0, evidence: "Self-granted Privileged Role Administrator \u2014 event 3" },
  { id: "T1528", name: "Steal Application Access Token", status: "gap", coverage: 0, evidence: "Illicit OAuth consent (eM Client) \u2014 event 4" },
  { id: "T1021.001", name: "Remote Services: RDP", status: "gap", coverage: 0, evidence: "Type-10 logon to WKSTN-07 \u2014 event 5" },
  { id: "T1071", name: "Application Layer Protocol (C2)", status: "gap", coverage: 0, evidence: "C2 beacon to 45.155.205.233:443 \u2014 event 8" },
  { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", status: "covered", coverage: 100, evidence: "lsass_memory_access, lsass_minidump rules" },
  { id: "T1003.006", name: "OS Credential Dumping: DCSync", status: "covered", coverage: 100, evidence: "dcsync rule" },
].sort((a, b) => a.coverage - b.coverage || a.id.localeCompare(b.id));

function statusStyle(status) {
  if (status === "covered") return { color: COLORS.covered, bg: COLORS.coveredBg, label: "Covered" };
  if (status === "partial") return { color: COLORS.partial, bg: COLORS.partialBg, label: "Partial" };
  return { color: COLORS.gap, bg: COLORS.gapBg, label: "Gap" };
}

function StatusChip({ status }) {
  const s = statusStyle(status);
  const Icon = status === "covered" ? ShieldCheck : ShieldAlert;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "3px 10px",
        borderRadius: 999,
        background: s.bg,
        color: s.color,
        fontFamily: FONT_BODY,
        fontSize: 12,
        fontWeight: 600,
        letterSpacing: 0.2,
        whiteSpace: "nowrap",
      }}
    >
      <Icon size={13} strokeWidth={2.5} />
      {s.label}
    </span>
  );
}

function CoverageMeter({ coveredPct, gapPct }) {
  return (
    <div>
      <div style={{ display: "flex", height: 22, borderRadius: 6, overflow: "hidden", border: `1px solid ${COLORS.cardBorder}` }}>
        <div style={{ width: `${coveredPct}%`, background: COLORS.covered }} />
        <div style={{ width: `${gapPct}%`, background: COLORS.gap }} />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8, fontFamily: FONT_BODY, fontSize: 13, color: COLORS.textMuted }}>
        <span><b style={{ color: COLORS.covered }}>{coveredPct}%</b> covered</span>
        <span><b style={{ color: COLORS.gap }}>{gapPct}%</b> gap</span>
      </div>
    </div>
  );
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const d = payload[0].payload;
  const s = statusStyle(d.status);
  return (
    <div style={{ background: "#fff", border: `1px solid ${COLORS.cardBorder}`, borderRadius: 8, padding: "10px 12px", boxShadow: "0 4px 16px rgba(0,0,0,0.08)", fontFamily: FONT_BODY, maxWidth: 260 }}>
      <div style={{ fontFamily: FONT_MONO, fontWeight: 700, fontSize: 13, color: COLORS.textPrimary }}>{d.id}</div>
      <div style={{ fontSize: 12, color: COLORS.textPrimary, marginTop: 2 }}>{d.name}</div>
      <div style={{ fontSize: 12, color: s.color, fontWeight: 600, marginTop: 6 }}>{s.label} \u2014 {d.coverage}%</div>
    </div>
  );
}

export default function DetectionCoverageDashboard() {
  const [showGapsOnly, setShowGapsOnly] = useState(false);

  const stats = useMemo(() => {
    const total = TECHNIQUES.length;
    const covered = TECHNIQUES.filter((t) => t.status === "covered").length;
    const gaps = TECHNIQUES.filter((t) => t.status === "gap").length;
    const avg = Math.round(TECHNIQUES.reduce((sum, t) => sum + t.coverage, 0) / total);
    return { total, covered, gaps, avg, coveredPct: Math.round((covered / total) * 100), gapPct: Math.round((gaps / total) * 100) };
  }, []);

  const visible = showGapsOnly ? TECHNIQUES.filter((t) => t.status !== "covered") : TECHNIQUES;

  return (
    <div style={{ minHeight: "100%", background: COLORS.pageBg, fontFamily: FONT_BODY }}>
      {/* Header */}
      <div style={{ background: COLORS.headerBg, padding: "20px 28px" }}>
        <div style={{ fontFamily: FONT_DISPLAY, color: "#fff", fontSize: 22, fontWeight: 700, letterSpacing: 0.2 }}>
          Detection Coverage
        </div>
        <div style={{ color: COLORS.ice, fontSize: 13, marginTop: 3 }}>
          j.rivera cloud-to-endpoint compromise \u2014 ATT&CK techniques vs. current rule coverage
        </div>
      </div>

      <div style={{ maxWidth: 920, margin: "0 auto", padding: "28px 24px 40px" }}>
        {/* Hero: coverage meter + stats */}
        <div style={{ background: "#fff", border: `1px solid ${COLORS.cardBorder}`, borderRadius: 10, padding: 24, marginBottom: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", flexWrap: "wrap", gap: 12, marginBottom: 14 }}>
            <div style={{ fontFamily: FONT_DISPLAY, fontSize: 17, fontWeight: 700, color: COLORS.textPrimary }}>
              Overall Coverage
            </div>
            <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: COLORS.textMuted }}>
              {stats.total} techniques observed in this incident
            </div>
          </div>
          <CoverageMeter coveredPct={stats.coveredPct} gapPct={stats.gapPct} />

          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginTop: 22 }}>
            <StatBlock label="Techniques Observed" value={stats.total} color={COLORS.textPrimary} />
            <StatBlock label="Average Coverage" value={`${stats.avg}%`} color={stats.avg < 50 ? COLORS.gap : COLORS.covered} />
            <StatBlock label="Detection Gaps" value={stats.gaps} color={COLORS.gap} />
          </div>
        </div>

        {/* Bar chart */}
        <div style={{ background: "#fff", border: `1px solid ${COLORS.cardBorder}`, borderRadius: 10, padding: 24, marginBottom: 20 }}>
          <div style={{ fontFamily: FONT_DISPLAY, fontSize: 17, fontWeight: 700, color: COLORS.textPrimary, marginBottom: 4 }}>
            Coverage by Technique
          </div>
          <div style={{ fontSize: 12.5, color: COLORS.textMuted, marginBottom: 16 }}>
            Sorted worst-covered first
          </div>
          <ResponsiveContainer width="100%" height={340}>
            <BarChart data={TECHNIQUES} layout="vertical" margin={{ top: 0, right: 30, left: 0, bottom: 0 }}>
              <XAxis type="number" domain={[0, 100]} tickFormatter={(v) => `${v}%`} tick={{ fontFamily: FONT_BODY, fontSize: 11, fill: COLORS.textMuted }} axisLine={{ stroke: COLORS.cardBorder }} tickLine={false} />
              <YAxis type="category" dataKey="id" width={92} tick={{ fontFamily: FONT_MONO, fontSize: 12, fill: COLORS.textPrimary }} axisLine={{ stroke: COLORS.cardBorder }} tickLine={false} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(0,0,0,0.03)" }} />
              <Bar dataKey="coverage" radius={[0, 4, 4, 0]} barSize={20}>
                {TECHNIQUES.map((t) => (
                  <Cell key={t.id} fill={statusStyle(t.status).color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Technique list with filter */}
        <div style={{ background: "#fff", border: `1px solid ${COLORS.cardBorder}`, borderRadius: 10, padding: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 10 }}>
            <div style={{ fontFamily: FONT_DISPLAY, fontSize: 17, fontWeight: 700, color: COLORS.textPrimary }}>
              Technique Detail
            </div>
            <button
              onClick={() => setShowGapsOnly((v) => !v)}
              style={{
                display: "inline-flex", alignItems: "center", gap: 6,
                padding: "7px 14px", borderRadius: 7, cursor: "pointer",
                border: `1px solid ${showGapsOnly ? COLORS.gap : COLORS.cardBorder}`,
                background: showGapsOnly ? COLORS.gapBg : "#fff",
                color: showGapsOnly ? COLORS.gap : COLORS.textMuted,
                fontFamily: FONT_BODY, fontSize: 12.5, fontWeight: 600,
              }}
            >
              <Filter size={13} strokeWidth={2.5} />
              {showGapsOnly ? "Showing gaps only" : "Show gaps only"}
            </button>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {visible.map((t) => (
              <div
                key={t.id}
                style={{
                  display: "flex", alignItems: "center", gap: 14,
                  padding: "12px 14px", borderRadius: 8,
                  background: statusStyle(t.status).bg,
                  border: `1px solid ${COLORS.cardBorder}`,
                }}
              >
                <div style={{ fontFamily: FONT_MONO, fontWeight: 700, fontSize: 13, color: COLORS.textPrimary, width: 96, flexShrink: 0 }}>
                  {t.id}
                </div>
                <div style={{ flex: 1, minWidth: 180 }}>
                  <div style={{ fontSize: 13.5, color: COLORS.textPrimary, fontWeight: 600 }}>{t.name}</div>
                  <div style={{ fontSize: 12, color: COLORS.textMuted, marginTop: 1 }}>{t.evidence}</div>
                </div>
                <div style={{ width: 90, flexShrink: 0 }}>
                  <div style={{ height: 6, borderRadius: 3, background: "rgba(0,0,0,0.08)", overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${t.coverage}%`, background: statusStyle(t.status).color, borderRadius: 3 }} />
                  </div>
                </div>
                <StatusChip status={t.status} />
              </div>
            ))}
          </div>
        </div>

        <div style={{ fontSize: 11.5, color: COLORS.textMuted, marginTop: 18, fontFamily: FONT_BODY }}>
          Coverage checked against Module 5's curated detection rule mapping (credential-access focused). Cloud and lateral-movement techniques are not yet tracked in that mapping \u2014 reported here as gaps, not guessed.
        </div>
      </div>
    </div>
  );
}

function StatBlock({ label, value, color }) {
  return (
    <div>
      <div style={{ fontFamily: FONT_DISPLAY, fontSize: 30, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 12, color: COLORS.textMuted, marginTop: 2 }}>{label}</div>
    </div>
  );
}
