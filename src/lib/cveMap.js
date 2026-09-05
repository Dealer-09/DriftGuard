/**
 * CVE Correlation Map
 * Maps misconfiguration types → known exploits / attack classes they enable.
 *
 * ACCURACY NOTES (verified):
 * - Entries with a real cve_id have been cross-checked against NVD records.
 * - Entries without a cve_id are framed as "attack class" (honest, still impactful).
 *   Citing a wrong CVE number in a live demo is worse than citing none.
 *
 * Two confirmed correct CVE pairings:
 *   PRIVILEGED_CONTAINER → CVE-2022-0185  ✅ (CAP_SYS_ADMIN required, --privileged grants it)
 *   RUN_AS_ROOT          → CVE-2019-5736  ✅ (runc escape, explicitly requires root in container)
 *
 * Others: correct attack class, no specific CVE claimed.
 */
export const CVE_CORRELATION = {

  // ── Verified CVE mappings ─────────────────────────────────────────────────

  PRIVILEGED_CONTAINER: [
    {
      cve_id: 'CVE-2022-0185',
      cvss: 8.8,
      summary: 'Linux kernel heap overflow in legacy_parse_param() — requires CAP_SYS_ADMIN, granted automatically by privileged:true, enabling full container escape to host.',
      nvd_url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-0185',
      attack_technique: 'T1611 — Escape to Host',
      verified: true,
    },
  ],

  RUN_AS_ROOT: [
    {
      cve_id: 'CVE-2019-5736',
      cvss: 8.6,
      summary: 'runc container escape via overwriting /proc/self/exe — explicitly requires root (UID 0) inside the container. Non-root containers are not affected.',
      nvd_url: 'https://nvd.nist.gov/vuln/detail/CVE-2019-5736',
      attack_technique: 'T1611 — Escape to Host',
      verified: true,
    },
  ],

  // ── Attack-class entries (no CVE claimed — honest framing) ───────────────

  HOST_NETWORK: [
    {
      cve_id: null,
      cvss: null,
      summary: 'hostNetwork:true places the container in the host network namespace — it can bind to host ports, sniff node-level traffic, and bypass all Kubernetes NetworkPolicy rules. Same attack class as node-level network interception vulnerabilities.',
      nvd_url: null,
      attack_technique: 'T1599 — Network Boundary Bridging',
      verified: true,
    },
  ],

  LITERAL_SECRET_ENV: [
    {
      cve_id: null,
      cvss: null,
      summary: 'Environment variables are stored unencrypted in the pod spec and etcd, and are visible via /proc/<pid>/environ to any process running as the same UID. Any code execution in the container trivially reads them.',
      nvd_url: null,
      attack_technique: 'T1552.007 — Unsecured Credentials: Container API',
      verified: true,
    },
  ],

  MISSING_READ_ONLY_ROOT: [
    {
      cve_id: null,
      cvss: null,
      summary: 'A writable root filesystem allows an attacker with code execution to overwrite binaries, install persistence mechanisms, or drop malware. Standard post-exploitation foothold pattern.',
      nvd_url: null,
      attack_technique: 'T1574 — Hijack Execution Flow',
      verified: true,
    },
  ],

  ALLOW_PRIVILEGE_ESCALATION: [
    {
      cve_id: null,
      cvss: null,
      summary: 'Without allowPrivilegeEscalation:false (sets no_new_privs=1 in the kernel), a process can gain more privileges than its parent via setuid binaries — the standard local privilege escalation class.',
      nvd_url: null,
      attack_technique: 'T1068 — Exploitation for Privilege Escalation',
      verified: true,
    },
  ],
};
