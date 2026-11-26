const BASE_URL = '/api';

export async function api(endpoint, { method = 'GET', body, signal } = {}) {
  const res = await fetch(`${BASE_URL}${endpoint}`, {
    method,
    signal,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const detail = Array.isArray(err.detail) ? err.detail.map((d) => d.msg).join(', ') : err.detail;
    throw new Error(detail || `Request failed (${res.status})`);
  }
  if (res.status === 204) return null;
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function downloadPdfReport(scan) {
  const report = await api(`/reports?scan_id=${scan.id}`, { method: 'POST' });
  const res = await fetch(`${BASE_URL}/reports/${report.id}/download`);
  if (!res.ok) throw new Error('Download failed');
  downloadBlob(await res.blob(), `securescan-${scan.domain}-${scan.id}.pdf`);
}

export function downloadJson(data, filename) {
  downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }), filename);
}
