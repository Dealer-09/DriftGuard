/**
 * Kubernetes YAML Parser
 * Uses js-yaml to parse single or multi-document YAML manifests.
 */
import * as yaml from 'js-yaml';

export function parseK8sManifest(content) {
  if (!content || !content.trim()) return [];

  const docs = [];
  try {
    yaml.loadAll(content, (doc) => {
      if (doc && typeof doc === 'object') docs.push(doc);
    });
  } catch (e) {
    console.error('YAML parse error:', e.message);
  }
  return docs;
}

/**
 * Extract all container specs from a manifest doc (handles Pod, Deployment, DaemonSet, etc.)
 */
export function extractContainers(doc) {
  const containers = [];

  const podSpec =
    doc?.spec?.template?.spec ||  // Deployment, DaemonSet, StatefulSet, Job
    doc?.spec ||                   // Pod
    null;

  if (!podSpec) return containers;

  const allContainers = [
    ...(podSpec.containers || []),
    ...(podSpec.initContainers || []),
  ];

  for (const c of allContainers) {
    containers.push({ container: c, podSpec, doc });
  }
  return containers;
}

/**
 * Get the pod-level securityContext (differs from container-level)
 */
export function getPodSecurityContext(doc) {
  return (
    doc?.spec?.template?.spec?.securityContext ||
    doc?.spec?.securityContext ||
    {}
  );
}
