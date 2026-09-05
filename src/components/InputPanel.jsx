import React from 'react';

const DEMO_DOCKERFILE = `FROM node:18-alpine

WORKDIR /app

# Install deps
COPY package*.json ./
RUN npm ci

COPY . .

# NOTE: No USER instruction — runs as root
# NOTE: No HEALTHCHECK

EXPOSE 3000

CMD ["node", "server.js"]`;

const DEMO_K8S = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: demo-app
  template:
    metadata:
      labels:
        app: demo-app
    spec:
      hostNetwork: true
      containers:
        - name: demo-app
          image: myapp:latest
          ports:
            - containerPort: 3000
          env:
            - name: DB_PASSWORD
              value: "supersecret123"
            - name: API_KEY
              value: "hardcoded-api-key"
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true`;

export default function InputPanel({ dockerfile, k8s, onDockerfileChange, onK8sChange, onScan, scanning }) {
  const loadDemo = () => {
    onDockerfileChange(DEMO_DOCKERFILE);
    onK8sChange(DEMO_K8S);
  };

  return (
    <div className="space-y-4">
      {/* Controls row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={loadDemo}
            className="text-xs text-gray-500 border border-gray-200 rounded px-3 py-1.5 hover:border-gray-400 hover:text-gray-800 transition-colors"
          >
            Load demo files
          </button>
          <span className="text-xs text-gray-300">or paste your own below</span>
        </div>
        <button
          onClick={onScan}
          disabled={scanning || (!dockerfile.trim() && !k8s.trim())}
          className="px-5 py-2 bg-gray-950 text-white text-sm font-semibold rounded hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
        >
          {scanning ? (
            <>
              <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
              Scanning…
            </>
          ) : (
            'Scan →'
          )}
        </button>
      </div>

      {/* Two editor panes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Dockerfile */}
        <div className="flex flex-col">
          <label className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-gray-400 inline-block" />
            Dockerfile
          </label>
          <textarea
            value={dockerfile}
            onChange={e => onDockerfileChange(e.target.value)}
            placeholder="Paste your Dockerfile here…"
            spellCheck={false}
            rows={18}
            className="w-full border border-gray-200 rounded p-3 text-xs resize-none focus:outline-none focus:border-gray-400 bg-gray-950 text-gray-100 placeholder-gray-600 leading-relaxed"
          />
        </div>

        {/* K8s YAML */}
        <div className="flex flex-col">
          <label className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-400 inline-block" />
            Kubernetes Manifest (YAML)
          </label>
          <textarea
            value={k8s}
            onChange={e => onK8sChange(e.target.value)}
            placeholder="Paste your Kubernetes YAML here… (supports multi-document with ---)"
            spellCheck={false}
            rows={18}
            className="w-full border border-gray-200 rounded p-3 text-xs resize-none focus:outline-none focus:border-gray-400 bg-gray-950 text-gray-100 placeholder-gray-600 leading-relaxed"
          />
        </div>
      </div>
    </div>
  );
}
