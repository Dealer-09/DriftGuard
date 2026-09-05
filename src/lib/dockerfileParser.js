/**
 * Dockerfile Parser
 * Line-based regex parser — same approach as hook_scanner.py in the CLI.
 * No AST library needed; Dockerfile syntax is simple enough for line-by-line analysis.
 */

export function parseDockerfile(content) {
  const lines = content.split('\n');
  const instructions = [];

  let currentInstruction = null;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();

    if (!trimmed || trimmed.startsWith('#')) continue;

    // Handle line continuations
    if (currentInstruction && raw.endsWith('\\')) {
      currentInstruction.args += ' ' + trimmed.slice(0, -1).trim();
      continue;
    }
    if (currentInstruction && !raw.match(/^[A-Z]/)) {
      currentInstruction.args += ' ' + trimmed;
      continue;
    }

    const match = trimmed.match(/^([A-Z]+)\s+(.*)/s);
    if (match) {
      currentInstruction = {
        instruction: match[1].toUpperCase(),
        args: raw.endsWith('\\') ? match[2].slice(0, -1).trim() : match[2].trim(),
        line: i + 1,
        raw: trimmed,
      };
      instructions.push(currentInstruction);
    }
  }

  // Extract useful fields
  const fromInstructions = instructions.filter(i => i.instruction === 'FROM');
  const userInstructions = instructions.filter(i => i.instruction === 'USER');
  const exposeInstructions = instructions.filter(i => i.instruction === 'EXPOSE');
  const healthcheckInstructions = instructions.filter(i => i.instruction === 'HEALTHCHECK');
  const envInstructions = instructions.filter(i => i.instruction === 'ENV');
  const argInstructions = instructions.filter(i => i.instruction === 'ARG');
  const addInstructions = instructions.filter(i => i.instruction === 'ADD');
  const copyInstructions = instructions.filter(i => i.instruction === 'COPY');

  // Determine effective user (last USER instruction in final stage)
  const finalStageIdx = fromInstructions.length > 0
    ? fromInstructions[fromInstructions.length - 1].line
    : 0;
  const finalStageUser = userInstructions
    .filter(u => u.line > finalStageIdx)
    .pop();

  // Detect if FROM is multi-stage and final stage is minimal/distroless
  const finalFrom = fromInstructions[fromInstructions.length - 1];
  const isDistroless = finalFrom
    ? /distroless|scratch|alpine|busybox|slim/i.test(finalFrom.args)
    : false;

  // Extract base image
  const baseImage = finalFrom ? finalFrom.args.split(/\s+as\s+/i)[0].trim() : '';

  return {
    instructions,
    baseImage,
    isDistroless,
    finalStageUser: finalStageUser || null,
    exposedPorts: exposeInstructions.map(e => e.args.trim()),
    hasHealthcheck: healthcheckInstructions.length > 0,
    envVars: envInstructions,
    argVars: argInstructions,
    addInstructions,
    copyInstructions,
    fromInstructions,
    userInstructions,
    raw: content,
    lines,
  };
}
