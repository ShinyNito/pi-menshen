/**
 * Smoke test: run a REAL Guardian auto-review with a real reviewer session.
 *
 * Spawns a reviewer agent session (Guardian-style), feeds it a sample tool call
 * + a fake parent transcript, and prints the resulting assessment.
 *
 * Run manually (uses real model auth):
 *   node --experimental-strip-types smoke-review.ts
 */
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import {
  classifyRequest,
  createReviewerSession,
  disposeReviewerSession,
  type ClassifierResult,
} from "./classifier.ts";

const modelId = process.env.MENSHEN_SMOKE_MODEL ?? "goopq-ai/deepseek-v4-flash";
const cwd = process.cwd();

const modelRuntime = await ModelRuntime.create({
  authPath: `${process.env.HOME}/.pi/agent/auth.json`,
  modelsPath: `${process.env.HOME}/.pi/agent/models.json`,
});
const [provider, ...rest] = modelId.split("/");
const id = rest.join("/");
const model = modelRuntime.getModel(provider, id);
if (!model) {
  console.error(`model not found: ${modelId}`);
  process.exit(1);
}
console.log(`model: ${model.provider}/${model.id}`);

// Minimal fake ExtensionContext — the classifier only needs these pieces.
// getBranch must return a STABLE array reference (like pi's live branch) so
// delta-mode tests can grow the branch between reviews.
const liveBranch: unknown[] = [
  { type: "message", id: "u1", message: { role: "user", content: "Add a healthcheck to the docker-compose file" } },
  { type: "message", id: "a1", message: { role: "assistant", content: "I'll add it to the compose file." } },
  { type: "message", id: "t1", message: { role: "tool", name: "read", content: '{"path":"docker-compose.yml"}' } },
  { type: "message", id: "t2", message: { role: "toolResult", name: "read", content: "services:\n  app:\n    image: nginx" } },
];

const fakeCtx = {
  cwd,
  model,
  modelRegistry: { runtime: modelRuntime, find: () => model },
  sessionManager: { getBranch: () => liveBranch },
} as never;

const config = {
  enabled: true,
  classifierModel: "",
  classifierTimeoutMs: 60_000,
  maxClassifierChars: 18_000,
  gatedTools: ["bash", "write", "edit", "fetch_content", "mcp"],
  sensitivePaths: [".env", ".env.*", "*.pem", "package-lock.json", ".github/workflows"],
  guardian: {
    maxAttempts: 3,
    maxChecks: 3,
    checkTimeoutMs: 4000,
    checkOutputChars: 4000,
    consecutiveDenyLimit: 3,
    denyWindowLimit: 10,
    denyWindowSize: 50,
  },
  notifications: { enabled: false, onManualPrompt: false, onBreakerTrip: false, protocol: "auto" as const },
  relay: { enabled: false, probeTimeoutMs: 2000, responseTimeoutMs: 120000 },
  rules: { allow: [], deny: [], ask: [] },
} as never;

const reviewer = createReviewerSession();
const phases: string[] = [];

try {
  // Review 1: benign write inside the project
  console.log("\n--- review 1: write docker-compose.yml (benign) ---");
  let result: ClassifierResult = await classifyRequest(
    fakeCtx,
    {
      cwd,
      toolName: "edit",
      args: { filePath: "docker-compose.yml", oldString: "image: nginx", newString: "image: nginx\n    healthcheck:\n      test: [\"CMD\", \"curl\", \"-f\", \"http://localhost\"]" },
      matchKey: "edit docker-compose.yml",
      userRequest: "Add a healthcheck to the docker-compose file",
      ruleResult: { behavior: "unmatched" },
    },
    config,
    undefined,
    { session: reviewer, maxAttempts: 3, maxChecks: 3, onPhase: (p) => phases.push(JSON.stringify(p)) },
  );
  console.log("phases:", phases.slice(-6).join("  "));
  printResult(result);

  // Review 2: npm run build (not read-only, not dangerous → LLM review)
  console.log("\n--- review 2: bash npm run build (LLM review) ---");
  phases.length = 0;
  result = await classifyRequest(
    fakeCtx,
    {
      cwd,
      toolName: "bash",
      args: { command: "npm run build" },
      matchKey: "npm run build",
      userRequest: "Add a healthcheck to the docker-compose file",
      ruleResult: { behavior: "unmatched" },
    },
    config,
    undefined,
    { session: reviewer, maxAttempts: 3, maxChecks: 3, onPhase: (p) => phases.push(JSON.stringify(p)) },
  );
  console.log("phases:", phases.slice(-6).join("  "));
  printResult(result);

  // Review 3: npm run deploy (not read-only, not dangerous → LLM review; branch grew → delta mode)
  console.log("\n--- review 3: bash npm run deploy (delta transcript) ---");
  phases.length = 0;
  liveBranch.push(
    { type: "message", id: "a2", message: { role: "assistant", content: "Preparing the deploy." } },
    { type: "message", id: "t3", message: { role: "tool", name: "read", content: '{"path":"package.json"}' } },
  );
  result = await classifyRequest(
    fakeCtx,
    {
      cwd,
      toolName: "bash",
      args: { command: "npm run deploy" },
      matchKey: "npm run deploy",
      userRequest: "Add a healthcheck to the docker-compose file",
      ruleResult: { behavior: "unmatched" },
    },
    config,
    undefined,
    { session: reviewer, maxAttempts: 3, maxChecks: 3, onPhase: (p) => phases.push(JSON.stringify(p)) },
  );
  console.log("phases:", phases.slice(-6).join("  "));
  printResult(result);

  // Verify the delta: the LAST user message in the reviewer session must be a
  // TRANSCRIPT DELTA containing only the entries added after review 2.
  const reviewerSession = (reviewer as never as { session: { messages: Array<{ role: string; content: unknown }> } | null }).session;
  const lastUser = reviewerSession?.messages.filter((m) => m.role === "user").at(-1);
  const lastText = lastUser ? extractTextOf(lastUser.content) : "";
  console.log("\n--- last reviewer user message (delta verification) ---");
  console.log("contains TRANSCRIPT DELTA:", lastText.includes("TRANSCRIPT DELTA START"));
  console.log("contains TRANSCRIPT START (full):", lastText.includes(">>> TRANSCRIPT START"));
  console.log("contains new entry (a2):", lastText.includes("Preparing the deploy."));
  console.log("contains old entry (u1):", lastText.includes("Add a healthcheck"));
  console.log(lastText.slice(0, 400));

  function extractTextOf(content: unknown): string {
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
      return content
        .filter((p) => typeof p === "object" && p !== null && (p as { type?: string }).type === "text")
        .map((p) => (p as { text?: string }).text ?? "")
        .join("");
    }
    return "";
  }
} finally {
  disposeReviewerSession(reviewer);
  console.log("\nreviewer trunk disposed.");
}

function printResult(r: ClassifierResult): void {
  console.log(`decision:     ${r.decision}`);
  console.log(`classifier:   ${r.classifierUsed ? "LLM" : r.deterministic ? "deterministic" : "none"}`);
  console.log(`model:        ${r.model}`);
  console.log(`checks:       ${r.checks.join(", ") || "(none)"}`);
  console.log(`risk:         ${r.assessment.risk_level}`);
  console.log(`authorization:${r.assessment.user_authorization}`);
  console.log(`rationale:    ${r.assessment.rationale}`);
  console.log(`reviewed at delta baseline: ${(reviewer as never as { lastEntryCount?: number }).lastEntryCount}`);
}
