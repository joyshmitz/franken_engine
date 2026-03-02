#!/usr/bin/env node

import { createHash } from "node:crypto";

async function readStdinUtf8() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function emit(payload) {
  process.stdout.write(JSON.stringify(payload));
}

function emitError(errorCode, detail) {
  emit({ error_code: errorCode });
  if (detail) {
    process.stderr.write(`${detail}\n`);
  }
}

function normalizeSource(source) {
  return source.replace(/\r\n/g, "\n");
}

async function main() {
  const stdinPayload = await readStdinUtf8();
  let request;
  try {
    request = JSON.parse(stdinPayload);
  } catch (error) {
    emitError("external_request_invalid_json", `invalid stdin payload: ${error}`);
    process.exitCode = 1;
    return;
  }

  if (!request || typeof request.source !== "string") {
    emitError(
      "external_request_missing_source",
      "stdin payload must include string field `source`",
    );
    process.exitCode = 1;
    return;
  }

  const digest = createHash("sha256")
    .update(normalizeSource(request.source), "utf8")
    .digest("hex");
  emit({ hash: `sha256:${digest}` });
}

main().catch((error) => {
  emitError("external_adapter_internal_error", String(error));
  process.exitCode = 1;
});
