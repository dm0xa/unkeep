import type {
  ApiErrorBody,
  ChallengeResponse,
  CreateResponse,
  OpenResponse,
  ReceiptView,
  RevokeResponse,
  SecretEnvelope,
} from "./types.ts";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function readError(response: Response): Promise<ApiError> {
  let body: ApiErrorBody | null = null;
  try {
    body = (await response.json()) as ApiErrorBody;
  } catch {
    body = null;
  }
  const code = body?.error?.code ?? "request_failed";
  const message = body?.error?.message ?? "The request failed.";
  return new ApiError(response.status, code, message);
}

async function request<T>(
  path: string,
  init: RequestInit,
): Promise<T> {
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    referrerPolicy: "no-referrer",
    // A half-open connection must not strand the UI on "Locking…" or
    // "Revealing…"; every caller already has an error path.
    signal: AbortSignal.timeout(15_000),
    ...init,
  });
  if (!response.ok) {
    throw await readError(response);
  }
  return (await response.json()) as T;
}

export function createSecret(
  envelope: SecretEnvelope,
  ttlSeconds: number,
  proof: string,
): Promise<CreateResponse> {
  return request<CreateResponse>("/api/secrets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ envelope, ttlSeconds, proof }),
  });
}

export function getChallenge(id: string): Promise<ChallengeResponse> {
  return request<ChallengeResponse>(
    `/api/secrets/${encodeURIComponent(id)}`,
    { method: "GET" },
  );
}

export function openSecret(
  id: string,
  challenge: string,
  proof: string,
): Promise<OpenResponse> {
  return request<OpenResponse>(
    `/api/secrets/${encodeURIComponent(id)}/open`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Not-Saved-Confirm": "reveal",
        "X-Secret-Proof": proof,
      },
      body: JSON.stringify({ challenge, confirmation: "reveal" }),
    },
  );
}

export function confirmDecrypted(
  id: string,
  viewToken: string,
): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(
    `/api/secrets/${encodeURIComponent(id)}/decrypted`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Not-Saved-Confirm": "reveal",
      },
      body: JSON.stringify({ viewToken }),
      // The recipient is told to close the tab right after revealing; keepalive
      // lets the event land even when they do.
      keepalive: true,
    },
  );
}

export function fetchReceipt(
  id: string,
  receiptToken: string,
): Promise<ReceiptView> {
  return request<ReceiptView>(
    `/api/secrets/${encodeURIComponent(id)}/receipt`,
    {
      method: "POST",
      headers: { "X-Receipt-Token": receiptToken },
    },
  );
}

export function revokeSecret(
  id: string,
  receiptToken: string,
): Promise<RevokeResponse> {
  return request<RevokeResponse>(
    `/api/secrets/${encodeURIComponent(id)}/revoke`,
    {
      method: "POST",
      headers: {
        "X-Receipt-Token": receiptToken,
        "X-Not-Saved-Confirm": "revoke",
      },
    },
  );
}
