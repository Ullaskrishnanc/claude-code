import { describe, it, expect, vi, beforeEach } from "vitest";
import { SignJWT } from "jose";
import { NextRequest } from "next/server";

// ── Mocks ────────────────────────────────────────────────────────────────────

// "server-only" throws at import time in non-server environments
vi.mock("server-only", () => ({}));

// Shared mock cookie store reused across all tests
const mockCookieStore = {
  get: vi.fn(),
  set: vi.fn(),
  delete: vi.fn(),
};

vi.mock("next/headers", () => ({
  cookies: vi.fn(() => Promise.resolve(mockCookieStore)),
}));

// Import AFTER mocks are registered
import {
  createSession,
  getSession,
  deleteSession,
  verifySession,
  type SessionPayload,
} from "@/lib/auth";

// ── Helpers ──────────────────────────────────────────────────────────────────

const JWT_SECRET = new TextEncoder().encode("development-secret-key");
const COOKIE_NAME = "auth-token";

/** Build a real signed JWT with the dev secret */
async function signToken(
  payload: SessionPayload,
  expirationTime: string | number = "7d"
) {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(expirationTime)
    .setIssuedAt()
    .sign(JWT_SECRET);
}

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

const samplePayload: SessionPayload = {
  userId: "user-123",
  email: "test@example.com",
  expiresAt: new Date(Date.now() + SEVEN_DAYS_MS),
};

// ── createSession ────────────────────────────────────────────────────────────

describe("createSession", () => {
  beforeEach(() => vi.clearAllMocks());

  it("sets an HTTP-only cookie named 'auth-token'", async () => {
    await createSession("user-123", "test@example.com");

    expect(mockCookieStore.set).toHaveBeenCalledOnce();
    const [name, , options] = mockCookieStore.set.mock.calls[0];
    expect(name).toBe(COOKIE_NAME);
    expect(options.httpOnly).toBe(true);
  });

  it("sets cookie with lax sameSite and root path", async () => {
    await createSession("user-123", "test@example.com");

    const [, , options] = mockCookieStore.set.mock.calls[0];
    expect(options.sameSite).toBe("lax");
    expect(options.path).toBe("/");
  });

  it("sets cookie expiry approximately 7 days from now", async () => {
    const before = Date.now();
    await createSession("user-123", "test@example.com");
    const after = Date.now();

    const [, , options] = mockCookieStore.set.mock.calls[0];
    const expiresMs = (options.expires as Date).getTime();

    expect(expiresMs).toBeGreaterThanOrEqual(before + SEVEN_DAYS_MS - 1000);
    expect(expiresMs).toBeLessThanOrEqual(after + SEVEN_DAYS_MS + 1000);
  });

  it("stores a non-empty JWT string as the cookie value", async () => {
    await createSession("user-123", "test@example.com");

    const [, token] = mockCookieStore.set.mock.calls[0];
    expect(typeof token).toBe("string");
    // JWTs have three base64-url segments separated by dots
    expect(token.split(".")).toHaveLength(3);
  });
});

// ── getSession ───────────────────────────────────────────────────────────────

describe("getSession", () => {
  beforeEach(() => vi.clearAllMocks());

  it("returns null when no cookie is present", async () => {
    mockCookieStore.get.mockReturnValue(undefined);
    expect(await getSession()).toBeNull();
  });

  it("returns null for a malformed / tampered token", async () => {
    mockCookieStore.get.mockReturnValue({ value: "not.a.valid.jwt" });
    expect(await getSession()).toBeNull();
  });

  it("returns the session payload for a valid token", async () => {
    const token = await signToken(samplePayload);
    mockCookieStore.get.mockReturnValue({ value: token });

    const session = await getSession();
    expect(session).not.toBeNull();
    expect(session?.userId).toBe("user-123");
    expect(session?.email).toBe("test@example.com");
  });

  it("returns null for an expired token", async () => {
    const token = await signToken(samplePayload, -1); // already expired
    mockCookieStore.get.mockReturnValue({ value: token });

    expect(await getSession()).toBeNull();
  });

  it("reads the cookie by the correct name", async () => {
    mockCookieStore.get.mockReturnValue(undefined);
    await getSession();
    expect(mockCookieStore.get).toHaveBeenCalledWith(COOKIE_NAME);
  });
});

// ── deleteSession ────────────────────────────────────────────────────────────

describe("deleteSession", () => {
  beforeEach(() => vi.clearAllMocks());

  it("deletes the auth-token cookie", async () => {
    await deleteSession();
    expect(mockCookieStore.delete).toHaveBeenCalledOnce();
    expect(mockCookieStore.delete).toHaveBeenCalledWith(COOKIE_NAME);
  });
});

// ── verifySession ────────────────────────────────────────────────────────────

describe("verifySession", () => {
  const makeRequest = (cookie?: string) =>
    new NextRequest("http://localhost/api/test", {
      headers: cookie ? { cookie } : {},
    });

  it("returns null when the request carries no cookie", async () => {
    expect(await verifySession(makeRequest())).toBeNull();
  });

  it("returns null for a malformed token in the request", async () => {
    const req = makeRequest(`${COOKIE_NAME}=bad.token.value`);
    expect(await verifySession(req)).toBeNull();
  });

  it("returns the session payload for a valid token in the request", async () => {
    const token = await signToken(samplePayload);
    const req = makeRequest(`${COOKIE_NAME}=${token}`);

    const session = await verifySession(req);
    expect(session).not.toBeNull();
    expect(session?.userId).toBe("user-123");
    expect(session?.email).toBe("test@example.com");
  });

  it("returns null for an expired token in the request", async () => {
    const token = await signToken(samplePayload, -1);
    const req = makeRequest(`${COOKIE_NAME}=${token}`);

    expect(await verifySession(req)).toBeNull();
  });

  it("returns null when a different cookie is present but not auth-token", async () => {
    const req = makeRequest("session_id=abc123");
    expect(await verifySession(req)).toBeNull();
  });
});
