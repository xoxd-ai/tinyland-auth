import { describe, expect, it, vi } from "vitest";
import {
  createFixedTenantStorageAdapter,
  resolveAuthTenantId,
  type TenantScopedStorage,
} from "../src/storage/fixedTenant.js";
import { createFirstUserBootstrapReceipt } from "../src/storage/firstUserBootstrap.js";
import type { AdminUser } from "../src/types/index.js";
import { makeClaim, makeFinalization } from "./storage-conformance.js";

const TENANT = "12345678-1234-4123-8123-123456789abc";
const OTHER_TENANT = "87654321-4321-4321-8321-cba987654321";

function makeStub(): TenantScopedStorage {
  const claims = new Map<string, ReturnType<typeof makeClaim>>();
  const receipts = new Map<
    string,
    ReturnType<typeof createFirstUserBootstrapReceipt>
  >();
  return {
    init: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    claimFirstUserBootstrap: vi.fn().mockImplementation(async (tenantId, claim) => {
      claims.set(tenantId, claim);
      return claim;
    }),
    finalizeFirstUserBootstrap: vi.fn().mockImplementation(async (tenantId, finalization) => {
      const claim = claims.get(tenantId);
      if (!claim) throw new Error("missing synthetic claim");
      const receipt = createFirstUserBootstrapReceipt(claim, finalization);
      receipts.set(tenantId, receipt);
      return receipt;
    }),
    getFirstUserBootstrapReceipt: vi.fn().mockImplementation(async (tenantId) =>
      receipts.get(tenantId) ?? null),
    getUser: vi.fn().mockResolvedValue(null),
    getUserByHandle: vi.fn().mockResolvedValue(null),
    getUserByEmail: vi.fn().mockResolvedValue(null),
    getAllUsers: vi.fn().mockResolvedValue([]),
    createUser: vi.fn().mockImplementation(async (_t, u) => ({
      id: "u1",
      tenantId: _t,
      ...u,
    } as AdminUser)),
    updateUser: vi.fn().mockResolvedValue({} as AdminUser),
    deleteUser: vi.fn().mockResolvedValue(true),
    hasUsers: vi.fn().mockResolvedValue(false),
    getSession: vi.fn().mockResolvedValue(null),
    getSessionsByUser: vi.fn().mockResolvedValue([]),
    getAllSessions: vi.fn().mockResolvedValue([]),
    createSession: vi.fn().mockResolvedValue({} as never),
    updateSession: vi.fn().mockResolvedValue({} as never),
    deleteSession: vi.fn().mockResolvedValue(true),
    deleteUserSessions: vi.fn().mockResolvedValue(0),
    cleanupExpiredSessions: vi.fn().mockResolvedValue(0),
    getTOTPSecret: vi.fn().mockResolvedValue(null),
    saveTOTPSecret: vi.fn().mockResolvedValue(undefined),
    deleteTOTPSecret: vi.fn().mockResolvedValue(true),
    getBackupCodes: vi.fn().mockResolvedValue(null),
    saveBackupCodes: vi.fn().mockResolvedValue(undefined),
    deleteBackupCodes: vi.fn().mockResolvedValue(true),
    getInvitation: vi.fn().mockResolvedValue(null),
    getInvitationById: vi.fn().mockResolvedValue(null),
    getAllInvitations: vi.fn().mockResolvedValue([]),
    getPendingInvitations: vi.fn().mockResolvedValue([]),
    createInvitation: vi.fn().mockResolvedValue({} as never),
    updateInvitation: vi.fn().mockResolvedValue({} as never),
    deleteInvitation: vi.fn().mockResolvedValue(true),
    cleanupExpiredInvitations: vi.fn().mockResolvedValue(0),
    logAuditEvent: vi.fn().mockResolvedValue({} as never),
    getAuditEvents: vi.fn().mockResolvedValue([]),
    getRecentAuditEvents: vi.fn().mockResolvedValue([]),
  };
}

describe("resolveAuthTenantId", () => {
  it("returns the tenant from the first non-empty value", () => {
    const result = resolveAuthTenantId({
      ELDERS_AUTH_TENANT_ID: TENANT,
      AUTH_TENANT_ID: undefined,
    });
    expect(result).toBe(TENANT);
  });

  it("falls back to subsequent keys when earlier ones are empty", () => {
    const result = resolveAuthTenantId({
      FIRST: undefined,
      SECOND: TENANT,
    });
    expect(result).toBe(TENANT);
  });

  it("lowercases the tenant id", () => {
    const upper = TENANT.toUpperCase();
    expect(resolveAuthTenantId({ A: upper })).toBe(TENANT);
  });

  it("throws when no value is set", () => {
    expect(() =>
      resolveAuthTenantId({ A: undefined, B: undefined }),
    ).toThrowError(/required/);
  });

  it("throws when the tenant id is not a UUID", () => {
    expect(() => resolveAuthTenantId({ A: "not-a-uuid" })).toThrowError(/UUID/);
  });
});

describe("createFixedTenantStorageAdapter", () => {
  it("rejects non-UUID tenant ids", () => {
    expect(() =>
      createFixedTenantStorageAdapter("not-a-uuid", makeStub()),
    ).toThrowError(/UUID/);
  });

  it("normalizes uppercase tenant ids to lowercase", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(
      TENANT.toUpperCase(),
      stub,
    );
    await adapter.getUser("u1");
    expect(stub.getUser).toHaveBeenCalledWith(TENANT, "u1");
  });

  it("forwards getUser with the fixed tenant id", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.getUser("u1");
    expect(stub.getUser).toHaveBeenCalledWith(TENANT, "u1");
  });

  it("forwards getUserByHandle", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.getUserByHandle("alice");
    expect(stub.getUserByHandle).toHaveBeenCalledWith(TENANT, "alice");
  });

  it("forwards createUser without leaking IStorageAdapter shape", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    const user = {
      handle: "alice",
      email: "alice@example.com",
      passwordHash: "x",
      role: "admin",
      isActive: true,
      needsOnboarding: false,
      onboardingStep: 0,
    } as unknown as Omit<AdminUser, "id">;
    await adapter.createUser(user);
    expect(stub.createUser).toHaveBeenCalledWith(TENANT, user);
  });

  it("forwards createSession with metadata", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    const meta = { ipAddress: "127.0.0.1", userAgent: "test" } as never;
    await adapter.createSession("u1", { id: "u1" } as Partial<AdminUser>, meta);
    expect(stub.createSession).toHaveBeenCalledWith(
      TENANT,
      "u1",
      { id: "u1" },
      meta,
    );
  });

  it("forwards init/close to underlying storage", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.init();
    await adapter.close();
    expect(stub.init).toHaveBeenCalled();
    expect(stub.close).toHaveBeenCalled();
  });

  it("forwards audit operations with tenant id", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.getRecentAuditEvents(50);
    expect(stub.getRecentAuditEvents).toHaveBeenCalledWith(TENANT, 50);
  });

  it("forwards TOTP and backup code operations", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.getTOTPSecret("alice");
    await adapter.deleteBackupCodes("u1");
    expect(stub.getTOTPSecret).toHaveBeenCalledWith(TENANT, "alice");
    expect(stub.deleteBackupCodes).toHaveBeenCalledWith(TENANT, "u1");
  });

  it("forwards normalized bootstrap tenants in arguments and payloads", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    const claim = makeClaim({ tenantId: TENANT.toUpperCase() });
    const finalization = makeFinalization(claim);
    (finalization.user as AdminUser & { tenantId?: string }).tenantId =
      TENANT.toUpperCase();

    await adapter.claimFirstUserBootstrap(claim);
    await adapter.finalizeFirstUserBootstrap(finalization);
    await adapter.getFirstUserBootstrapReceipt(TENANT.toUpperCase());

    expect(stub.claimFirstUserBootstrap).toHaveBeenCalledWith(
      TENANT,
      expect.objectContaining({ tenantId: TENANT }),
    );
    expect(stub.finalizeFirstUserBootstrap).toHaveBeenCalledWith(
      TENANT,
      expect.objectContaining({
        tenantId: TENANT,
        user: expect.objectContaining({ tenantId: TENANT }),
      }),
    );
    expect(stub.getFirstUserBootstrapReceipt).toHaveBeenCalledWith(TENANT);
  });

  it("accepts claimedAt at 600000 ms and rejects 600001 ms before forwarding", async () => {
    const now = Date.parse("2026-07-14T12:00:00.000Z");
    vi.useFakeTimers();
    try {
      vi.setSystemTime(now);
      const stub = makeStub();
      const adapter = createFixedTenantStorageAdapter(TENANT, stub);
      const boundary = makeClaim({
        claimedAt: new Date(now - 600_000).toISOString(),
      });
      await expect(adapter.claimFirstUserBootstrap(boundary)).resolves.toEqual(
        boundary,
      );

      vi.mocked(stub.claimFirstUserBootstrap).mockClear();
      const expired = makeClaim({
        attemptId: "expired-attempt",
        claimedAt: new Date(now - 600_001).toISOString(),
      });
      expect(() => adapter.claimFirstUserBootstrap(expired)).toThrow(
        /active claim window/i,
      );
      expect(stub.claimFirstUserBootstrap).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects malformed, wrong-tenant, and wrong-claim adapter returns", async () => {
    const claim = makeClaim();
    const returnedClaims: unknown[] = [
      {},
      { ...claim, tenantId: OTHER_TENANT },
      { ...claim, attemptId: "different-attempt" },
      {
        ...claim,
        claimedAt: new Date(Date.parse(claim.claimedAt) + 1).toISOString(),
      },
    ];

    for (const returned of returnedClaims) {
      const stub = makeStub();
      vi.mocked(stub.claimFirstUserBootstrap).mockResolvedValue(returned as never);
      const adapter = createFixedTenantStorageAdapter(TENANT, stub);
      await expect(adapter.claimFirstUserBootstrap(claim)).rejects.toThrow();
    }
  });

  it("rejects malformed or mismatched finalization receipts from the backend", async () => {
    const claim = makeClaim();
    const finalization = makeFinalization(claim);
    const validReceipt = createFirstUserBootstrapReceipt(claim, finalization);
    const returnedReceipts: unknown[] = [
      {},
      { ...validReceipt, tenantId: OTHER_TENANT },
      { ...validReceipt, claimedAt: "2000-01-01T00:00:00.000Z" },
      { ...validReceipt, materialDigest: "0".repeat(64) },
    ];

    for (const returned of returnedReceipts) {
      const stub = makeStub();
      const adapter = createFixedTenantStorageAdapter(TENANT, stub);
      await adapter.claimFirstUserBootstrap(claim);
      vi.mocked(stub.finalizeFirstUserBootstrap).mockResolvedValue(returned as never);
      await expect(adapter.finalizeFirstUserBootstrap(finalization)).rejects.toThrow();
    }
  });

  it("rejects a forged claim timestamp before forwarding finalization", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    const claim = makeClaim();
    const finalization = makeFinalization(claim);
    finalization.user.createdAt = "2000-01-01T00:00:00.000Z";
    vi.mocked(stub.finalizeFirstUserBootstrap).mockClear();

    expect(() => adapter.finalizeFirstUserBootstrap(finalization)).toThrow(
      /claim lifetime/i,
    );
    expect(stub.finalizeFirstUserBootstrap).not.toHaveBeenCalled();
  });

  it("rejects wrong-tenant and forged-time stored receipts", async () => {
    const claim = makeClaim();
    const finalization = makeFinalization(claim);
    const receipt = createFirstUserBootstrapReceipt(claim, finalization);
    for (const returned of [
      { ...receipt, tenantId: OTHER_TENANT },
      { ...receipt, claimedAt: "2000-01-01T00:00:00.000Z" },
    ]) {
      const stub = makeStub();
      const adapter = createFixedTenantStorageAdapter(TENANT, stub);
      vi.mocked(stub.getFirstUserBootstrapReceipt).mockResolvedValue(returned);
      await expect(adapter.getFirstUserBootstrapReceipt(TENANT)).rejects.toThrow();
    }
  });

  it("rejects bootstrap material for a different tenant", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    const claim = makeClaim();
    const finalization = makeFinalization(claim);
    (finalization.user as AdminUser & { tenantId?: string }).tenantId =
      OTHER_TENANT;

    expect(() => adapter.finalizeFirstUserBootstrap(finalization)).toThrow(
      /does not match fixed tenant/,
    );
    expect(stub.finalizeFirstUserBootstrap).not.toHaveBeenCalled();
    expect(() =>
      adapter.getFirstUserBootstrapReceipt(
        OTHER_TENANT,
      ),
    ).toThrow(/does not match fixed tenant/);
  });
});
