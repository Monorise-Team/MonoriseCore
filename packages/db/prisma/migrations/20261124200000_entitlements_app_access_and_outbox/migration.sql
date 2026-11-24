-- CreateEnum
CREATE TYPE "EntitlementSourceType" AS ENUM ('CONTRACT', 'SUBSCRIPTION', 'TRIAL', 'MANUAL', 'OFFER', 'PACKAGE');

-- CreateEnum
CREATE TYPE "EntitlementStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'ENDED');

-- CreateEnum
CREATE TYPE "EntitlementSuspendedReason" AS ENUM ('OVERDUE');

-- CreateEnum
CREATE TYPE "AppAccessStatus" AS ENUM ('ACTIVE', 'REVOKED');

-- CreateTable
CREATE TABLE "entitlements" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "productId" UUID NOT NULL,
    "planId" UUID,
    "sourceType" "EntitlementSourceType" NOT NULL,
    "sourceId" UUID,
    "status" "EntitlementStatus" NOT NULL DEFAULT 'ACTIVE',
    "startsAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endsAt" TIMESTAMPTZ(3),
    "suspendedReason" "EntitlementSuspendedReason",
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "entitlements_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app_access" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "productId" UUID NOT NULL,
    "status" "AppAccessStatus" NOT NULL DEFAULT 'ACTIVE',
    "grantedByAccountId" UUID NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMPTZ(3),

    CONSTRAINT "app_access_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "outbox_events" (
    "id" UUID NOT NULL,
    "organizationId" UUID,
    "type" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "resourceVersion" INTEGER NOT NULL,
    "payload" JSONB NOT NULL,
    "occurredAt" TIMESTAMPTZ(3) NOT NULL,
    "publishedAt" TIMESTAMPTZ(3),

    CONSTRAINT "outbox_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "entitlements_organizationId_idx" ON "entitlements"("organizationId");

-- CreateIndex
CREATE INDEX "entitlements_organizationId_productId_idx" ON "entitlements"("organizationId", "productId");

-- CreateIndex
CREATE INDEX "entitlements_productId_idx" ON "entitlements"("productId");

-- CreateIndex
CREATE INDEX "app_access_organizationId_idx" ON "app_access"("organizationId");

-- CreateIndex
CREATE INDEX "app_access_organizationId_accountId_idx" ON "app_access"("organizationId", "accountId");

-- CreateIndex
CREATE INDEX "app_access_organizationId_productId_idx" ON "app_access"("organizationId", "productId");

-- CreateIndex
CREATE INDEX "app_access_productId_idx" ON "app_access"("productId");

-- CreateIndex
CREATE INDEX "outbox_events_organizationId_idx" ON "outbox_events"("organizationId");

-- AddForeignKey
ALTER TABLE "entitlements" ADD CONSTRAINT "entitlements_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "entitlements" ADD CONSTRAINT "entitlements_productId_fkey" FOREIGN KEY ("productId") REFERENCES "products"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "app_access" ADD CONSTRAINT "app_access_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "app_access" ADD CONSTRAINT "app_access_organizationId_accountId_fkey" FOREIGN KEY ("organizationId", "accountId") REFERENCES "accounts"("organizationId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "app_access" ADD CONSTRAINT "app_access_productId_fkey" FOREIGN KEY ("productId") REFERENCES "products"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

