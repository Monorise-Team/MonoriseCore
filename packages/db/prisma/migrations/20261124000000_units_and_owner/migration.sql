-- CreateEnum
CREATE TYPE "UnitType" AS ENUM ('BRANCH', 'DEPARTMENT', 'TEAM');

-- CreateEnum
CREATE TYPE "UnitStatus" AS ENUM ('ACTIVE', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "UnitMembershipRole" AS ENUM ('MEMBER', 'LEADER');

-- AlterTable
ALTER TABLE "organizations" ADD COLUMN     "ownerAccountId" UUID;

-- CreateTable
CREATE TABLE "organization_units" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "parentId" UUID,
    "name" TEXT NOT NULL,
    "type" "UnitType" NOT NULL,
    "status" "UnitStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "organization_units_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "unit_memberships" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "unitId" UUID NOT NULL,
    "employeeId" UUID NOT NULL,
    "role" "UnitMembershipRole" NOT NULL DEFAULT 'MEMBER',
    "joinedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "unit_memberships_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "organization_units_organizationId_idx" ON "organization_units"("organizationId");

-- CreateIndex
CREATE INDEX "organization_units_organizationId_parentId_idx" ON "organization_units"("organizationId", "parentId");

-- CreateIndex
CREATE UNIQUE INDEX "organization_units_organizationId_id_key" ON "organization_units"("organizationId", "id");

-- CreateIndex
CREATE INDEX "unit_memberships_organizationId_idx" ON "unit_memberships"("organizationId");

-- CreateIndex
CREATE INDEX "unit_memberships_organizationId_unitId_idx" ON "unit_memberships"("organizationId", "unitId");

-- CreateIndex
CREATE INDEX "unit_memberships_organizationId_employeeId_idx" ON "unit_memberships"("organizationId", "employeeId");

-- CreateIndex
CREATE UNIQUE INDEX "unit_memberships_unitId_employeeId_key" ON "unit_memberships"("unitId", "employeeId");

-- CreateIndex
CREATE UNIQUE INDEX "organizations_ownerAccountId_key" ON "organizations"("ownerAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "employees_organizationId_id_key" ON "employees"("organizationId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "accounts_organizationId_id_key" ON "accounts"("organizationId", "id");

-- AddForeignKey
ALTER TABLE "organizations" ADD CONSTRAINT "organizations_ownerAccountId_fkey" FOREIGN KEY ("ownerAccountId") REFERENCES "accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_units" ADD CONSTRAINT "organization_units_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_units" ADD CONSTRAINT "organization_units_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "organization_units"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "unit_memberships" ADD CONSTRAINT "unit_memberships_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "unit_memberships" ADD CONSTRAINT "unit_memberships_organizationId_unitId_fkey" FOREIGN KEY ("organizationId", "unitId") REFERENCES "organization_units"("organizationId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "unit_memberships" ADD CONSTRAINT "unit_memberships_organizationId_employeeId_fkey" FOREIGN KEY ("organizationId", "employeeId") REFERENCES "employees"("organizationId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Composite same-organization foreign keys for nullable references (not expressible in Prisma schema)
ALTER TABLE "organizations" ADD CONSTRAINT "organizations_id_ownerAccountId_fkey" FOREIGN KEY ("id", "ownerAccountId") REFERENCES "accounts"("organizationId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "organization_units" ADD CONSTRAINT "organization_units_organizationId_parentId_fkey" FOREIGN KEY ("organizationId", "parentId") REFERENCES "organization_units"("organizationId", "id") ON DELETE RESTRICT ON UPDATE CASCADE;
