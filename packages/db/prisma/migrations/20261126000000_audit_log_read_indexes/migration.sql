-- Indeksy złożone do stronicowanego odczytu i filtrowania dziennika zdarzeń firmy (MonoriseCore#63, ADR-0039).

-- DropIndex
DROP INDEX "public"."audit_log_organizationId_createdAt_idx";

-- CreateIndex
CREATE INDEX "audit_log_org_created_id_idx"
  ON "public"."audit_log"("organizationId", "createdAt" DESC, "id" DESC);

-- CreateIndex
CREATE INDEX "audit_log_org_actor_created_id_idx"
  ON "public"."audit_log"("organizationId", "actorAccountId", "createdAt" DESC, "id" DESC);

-- CreateIndex
CREATE INDEX "audit_log_org_action_created_id_idx"
  ON "public"."audit_log"("organizationId", "action", "createdAt" DESC, "id" DESC);

-- CreateIndex
CREATE INDEX "audit_log_org_resource_created_id_idx"
  ON "public"."audit_log"("organizationId", "resourceType", "resourceId", "createdAt" DESC, "id" DESC);
