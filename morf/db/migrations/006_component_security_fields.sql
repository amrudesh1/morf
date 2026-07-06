-- Add lossless component security fields so services, broadcast_receivers, and
-- content_providers round-trip their manifest data the same way activities do
-- (which already has intent_filters). Mirrors models.Service / models.BroadcastReceiver /
-- models.ContentProvider gorm tags. Idempotent: uses IF NOT EXISTS so the
-- migration is safe to re-run.

-- services.intent_filters
ALTER TABLE services
    ADD COLUMN intent_filters JSON;

-- broadcast_receivers.intent_filters
ALTER TABLE broadcast_receivers
    ADD COLUMN intent_filters JSON;

-- content_providers.intent_filters / authorities / grant_uri_permissions
ALTER TABLE content_providers
    ADD COLUMN intent_filters JSON;

ALTER TABLE content_providers
    ADD COLUMN authorities JSON;

ALTER TABLE content_providers
    ADD COLUMN grant_uri_permissions BOOLEAN NOT NULL DEFAULT FALSE;
