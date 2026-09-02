// Public registration is validated before persistence. Passkeys are enrolled
// only from authenticated settings, and the verification-only pending_email
// trait is never accepted from a registration client.
function(ctx)
local has = function(obj, key) std.type(obj) == 'object' && std.objectHas(obj, key);
local identity = if has(ctx, 'identity') then ctx.identity else {};
local traits = if has(identity, 'traits') then identity.traits else {};
local flow = if has(ctx, 'flow') then ctx.flow else {};
local transient = if has(flow, 'transient_payload') then flow.transient_payload else {};
{
  flow_id: if has(flow, 'id') then flow.id else '',
  flow_type: if has(flow, 'type') then flow.type else 'unknown',
  identity_id: if has(identity, 'id') then identity.id else '',
  email: if has(traits, 'email') then traits.email else '',
  pending_email: if has(traits, 'pending_email') then traits.pending_email else '',
  method: if has(flow, 'active') then flow.active else '',
  preferred_locale: if has(transient, 'preferred_locale') then transient.preferred_locale else '',
}
