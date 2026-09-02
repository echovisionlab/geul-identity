// Completes a staged canonical-email change only after Kratos verifies the
// exact pending address. The backend treats this payload as a lifecycle hint
// and re-reads the committed Identity before applying it.
function(ctx)
local has = function(obj, key) std.type(obj) == 'object' && std.objectHas(obj, key);
local identity = if has(ctx, 'identity') then ctx.identity else {};
local traits = if has(identity, 'traits') then identity.traits else {};
{
  flow_id: if has(ctx, 'flow') && has(ctx.flow, 'id') then ctx.flow.id else '',
  identity_id: if has(identity, 'id') then identity.id else '',
  email: if has(traits, 'email') then traits.email else '',
  pending_email: if has(traits, 'pending_email') then traits.pending_email else '',
}
