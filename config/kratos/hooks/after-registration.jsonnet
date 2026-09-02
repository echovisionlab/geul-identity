function(ctx)
local has = function(obj, key) std.type(obj) == 'object' && std.objectHas(obj, key);
local identity = if has(ctx, 'identity') then ctx.identity else {};
local traits = if has(identity, 'traits') then identity.traits else {};
local flow = if has(ctx, 'flow') then ctx.flow else {};
local transient = if has(flow, 'transient_payload') then flow.transient_payload else {};
{
  identity_id: if has(identity, 'id') then identity.id else '',
  email: if has(traits, 'email') then traits.email else '',
  preferred_locale: if has(transient, 'preferred_locale') then transient.preferred_locale else '',
  trigger: 'registration',
}
