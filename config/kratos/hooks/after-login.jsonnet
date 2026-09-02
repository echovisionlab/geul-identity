function(ctx)
local has = function(obj, key) std.type(obj) == 'object' && std.objectHas(obj, key);
local identity = if has(ctx, 'identity') then ctx.identity else {};
local traits = if has(identity, 'traits') then identity.traits else {};
{
  identity_id: if has(identity, 'id') then identity.id else '',
  email: if has(traits, 'email') then traits.email else '',
  trigger: 'login',
}
