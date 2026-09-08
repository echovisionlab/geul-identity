// Project the explicit, request-local inventory supplied by the settings
// executor. Public identity/session JSON intentionally never includes secrets.
function(ctx) {
  identity_id: ctx.identity.id,
  flow_id: if std.objectHas(ctx, 'flow') && std.objectHas(ctx.flow, 'id') then ctx.flow.id else '',
  flow_type: if std.objectHas(ctx, 'flow') && std.objectHas(ctx.flow, 'type') then ctx.flow.type else 'unknown',
  credentials_present: std.objectHas(ctx, 'credential_change') && std.objectHas(ctx.credential_change, 'credentials'),
  credentials: if std.objectHas(ctx, 'credential_change') then ctx.credential_change.credentials else {},
  previous_credentials_present: std.objectHas(ctx, 'credential_change') && std.objectHas(ctx.credential_change, 'previous_credentials'),
  previous_credentials: if std.objectHas(ctx, 'credential_change') then ctx.credential_change.previous_credentials else {},
}
