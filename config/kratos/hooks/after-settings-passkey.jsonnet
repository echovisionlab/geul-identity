// after-settings-passkey.jsonnet
// Shared by the pre-persist policy hook and post-persist completion hook.
// Kratos keeps session.identity as the pre-mutation snapshot while identity is
// the proposed/final snapshot for the current settings mutation.
function(ctx) {
  identity_id: ctx.identity.id,
  flow_id: if std.objectHas(ctx, 'flow') && std.objectHas(ctx.flow, 'id') then ctx.flow.id else '',
  flow_type: if std.objectHas(ctx, 'flow') && std.objectHas(ctx.flow, 'type') then ctx.flow.type else 'unknown',
  credentials_present: std.objectHas(ctx.identity, 'credentials'),
  credentials: if std.objectHas(ctx.identity, 'credentials') then ctx.identity.credentials else {},
  previous_credentials_present:
    std.objectHas(ctx, 'session') &&
    std.objectHas(ctx.session, 'identity') &&
    std.objectHas(ctx.session.identity, 'credentials'),
  previous_credentials:
    if std.objectHas(ctx, 'session') &&
       std.objectHas(ctx.session, 'identity') &&
       std.objectHas(ctx.session.identity, 'credentials')
    then ctx.session.identity.credentials
    else {},
}
