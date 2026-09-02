// Kratos HTTP Courier - Email Request Template
// This transforms Kratos courier payloads to our Go API format.
// NOTE: Connect RPC uses camelCase for JSON field names.
function(ctx)
local has = function(obj, key) std.type(obj) == 'object' && std.objectHas(obj, key);
local templateData = if has(ctx, 'template_data') then ctx.template_data else {};
local templateType = if has(ctx, 'template_type') && std.type(ctx.template_type) == 'string' then ctx.template_type else '';
local supportedTemplateTypes = [
  'login_code_valid',
  'registration_code_valid',
  'verification_code_valid',
];
if !std.member(supportedTemplateTypes, templateType) then
  error 'unsupported Kratos courier template selector'
else
{
  recipient: ctx.recipient,
  templateType: templateType,
  templateData: {
    [if has(templateData, 'to') then 'to']: templateData.to,
    [if has(templateData, 'verification_code') then 'verification_code']: templateData.verification_code,
    [if has(templateData, 'verification_url') then 'verification_url']: templateData.verification_url,
    [if has(templateData, 'login_code') then 'login_code']: templateData.login_code,
    [if has(templateData, 'registration_code') then 'registration_code']: templateData.registration_code,
    [if has(templateData, 'request_url') then 'request_url']: templateData.request_url,
    [if has(templateData, 'expires_in_minutes') then 'expires_in_minutes']: templateData.expires_in_minutes,
    [if has(templateData, 'identity') then 'identity']: templateData.identity,
    [if has(templateData, 'traits') then 'traits']: templateData.traits,
    [if has(templateData, 'transient_payload') then 'transient_payload']: templateData.transient_payload,
  },
}
