local claims = {
  email_verified: false,
} + std.extVar('claims');

local hasVerifiedEmail =
  std.objectHas(claims, 'email') &&
  claims.email != null &&
  claims.email != '' &&
  claims.email_verified == true;

{
  identity: {
    traits: {
      [if hasVerifiedEmail then 'email' else null]: claims.email,
    },
    verified_addresses: std.prune([
      if hasVerifiedEmail then { via: 'email', value: claims.email } else null,
    ]),
  },
}
