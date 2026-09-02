export function assertGatewayUsesCanonicalSessionHeader(source) {
  for (const required of [
    "X-Session-Id:",
    "Extra.id",
    "regexMatch",
    "fail",
    "Cookie: ''",
    "Authorization: ''",
  ]) {
    if (!source.includes(required)) {
      throw new Error(`Oathkeeper gateway contract is missing ${required}`);
    }
  }
}
