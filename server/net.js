import { isIPv4, isIPv6 } from "node:net";

const UNKNOWN_CLIENT = "unknown-client";

function normalizedAddress(value) {
  let address = String(value ?? "").trim();
  if (address.startsWith("[") && address.endsWith("]")) {
    address = address.slice(1, -1);
  }
  const zoneIndex = address.indexOf("%");
  if (zoneIndex !== -1) address = address.slice(0, zoneIndex);
  return address;
}

function ipv6Groups(address) {
  let expanded = address.toLowerCase();
  const dottedTail = expanded.match(/(^|:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dottedTail) {
    const octets = dottedTail[2].split(".").map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    expanded = `${expanded.slice(0, dottedTail.index + dottedTail[1].length)}${high}:${low}`;
  }

  const halves = expanded.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [
    ...left,
    ...Array.from({ length: missing }, () => "0"),
    ...right,
  ].map((group) => Number.parseInt(group, 16));
  return groups.length === 8 && groups.every(Number.isInteger) ? groups : null;
}

function compressedIpv6(groups) {
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length; ) {
    if (groups[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === 0) end += 1;
    if (end - index > bestLength && end - index >= 2) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }

  const hex = groups.map((group) => group.toString(16));
  if (bestStart === -1) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
}

export function normalizeRateLimitIdentity(ip) {
  const address = normalizedAddress(ip);
  if (isIPv4(address)) return address;
  if (!isIPv6(address)) return UNKNOWN_CLIENT;

  const groups = ipv6Groups(address);
  if (!groups) return UNKNOWN_CLIENT;
  if (
    groups.slice(0, 5).every((group) => group === 0) &&
    groups[5] === 0xffff
  ) {
    return [
      groups[6] >>> 8,
      groups[6] & 0xff,
      groups[7] >>> 8,
      groups[7] & 0xff,
    ].join(".");
  }

  return `${compressedIpv6([...groups.slice(0, 4), 0, 0, 0, 0])}/64`;
}
