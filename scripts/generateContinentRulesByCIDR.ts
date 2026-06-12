import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";

const [, , dist, ...inputs] = process.argv;

if (!dist || inputs.length === 0) {
  console.error("Usage: node test.js <dist> <url-or-path> [url-or-path ...]");
  console.log("Environment variables:");
  console.log("  IPINFO_BASE_URL (optional, default: https://api.ipinfo.io/lite)");
  console.log("  IPINFO_TOKEN (required if IPINFO_BASE_URL requires authentication. This script does not check if its required or not, be careful.)");
  process.exit(1);
}

const ipinfoBaseUrl = process.env.IPINFO_BASE_URL || "https://api.ipinfo.io/lite";
const ipinfoToken = process.env.IPINFO_TOKEN;

const isUrl = (input: string) => /^https?:\/\//i.test(input);

const loadInput = async (input: string) => {
  if (!isUrl(input)) {
    return readFileSync(input, "utf8");
  }

  const response = await fetch(input);
  if (!response.ok) {
    throw new Error(`Failed to fetch ${input}: ${response.status} ${response.statusText}`);
  }

  return response.text();
};

const extractCidrs = (text: string) => {
  const cidrs = [];
  const seen = new Set();

  for (const line of text.split(/\r?\n/)) {
    const cidr = line.replace(/#.*/, "").trim().match(/(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}|[0-9a-f:]+\/\d{1,3}/i)?.[0];
    if (cidr && !seen.has(cidr)) {
      seen.add(cidr);
      cidrs.push(cidr);
    }
  }

  return cidrs;
};

const ipFromCidr = (cidr: string) => cidr.split("/")[0];

const lookupIpinfo = async (cidr: string) => {
  const ip = ipFromCidr(cidr);
  const url = new URL(`${ipinfoBaseUrl.replace(/\/$/, "")}/${ip}`);
  if (ipinfoToken) {
    url.searchParams.set("token", ipinfoToken);
  }

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to lookup ${ip}: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  if (!data.continent_code) {
    throw new Error(`Missing continent_code for ${ip}`);
  }

  return {
    cidr,
    country: String(data.country) || "Unknown",
    countryCode: String(data.country_code) || "Unknown",
    continent: String(data.continent) || "Unknown",
    continentCode: String(data.continent_code) || "Unknown",
  };
};

const sources = await Promise.all(inputs.map(loadInput));
const cidrs = extractCidrs(sources.join("\n"));
const ipinfos = [];

for (const cidr of cidrs) {
  console.debug(`lookup ${cidr}`);
  ipinfos.push(await lookupIpinfo(cidr));
}

const continentGroups: Record<string, Record<string, typeof ipinfos[0][]>> = {};
for (const ipinfo of ipinfos) {
  continentGroups[ipinfo.continentCode] ??= {};
  continentGroups[ipinfo.continentCode][ipinfo.country] ??= [];
  continentGroups[ipinfo.continentCode][ipinfo.country].push(ipinfo);
}

mkdirSync(dist, {recursive: true});

const generatedAt = new Date().toISOString();

for (const [continentCode, countryGroups] of Object.entries(continentGroups).sort(([a], [b]) => a.localeCompare(b))) {
  const ruleCount = Object.values(countryGroups).reduce((sum, items) => sum + items.length, 0);
  const continent = Object.values(countryGroups)[0][0].continent;
  const lines = [
    `# Summary: ${ruleCount} IP-CIDR rules for ${continentCode} (${continent})`,
    `# Generated at (UTC+0): ${generatedAt}`,
    `# Inputed sources: ${inputs.join(", ")}`,
    `# Data source: via ipinfo API (${ipinfoBaseUrl})`,
    "# Notes: THIS IS A GENERATED FILE, DO NOT EDIT MANUALLY. ",
    "",
  ];

  for (const [, items] of Object.entries(countryGroups).sort(([a], [b]) => a.localeCompare(b))) {
    const {country} = items[0];
    if (lines.at(-1) !== "") {
      lines.push("");
    }
    lines.push(`# ${country}`);
    lines.push(...items.map(({cidr}) => `IP-CIDR, ${cidr}, no-resolve`));
  }

  writeFileSync(path.join(dist, `${continentCode}.list`), `${lines.join("\n")}\n`);
}
