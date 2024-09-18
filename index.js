// src/index.js
class BadRequestException extends Error {
  constructor(reason) {
    super(reason);
    this.status = 400;
    this.statusText = "Bad Request";
  }
}

class CloudflareApiException extends Error {
  constructor(reason) {
    super(reason);
    this.status = 500;
    this.statusText = "Internal Server Error";
  }
}

class Cloudflare {
  constructor(options) {
    this.cloudflare_url = "https://api.cloudflare.com/client/v4";
    this.token = options.token;
  }

  async findZone(name) {
    console.log("Finding zone for name:", name); // Log zone name search

    const response = await this._fetchWithToken(`zones?name=${name}`);
    const body = await response.json();
    
    console.log("Find zone response:", body); // Log response body

    if (!body.success || body.result.length === 0) {
      throw new CloudflareApiException(`Failed to find zone '${name}'`);
    }
    return body.result[0];
  }

  async findRecord(zone, name, isIPV4 = true) {
    console.log("Finding record for zone:", zone, "name:", name); // Log zone and name search

    const rrType = isIPV4 ? "A" : "AAAA";
    const response = await this._fetchWithToken(`zones/${zone.id}/dns_records?name=${name}`);
    const body = await response.json();
    
    console.log("Find record response:", body); // Log response body

    if (!body.success || body.result.length === 0) {
      throw new CloudflareApiException(`Failed to find DNS record '${name}'`);
    }
    return body.result?.filter((rr) => rr.type === rrType)[0];
  }

  async updateRecord(record, value) {
    console.log("Updating record with value:", value); // Log the value to update

    record.content = value;
    const response = await this._fetchWithToken(
      `zones/${record.zone_id}/dns_records/${record.id}`,
      {
        method: "PUT",
        body: JSON.stringify(record)
      }
    );
    const body = await response.json();

    console.log("Update record response:", body); // Log update response

    if (!body.success) {
      throw new CloudflareApiException("Failed to update DNS record");
    }
    return body.result[0];
  }

  async _fetchWithToken(endpoint, options = {}) {
    const url = `${this.cloudflare_url}/${endpoint}`;
    options.headers = {
      ...options.headers,
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.token}`
    };
    return fetch(url, options);
  }
}

function requireHttps(request) {
  const { protocol } = new URL(request.url);
  const forwardedProtocol = request.headers.get("x-forwarded-proto");
  if (protocol !== "https:" || forwardedProtocol !== "https") {
    throw new BadRequestException("Please use a HTTPS connection.");
  }
}

function parseBasicAuth(request) {
  const authorization = request.headers.get("Authorization");
  if (!authorization) return {};
  const [, data] = authorization.split(" ");
  const decoded = atob(data);
  const index = decoded.indexOf(":");
  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    throw new BadRequestException("Invalid authorization value.");
  }
  return {
    username: decoded.substring(0, index),
    password: decoded.substring(index + 1)
  };
}

async function handleRequest(request) {
  console.log('Request URL:', request.url);
  console.log('Request headers:', [...request.headers.entries()]);

  requireHttps(request);
  const { pathname } = new URL(request.url);
  if (pathname === "/favicon.ico" || pathname === "/robots.txt") {
    return new Response(null, { status: 204 });
  }
  if (!pathname.endsWith("/update")) {
    return new Response("Not Found.", { status: 404 });
  }
  if (!request.headers.has("Authorization") && !request.url.includes("token=")) {
    return new Response("Not Found.", { status: 404 });
  }
  const { username, password } = parseBasicAuth(request);
  const url = new URL(request.url);
  const params = url.searchParams;
  const token = password || params.get("token");
  const hostnameParam = params.get("hostname") || params.get("host") || params.get("domains");
  const hostnames = hostnameParam?.split(",");
  const ipsParam = params.get("ips") || params.get("ip") || params.get("myip") || request.headers.get("Cf-Connecting-Ip");
  const ips = ipsParam?.split(",");
  if (!hostnames || hostnames.length === 0 || !ips || ips.length === 0) {
    throw new BadRequestException("You must specify both hostname(s) and IP address(es)");
  }
  for (const ip of ips) {
    await informAPI(hostnames, ip.trim(), username, token);
  }
  return new Response("good", {
    status: 200,
    headers: {
      "Content-Type": "text/plain;charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

async function informAPI(hostnames, ip, name, token) {
  const cloudflare = new Cloudflare({ token });
  const isIPV4 = ip.includes(".");
  
  console.log("InformAPI called with:", { hostnames, ip, name, token }); // Log input

  const zones = new Map();
  for (const hostname of hostnames) {
    const domainName = name && hostname.endsWith(name) ? name : hostname.replace(/.*?([^.]+\.[^.]+)$/, "$1");
    
    console.log("Looking up zone for domain:", domainName); // Log domain name
    
    if (!zones.has(domainName)) {
      const zone = await cloudflare.findZone(domainName);
      console.log("Zone found:", zone); // Log zone details
      zones.set(domainName, zone);
    }
    
    const zone = zones.get(domainName);
    const record = await cloudflare.findRecord(zone, hostname, isIPV4);
    
    console.log("DNS Record found:", record); // Log DNS record details
    
    await cloudflare.updateRecord(record, ip);
    console.log("DNS Record updated:", record); // Log the updated DNS record
  }
}

const src_default = {
  async fetch(request, env, ctx) {
    return handleRequest(request).catch((err) => {
      console.error(err.constructor.name, err);
      const message = err.reason || err.stack || "Unknown Error";
      return new Response(message, {
        status: err.status || 500,
        statusText: err.statusText || null,
        headers: {
          "Content-Type": "text/plain;charset=UTF-8",
          "Cache-Control": "no-store",
          "Content-Length": message.length
        }
      });
    });
  }
};

export default src_default;
//# sourceMappingURL=index.js.map
