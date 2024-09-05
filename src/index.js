import Fastify from "fastify";
import fastifyCors from "@fastify/cors";

const fastify = Fastify({ logger: true });

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : ["http://localhost:3000"];
const USERNAME = process.env.USERNAME || "admin";
const PASSWORD = process.env.PASSWORD || "password";
const MAX_FAILED_ATTEMPTS = process.env.PORT
  ? parseInt(process.env.MAX_FAILED_ATTEMPTS, 10)
  : 3;
const BAN_DURATION_HOURS = process.env.PORT
  ? parseInt(process.env.BAN_DURATION_HOURS * 60 * 60 * 1000, 60 * 60 * 1000)
  : 1;

await fastify.register(fastifyCors, {
  origin: ALLOWED_ORIGINS,
});

const failedLoginAttempts = {};
const bannedIPs = {};

function isIPBanned(ip) {
  if (bannedIPs[ip]) {
    const banExpiration = bannedIPs[ip];
    if (Date.now() < banExpiration) {
      return true;
    } else {
      delete bannedIPs[ip];
      return false;
    }
  }
  return false;
}

function trackFailedAttempt(ip) {
  if (!failedLoginAttempts[ip]) {
    failedLoginAttempts[ip] = { count: 1, lastAttempt: Date.now() };
  } else {
    failedLoginAttempts[ip].count += 1;
    failedLoginAttempts[ip].lastAttempt = Date.now();
  }

  if (failedLoginAttempts[ip].count >= MAX_FAILED_ATTEMPTS) {
    bannedIPs[ip] = Date.now() + BAN_DURATION_HOURS;
    delete failedLoginAttempts[ip];
  }
}

function resetFailedAttempts(ip) {
  if (failedLoginAttempts[ip]) {
    delete failedLoginAttempts[ip];
  }
}

function validateOrigin(req, reply) {
  const origin = req.headers["origin"];

  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    reply.status(403).send("Origin not allowed");
    return false;
  }

  return true;
}

function basicAuth(req, reply) {
  const ip = req.ip || req.connection.remoteAddress;

  if (isIPBanned(ip)) {
    reply.status(403).send("Your IP is banned. Try again later.");
    return false;
  }

  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    reply
      .status(401)
      .header("WWW-Authenticate", 'Basic realm="Restricted Area"')
      .send("Authorization required");
    return false;
  }

  const base64Credentials = authHeader.split(" ")[1];
  const credentials = Buffer.from(base64Credentials, "base64").toString(
    "ascii"
  );
  const [username, password] = credentials.split(":");

  if (username === USERNAME && password === PASSWORD) {
    resetFailedAttempts(ip);
    return true;
  } else {
    trackFailedAttempt(ip);
    reply.status(401).send("Invalid credentials");
    return false;
  }
}

fastify.get("/health", async (request, reply) => {
  return "Gateway is up and running";
});

fastify.get("/verify", async (request, reply) => {
  if (!validateOrigin(request, reply)) {
    return;
  }
  if (!basicAuth(request, reply)) {
    return;
  }
  reply.status(200).send("Authenticated");
});

try {
  await fastify.listen({ host: "0.0.0.0", port: PORT });
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
