import Fastify from "fastify";
import fastifyCors from "@fastify/cors";

const fastify = Fastify({ logger: true });

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : ["http://localhost:3000"];
const USERNAME = process.env.USERNAME || "admin";
const PASSWORD = process.env.PASSWORD || "password";

await fastify.register(fastifyCors, {
  origin: allowedOrigins,
});

function basicAuth(req, reply) {
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
    return true;
  } else {
    reply.status(401).send("Invalid credentials");
    return false;
  }
}

fastify.get("/health", async (request, reply) => {
  return "Gateway is up and running";
});

fastify.get("/verify", async (request, reply) => {
  if (basicAuth(request, reply)) {
    reply.status(200).send("Authenticated");
  }
});

try {
  await fastify.listen({ port: PORT });
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
