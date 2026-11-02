const serverless = require("serverless-http");
const app = require("../../server");
const handler = serverless(app);

exports.handler = async (event, context) => {
  // Netlify's rewrite can expose the function path; map it back to the Express API route.
  if (event.path && event.path.startsWith("/.netlify/functions/api")) {
    event.path = event.path.replace(/^\/.netlify\/functions\/api/, "/api") || "/api";
  }
  return handler(event, context);
};
