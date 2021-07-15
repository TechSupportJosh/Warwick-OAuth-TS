import express from "express";
import { getAccessToken, getAuthorizationURI, getUserAttributes } from "./warwickapi";

const app = express();

app.get("/login", async (req, res) => {
  const authorizationUri = await getAuthorizationURI();

  if (!authorizationUri) return res.status(500).send("");

  res.redirect(authorizationUri);
});

app.get("/callback", async (req, res) => {
  // Attempt to get profile
  const accessToken = await getAccessToken(req.query.oauth_token?.toString() ?? "");

  if (!accessToken) return res.redirect("/");

  const attributes = await getUserAttributes(accessToken);

  res.send(attributes);
});

app.listen(8080, () => {
  console.log("Listening on port 8080...");
});
