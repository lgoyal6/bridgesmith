/** Local server for the same handler shipped as a serverless function. */
import express from "express";
import handler from "../api/run.js";
const app = express();
app.all("/api/run", handler);
app.use(express.static("docs/demo"));
app.listen(4318, "127.0.0.1", () => console.log("Connector lab ready at http://127.0.0.1:4318"));
