import serverless from "serverless-http";
import app from "../app.js";

export const config = { api: { bodyParser: false } };
export default serverless(app);
