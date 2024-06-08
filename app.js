import express from "express";
import logger from "morgan";
import cors from "cors";
import contactsRouter from "./routes/api/contacts.js";
import usersRouter from "./routes/api/users.js";
import connectToDb from "./utils/connectToDb.js";
import path from "path";

const app = express();

const formatsLogger = app.get("env") === "development" ? "dev" : "short";

connectToDb();

app.use(logger(formatsLogger));
app.use(cors());
app.use(express.json());

const __dirname = path.resolve();

app.use("/public", express.static(path.join(__dirname, "public")));
app.use("/api/contacts", contactsRouter);
app.use("/api/users", usersRouter);

app.use((req, res) => {
  res.status(404).json({ message: "Not found" });
});

app.use((err, req, res, next) => {
  res.status(500).json({ message: err.message });
});

export default app;
