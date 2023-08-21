const express = require("express");
const app = express();
const port = 3000;
const api = require("./api/index");

app.use(express.static("public"));
app.use("/api", api);

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
