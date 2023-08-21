const api = require("./api");
const express = require("express");
const router = express.Router();

router.get("/vulnerabilities", async (req, res) => {
  try {
    const vulnerabilities = await api.handleProwlerFile();
    console.log("GOT vulnerabilities", !!Object.keys(vulnerabilities)?.length);
    res.json(vulnerabilities);
  } catch (error) {
    console.error("Error handling vulnerabilities:", error);
    res
      .status(500)
      .json({ error: "An error occurred while processing vulnerabilities." });
  }
});
// Export the router to use it in the main app
module.exports = router;
