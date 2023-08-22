const api = require("./api");
const express = require("express");
const router = express.Router();

router.get("/vulnerabilities", async (req, res) => {
  try {
    const { severity } = req.query;
    const vulnerabilities = await api.getResourcesVulnerabilities(severity);
    res.header("Access-Control-Allow-Origin", "*");
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
