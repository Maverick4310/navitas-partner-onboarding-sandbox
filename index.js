/**
 * index.js
 * --------------------------------------------------------
 * Navitas Partner Onboarding Proxy (Sandbox)
 * --------------------------------------------------------
 * Purpose:
 *  - Receives partner onboarding JSON payloads
 *  - Forwards them to Salesforce Apex REST endpoint
 *  - Provides website legitimacy verification service (IP2WHOIS)
 * --------------------------------------------------------
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { forwardToSalesforce } = require('./src/services/salesforceProxy');
const { verifyWebsiteHandler } = require('./src/services/websiteVerifier');

const app = express();

// === Middleware ===
app.use(cors());
app.use(bodyParser.json({ limit: '5mb' }));

// === Health check ===
app.get('/ping', (req, res) => {
  res
    .status(200)
    .send(`Partner Onboarding Proxy is live in ${process.env.MODE || 'unknown'} mode`);
});

// === Partner Onboarding endpoint ===
app.post('/onboarding', forwardToSalesforce);

// === Website Verification endpoint (IP2WHOIS) ===
app.post('/verifyWebsite', verifyWebsiteHandler);

// === Start server ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(
    `🚀 Navitas Partner Onboarding Proxy (${process.env.MODE}) running on port ${PORT}`
  );
});
