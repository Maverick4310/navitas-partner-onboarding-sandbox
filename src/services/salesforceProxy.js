/**
 * salesforceProxy.js
 * --------------------------------------------------------
 * Generic forwarder to Salesforce endpoint.
 * Uses TARGET_SF_URL environment variable from Render.
 * --------------------------------------------------------
 */

const axios = require('axios');

async function forwardToSalesforce(req, res) {
  const targetUrl = process.env.TARGET_SF_URL;

  if (!targetUrl) {
    return res.status(500).json({ error: 'Missing TARGET_SF_URL environment variable.' });
  }

  try {
    const startTime = Date.now();

    const sfResponse = await axios.post(targetUrl, req.body, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 25000
    });

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`[${new Date().toISOString()}] [${process.env.MODE}] Forwarded to SF (${elapsed}s) → Status ${sfResponse.status}`);

    return res.status(sfResponse.status).send(sfResponse.data);

  } catch (error) {
    console.error(`[ERROR ${new Date().toISOString()}] Salesforce proxy failed: ${error.message}`);

    if (error.response) {
      return res.status(error.response.status).json({
        message: 'Salesforce responded with an error',
        status: error.response.status,
        data: error.response.data
      });
    } else if (error.request) {
      return res.status(504).json({ message: 'No response from Salesforce endpoint (timeout or network issue).' });
    } else {
      return res.status(500).json({ message: 'Internal proxy error.', detail: error.message });
    }
  }
}

module.exports = { forwardToSalesforce };
