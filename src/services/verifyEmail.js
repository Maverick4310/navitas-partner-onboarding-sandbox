// verifyEmail.js
// ------------------------------------------------------------
// Purpose:
//   - Validate an email address using EmailRep reputation API
//   - Return standardized JSON for Salesforce consumption
// ------------------------------------------------------------
// Dependencies:
//   - Environment variable: EMAILREP_API_KEY
// ------------------------------------------------------------
// Version: 1.0 (2025-10-14)
// ------------------------------------------------------------

import fetch from 'node-fetch';
module.exports = { verifyEmailHandler };


export async function verifyEmail(req, res) {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Missing email parameter' });
    }

    // === 1. Call EmailRep API ===
    const response = await fetch(`https://emailrep.io/${encodeURIComponent(email)}`, {
      method: 'GET',
      headers: {
        'Key': process.env.EMAILREP_API_KEY,
        'User-Agent': 'navitas-partner-onboarding'
      }
    });

    if (!response.ok) {
      const text = await response.text();
      return res.status(response.status).json({ error: `EmailRep API error: ${text}` });
    }

    const data = await response.json();

    // === 2. Format Output JSON ===
    const result = {
      email,
      domain: data.details?.domain || null,
      isValid: !data.suspicious,
      status: data.reputation || 'unknown',
      riskLevel: data.reputation || 'unknown',
      spamScore: data.risk || 0,
      summary: [
        `Reputation: ${data.reputation}`,
        `Suspicious: ${data.suspicious}`,
        `Days Since Domain Created: ${data.details?.days_since_domain_creation ?? 'N/A'}`,
        `Malicious Activity: ${data.details?.malicious_activity || 'none'}`,
        `Disposable: ${data.details?.disposable || false}`,
        `Free Provider: ${data.details?.free_provider || false}`
      ]
    };

    // === 3. Send JSON to Salesforce ===
    res.status(200).json(result);

  } catch (err) {
    console.error('verifyEmail error:', err);
    res.status(500).json({
      error: err.message || 'Unknown error',
      stack: err.stack
    });
  }
}
