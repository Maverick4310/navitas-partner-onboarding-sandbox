/**
 * emailVerifier.js
 * ------------------------------------------------------------
 * Purpose:
 *   - Validate an email address using the EmailRep reputation API
 *   - Return standardized JSON for Salesforce consumption
 * ------------------------------------------------------------
 * Dependencies:
 *   - Environment variable: EMAILREP_API_KEY
 * ------------------------------------------------------------
 * Version: 1.1 (2025-10-14)
 * Change Log:
 *   - Added fallback for missing domain (parse from email)
 *   - Reversed risk scale so 'high reputation' = 'low risk'
 * ------------------------------------------------------------
 */

const fetch = require('node-fetch');

const verifyEmailHandler = async (req, res) => {
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

    // === 2. Parse domain manually if not returned by EmailRep ===
    const parsedDomain = email.split('@')[1] || null;

    // === 3. Reverse EmailRep's reputation-to-risk mapping ===
    let riskLevel = 'unknown';
    switch ((data.reputation || '').toLowerCase()) {
      case 'high':
        riskLevel = 'low'; // trusted
        break;
      case 'medium':
        riskLevel = 'medium'; // neutral
        break;
      case 'low':
      case 'malicious':
      case 'very low':
        riskLevel = 'high'; // untrustworthy
        break;
      default:
        riskLevel = 'unknown';
    }

    // === 4. Build standardized result JSON ===
    const result = {
      email,
      domain: parsedDomain || data.details?.domain || null,
      isValid: !data.suspicious,
      status: data.reputation || 'unknown',
      riskLevel,
      spamScore: data.risk || 0,
      summary: [
        `Reputation: ${data.reputation}`,
        `Mapped Risk Level: ${riskLevel}`,
        `Suspicious: ${data.suspicious}`,
        `Days Since Domain Created: ${data.details?.days_since_domain_creation ?? 'N/A'}`,
        `Malicious Activity: ${data.details?.malicious_activity || 'none'}`,
        `Disposable: ${data.details?.disposable || false}`,
        `Free Provider: ${data.details?.free_provider || false}`
      ]
    };

    // === 5. Return JSON response ===
    res.status(200).json(result);

  } catch (err) {
    console.error('verifyEmail error:', err);
    res.status(500).json({
      error: err.message || 'Unknown error',
      stack: err.stack
    });
  }
};

module.exports = { verifyEmailHandler };
