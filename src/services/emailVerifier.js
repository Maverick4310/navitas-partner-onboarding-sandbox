/**
 * emailVerifier.js
 * ------------------------------------------------------------
 * Purpose:
 *   - Validate an email address using the EmailRep reputation API
 *   - Enrich with domain WHOIS data from IP2WHOIS
 *   - Return standardized JSON for Salesforce consumption
 * ------------------------------------------------------------
 * Dependencies:
 *   - Environment variables:
 *       EMAILREP_API_KEY   (EmailRep key)
 *       IP2WHOIS_API_KEY   (IP2WHOIS key)
 * ------------------------------------------------------------
 * Version: 2.0 (2025-10-14)
 * Change Log:
 *   - Added WHOIS enrichment via IP2WHOIS
 *   - Adjusted risk scoring based on domain age and status
 *   - Retains backward compatibility with Apex
 * ------------------------------------------------------------
 */

const fetch = require('node-fetch');

const verifyEmailHandler = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Missing email parameter' });
    }

    // === 1. Parse domain from email ===
    const parsedDomain = email.split('@')[1] || null;

    if (!parsedDomain) {
      return res.status(400).json({ error: 'Unable to extract domain from email' });
    }

    // === 2. Call EmailRep API ===
    const emailRepRes = await fetch(`https://emailrep.io/${encodeURIComponent(email)}`, {
      method: 'GET',
      headers: {
        'Key': process.env.EMAILREP_API_KEY,
        'User-Agent': 'navitas-partner-onboarding'
      }
    });

    if (!emailRepRes.ok) {
      const text = await emailRepRes.text();
      return res.status(emailRepRes.status).json({ error: `EmailRep API error: ${text}` });
    }

    const emailData = await emailRepRes.json();

    // === 3. Reverse EmailRep reputation scale ===
    let riskLevel = 'unknown';
    switch ((emailData.reputation || '').toLowerCase()) {
      case 'high':
        riskLevel = 'low';
        break;
      case 'medium':
        riskLevel = 'medium';
        break;
      case 'low':
      case 'malicious':
      case 'very low':
        riskLevel = 'high';
        break;
      default:
        riskLevel = 'unknown';
    }

    // === 4. Fetch WHOIS data from IP2WHOIS ===
    let whoisData = null;
    try {
      const whoisUrl = `https://api.ip2whois.com/v2?key=${process.env.IP2WHOIS_KEY}&domain=${parsedDomain}`;
      const whoisRes = await fetch(whoisUrl);
      if (whoisRes.ok) {
        whoisData = await whoisRes.json();
      }
    } catch (err) {
      console.warn(`WHOIS lookup failed for ${parsedDomain}: ${err.message}`);
    }

    // === 5. Adjust risk using WHOIS data ===
    let domainAgeDays = null;
    let domainStatus = null;
    if (whoisData && whoisData.domain_age) {
      domainAgeDays = parseInt(whoisData.domain_age, 10);
      domainStatus = (whoisData.domain_status || '').toLowerCase();

      if (domainAgeDays > 1500 && riskLevel === 'high') {
        // Established domain → reduce risk
        riskLevel = 'medium';
      } else if (domainAgeDays > 2500 && riskLevel === 'medium') {
        // Very old domain → mark as low risk
        riskLevel = 'low';
      }

      if (domainStatus.includes('inactive') || domainStatus.includes('expired')) {
        riskLevel = 'high';
      }
    }

    // === 6. Business domain correction ===
    const isBusinessDomain = !emailData.details?.free_provider && !emailData.details?.disposable;
    if (isBusinessDomain && riskLevel === 'high') {
      riskLevel = 'medium';
    }

    // === 7. Compose final summary ===
    const summary = [
      `Reputation: ${emailData.reputation}`,
      `Mapped Risk Level: ${riskLevel}`,
      `Suspicious: ${emailData.suspicious}`,
      `Days Since Domain Created: ${whoisData?.domain_age || 'N/A'}`,
      `Domain Status: ${whoisData?.domain_status || 'N/A'}`,
      `Registrar: ${whoisData?.registrar?.name || 'N/A'}`,
      `Malicious Activity: ${emailData.details?.malicious_activity || 'none'}`,
      `Disposable: ${emailData.details?.disposable || false}`,
      `Free Provider: ${emailData.details?.free_provider || false}`
    ];

    // === 8. Final response ===
    const result = {
      email,
      domain: parsedDomain,
      isValid: !emailData.suspicious,
      status: emailData.reputation || 'unknown',
      riskLevel,
      spamScore: emailData.risk || 0,
      domainAgeDays,
      domainStatus,
      summary
    };

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
