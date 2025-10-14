/**
 * emailVerifier.js
 * ------------------------------------------------------------
 * Purpose:
 *   - Validate an email address using the EmailRep reputation API
 *   - Enrich results with IP2WHOIS domain intelligence
 *   - Return standardized JSON for Salesforce consumption
 * ------------------------------------------------------------
 * Environment variables:
 *   - EMAILREP_API_KEY   (EmailRep access key)
 *   - IP2WHOIS_API_KEY   (IP2WHOIS access key)
 * ------------------------------------------------------------
 * Version: 2.1 (2025-10-14)
 * Change Log:
 *   - Added IP2WHOIS enrichment (domain age, registrar, status)
 *   - Reversed risk scale (high rep = low risk)
 *   - Downgrade “high” risk for business domains to “medium”
 *   - Normalize isValid for legitimate business domains
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
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // === 2. Query EmailRep ===
    const emailRepRes = await fetch(`https://emailrep.io/${encodeURIComponent(email)}`, {
      method: 'GET',
      headers: {
        Key: process.env.EMAILREP_API_KEY,
        'User-Agent': 'navitas-partner-onboarding'
      }
    });

    if (!emailRepRes.ok) {
      const text = await emailRepRes.text();
      return res
        .status(emailRepRes.status)
        .json({ error: `EmailRep API error: ${text}` });
    }

    const emailRepData = await emailRepRes.json();

    // === 3. Query IP2WHOIS ===
    let whoisData = {};
    try {
      const whoisUrl = `https://api.ip2whois.com/v2?key=${process.env.IP2WHOIS_API_KEY}&domain=${parsedDomain}`;
      const whoisRes = await fetch(whoisUrl);
      if (whoisRes.ok) {
        whoisData = await whoisRes.json();
      }
    } catch (whoisErr) {
      console.warn('WHOIS lookup failed:', whoisErr.message);
    }

    // === 4. Reverse EmailRep's reputation → risk ===
    let riskLevel = 'unknown';
    switch ((emailRepData.reputation || '').toLowerCase()) {
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

    // === 5. Business domain correction ===
    const isBusinessDomain = !emailRepData.details?.free_provider && !emailRepData.details?.disposable;
    if (isBusinessDomain && riskLevel === 'high') {
      riskLevel = 'medium';
    }

    // === 6. Determine validity more intelligently ===
    let isValid = !emailRepData.suspicious;
    if (isBusinessDomain && emailRepData.suspicious) {
      isValid = true; // treat legitimate business domains as valid even if "suspicious"
    }

    // === 7. Calculate domain age (in days) ===
    let domainAgeDays = null;
    try {
      if (whoisData.create_date) {
        const createdDate = new Date(whoisData.create_date);
        const now = new Date();
        domainAgeDays = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
      }
    } catch (ageErr) {
      console.warn('Domain age calculation failed:', ageErr.message);
    }

    // === 8. Extract registrar and status info ===
    const registrar = whoisData.registrar?.name || 'Unknown';
    const domainStatus = whoisData.domain_status || 'N/A';

    // === 9. Build standardized JSON result ===
    const result = {
      email,
      domain: parsedDomain || emailRepData.details?.domain || null,
      isValid,
      status: emailRepData.reputation || 'unknown',
      riskLevel,
      spamScore: emailRepData.risk || 0,
      domainAgeDays,
      domainStatus,
      summary: [
        `Reputation: ${emailRepData.reputation}`,
        `Mapped Risk Level: ${riskLevel}`,
        `Suspicious: ${emailRepData.suspicious}`,
        `Days Since Domain Created: ${domainAgeDays ?? 'N/A'}`,
        `Domain Status: ${domainStatus}`,
        `Registrar: ${registrar}`,
        `Malicious Activity: ${emailRepData.details?.malicious_activity || 'none'}`,
        `Disposable: ${emailRepData.details?.disposable || false}`,
        `Free Provider: ${emailRepData.details?.free_provider || false}`
      ]
    };

    // === 10. Return combined JSON ===
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
