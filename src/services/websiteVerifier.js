/**
 * websiteVerifier.js
 * --------------------------------------------------------
 * Purpose:
 *  - Analyze a vendor’s website to assess legitimacy
 *  - Used by Salesforce credit underwriting automation
 * --------------------------------------------------------
 */

const whois = require('whois-json');
const dns = require('dns').promises; 

/**
 * POST /verifyWebsite
 * Body: { "website": "https://example.com" }
 */
async function verifyWebsiteHandler(req, res) {
  const { website } = req.body || {};
  if (!website) {
    return res.status(400).json({ error: true, message: 'Website URL is required.' });
  }

  try {
    const cleanDomain = website
      .replace(/^https?:\/\//, '')
      .replace(/\/.*/, '')
      .trim();

    // === Basic indicators ===
    const whoisData = await safeWhoisLookup(cleanDomain);
    const domainAge = computeDomainAge(whoisData);
    const hasSSL = website.startsWith('https://');
    const resolvedIP = await safeDnsLookup(cleanDomain);

    // === Simple scoring model ===
    let score = 50;
    const summary = [];

    if (domainAge >= 365) {
      score += 20;
      summary.push(`Domain active for ${(domainAge / 365).toFixed(1)} years`);
    } else if (domainAge >= 90) {
      score += 10;
      summary.push('Domain older than 3 months');
    } else {
      score -= 15;
      summary.push('New domain (less than 3 months old)');
    }

    if (hasSSL) {
      score += 10;
      summary.push('Valid HTTPS detected');
    } else {
      score -= 10;
      summary.push('No HTTPS detected');
    }

    if (resolvedIP) {
      summary.push(`Resolves to IP ${resolvedIP}`);
    } else {
      score -= 5;
      summary.push('Unable to resolve DNS');
    }

    // Cap score
    if (score > 100) score = 100;
    if (score < 0) score = 0;

    const status =
      score >= 80
        ? 'Likely Legitimate'
        : score >= 50
        ? 'Needs Review'
        : 'Potentially Fraudulent';

    const result = {
      domain: cleanDomain,
      score,
      status,
      summary,
      riskLevel:
        status === 'Likely Legitimate'
          ? 'Low'
          : status === 'Needs Review'
          ? 'Medium'
          : 'High',
      timestamp: new Date().toISOString()
    };

    console.log(
      `[${new Date().toISOString()}] Website check → ${cleanDomain} → ${status} (${score})`
    );
    return res.status(200).json(result);
  } catch (err) {
    console.error('Error verifying website:', err.message);
    return res.status(500).json({ error: true, message: err.message });
  }
}

/** WHOIS lookup with fail-safe */
async function safeWhoisLookup(domain) {
  try {
    return await whois(domain);
  } catch (e) {
    console.warn(`WHOIS lookup failed for ${domain}: ${e.message}`);
    return {};
  }
}

/** Estimate domain age in days */
function computeDomainAge(whoisData) {
  if (!whoisData.creationDate) return 0;
  const created = new Date(whoisData.creationDate);
  return Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
}

/** Resolve domain to IP with fail-safe */
async function safeDnsLookup(domain) {
  try {
    const res = await dns.lookup(domain);
    return res.address;
  } catch {
    return null;
  }
}

module.exports = { verifyWebsiteHandler };
