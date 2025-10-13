/**
 * websiteVerifier.js
 * --------------------------------------------------------
 * Purpose:
 *  - Evaluate website legitimacy using IP2WHOIS API
 *  - Determine domain age, registrar, and nameserver info
 *  - Return structured result for Salesforce Note creation
 * --------------------------------------------------------
 * Required Env Vars:
 *  - IP2WHOIS_KEY (from ip2whois.com)
 * Optional:
 *  - VERIFIER_DEBUG=true
 * --------------------------------------------------------
 */

const axios = require('axios');
const dns = require('dns').promises;

async function verifyWebsiteHandler(req, res) {
  const { website } = req.body || {};
  if (!website) {
    return res.status(400).json({ error: true, message: 'Website URL is required.' });
  }

  const apiKey = process.env.IP2WHOIS_KEY;
  const debug = process.env.VERIFIER_DEBUG === 'true';

  try {
    const cleanDomain = website
      .replace(/^https?:\/\//, '')
      .replace(/\/.*/, '')
      .trim()
      .toLowerCase();

    if (debug) console.log(`Checking WHOIS for: ${cleanDomain}`);

    // === DNS Lookup ===
    let resolvedIP = null;
    try {
      const dnsRes = await dns.lookup(cleanDomain);
      resolvedIP = dnsRes.address;
    } catch (e) {
      if (debug) console.warn(`DNS lookup failed for ${cleanDomain}: ${e.message}`);
    }

    // === WHOIS Lookup ===
    let whoisData = {};
    if (!apiKey) {
      return res
        .status(500)
        .json({ error: true, message: 'Missing IP2WHOIS_KEY environment variable.' });
    }

    try {
      const url = `https://api.ip2whois.com/v2?key=${encodeURIComponent(apiKey)}&domain=${encodeURIComponent(cleanDomain)}`;
      const response = await axios.get(url, { timeout: 10000 });
      whoisData = response.data || {};
      if (debug) console.log('WHOIS response:', whoisData);
    } catch (err) {
      console.error(`WHOIS request failed for ${cleanDomain}: ${err.message}`);
      return res.status(500).json({ error: true, message: 'IP2WHOIS request failed.' });
    }

    // === Compute domain age ===
    const ageDays =
      whoisData.domain_age ||
      (whoisData.create_date
        ? Math.floor((Date.now() - new Date(whoisData.create_date).getTime()) / (1000 * 60 * 60 * 24))
        : 0);
    const ageYears = (ageDays / 365).toFixed(1);

    // === Scoring ===
    let score = 50;
    const summary = [];

    if (ageDays > 0) {
      summary.push(`Domain active for ${ageYears} years (since ${whoisData.create_date?.split('T')[0] || 'unknown'})`);
      if (ageDays < 90) score -= 15;
      else if (ageDays < 365) score -= 5;
      else if (ageDays >= 365) score += 20;
    } else {
      summary.push('Domain age unavailable');
    }

    if (whoisData.registrar && whoisData.registrar.name) {
      summary.push(`Registrar: ${whoisData.registrar.name}`);
      const reg = whoisData.registrar.name.toLowerCase();
      if (reg.includes('corporate') || reg.includes('markmonitor') || reg.includes('csc')) {
        score += 5;
      }
    }

    if (whoisData.nameservers && whoisData.nameservers.length) {
      const ns = whoisData.nameservers.slice(0, 2).join(', ');
      summary.push(`Nameservers: ${ns}`);
      const nsText = whoisData.nameservers.join(' ').toLowerCase();
      if (nsText.includes('cloudflare') || nsText.includes('google') || nsText.includes('aws')) {
        score += 3;
      }
    }

    if (website.toLowerCase().startsWith('https://')) {
      summary.push('Valid HTTPS detected');
      score += 10;
    } else {
      summary.push('No HTTPS detected');
      score -= 10;
    }

    if (resolvedIP) summary.push(`Resolves to IP ${resolvedIP}`);

    // Clamp score
    if (score > 100) score = 100;
    if (score < 0) score = 0;

    const status =
      score >= 80
        ? 'Likely Legitimate'
        : score >= 50
        ? 'Needs Review'
        : 'Potentially Fraudulent';
    const riskLevel =
      status === 'Likely Legitimate'
        ? 'Low'
        : status === 'Needs Review'
        ? 'Medium'
        : 'High';

    const result = {
      domain: cleanDomain,
      score,
      status,
      summary,
      riskLevel,
      timestamp: new Date().toISOString()
    };

    return res.status(200).json(result);
  } catch (err) {
    console.error('verifyWebsiteHandler error:', err.message);
    return res.status(500).json({ error: true, message: err.message });
  }
}

module.exports = { verifyWebsiteHandler };
