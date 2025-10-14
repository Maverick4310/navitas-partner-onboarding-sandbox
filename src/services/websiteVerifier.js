/**
 * websiteVerifier.js
 * --------------------------------------------------------
 * Purpose:
 *  - Evaluate website legitimacy using IP2WHOIS + Google Safe Browsing API
 *  - Return risk score and human-readable summary
 * --------------------------------------------------------
 * Env Vars required:
 *  - IP2WHOIS_KEY
 *  - GSB_API_KEY
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

  const whoisKey = process.env.IP2WHOIS_KEY;
  const gsbKey = process.env.GSB_API_KEY;
  const debug = process.env.VERIFIER_DEBUG === 'true';

  try {
    const cleanDomain = website
      .replace(/^https?:\/\//, '')
      .replace(/\/.*/, '')
      .trim()
      .toLowerCase();

    if (debug) console.log(`🔍 Verifying ${cleanDomain}`);

    let summary = [];
    let score = 50;

    // === DNS Lookup ===
    let resolvedIP = null;
    try {
      const dnsRes = await dns.lookup(cleanDomain);
      resolvedIP = dnsRes.address;
      summary.push(`Resolves to IP ${resolvedIP}`);
    } catch (e) {
      if (debug) console.warn(`DNS lookup failed: ${e.message}`);
    }

    // === 1) IP2WHOIS Check ===
    let whoisData = {};
    if (whoisKey) {
      try {
        const url = `https://api.ip2whois.com/v2?key=${encodeURIComponent(whoisKey)}&domain=${encodeURIComponent(cleanDomain)}`;
        const resp = await axios.get(url, { timeout: 10000 });
        whoisData = resp.data || {};
        if (debug) console.log('WHOIS:', whoisData);
      } catch (e) {
        console.warn(`WHOIS lookup failed for ${cleanDomain}: ${e.message}`);
      }
    }

    const ageDays =
      whoisData.domain_age ||
      (whoisData.create_date
        ? Math.floor((Date.now() - new Date(whoisData.create_date).getTime()) / (1000 * 60 * 60 * 24))
        : 0);
    const ageYears = (ageDays / 365).toFixed(1);

    if (ageDays > 0) {
      summary.push(`Domain active for ${ageYears} years (since ${whoisData.create_date?.split('T')[0] || 'unknown'})`);
      if (ageDays < 90) score -= 15;
      else if (ageDays < 365) score -= 5;
      else score += 20;
    } else {
      summary.push('Domain age unavailable');
    }

    if (whoisData.registrar?.name) {
      summary.push(`Registrar: ${whoisData.registrar.name}`);
    }
    if (whoisData.nameservers?.length) {
      summary.push(`Nameservers: ${whoisData.nameservers.slice(0, 2).join(', ')}`);
    }

    // === 2) HTTPS Check ===
    if (website.toLowerCase().startsWith('https://')) {
      summary.push('Valid HTTPS detected');
      score += 10;
    } else {
      summary.push('No HTTPS detected');
      score -= 10;
    }

    // === 3) Google Safe Browsing Check ===
    if (gsbKey) {
      try {
        const gsbUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(gsbKey)}`;
        const gsbBody = {
          client: { clientId: 'navitas', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: website }]
          }
        };
        const gsbResp = await axios.post(gsbUrl, gsbBody, { timeout: 8000 });
        if (gsbResp.data && gsbResp.data.matches && gsbResp.data.matches.length > 0) {
          summary.push('⚠️ Flagged by Google Safe Browsing for malware/phishing');
          score -= 30;
        } else {
          summary.push('No threats found (Google Safe Browsing)');
          score += 10;
        }
      } catch (e) {
        console.warn(`GSB check failed: ${e.message}`);
      }
    } else {
      summary.push('Google Safe Browsing key not configured');
    }

    // === 4) Finalize score ===
    if (score > 100) score = 100;
    if (score < 0) score = 0;

    const status =
      score >= 80 ? 'Likely Legitimate' : score >= 50 ? 'Needs Review' : 'Potentially Fraudulent';
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

    if (debug) console.log('✅ Verification Result:', result);
    return res.status(200).json(result);
  } catch (err) {
    console.error('verifyWebsiteHandler error:', err);
    return res.status(500).json({ error: true, message: err.message });
  }
}

module.exports = { verifyWebsiteHandler };
