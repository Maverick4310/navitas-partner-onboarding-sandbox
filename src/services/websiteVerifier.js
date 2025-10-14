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

// === helper to test HTTPS even when "https://" missing ===
async function checkHttpsAvailable(domain) {
  try {
    const res = await axios.get(`https://${domain}`, { timeout: 5000, maxRedirects: 2 });
    return res.status >= 200 && res.status < 400;
  } catch {
    return false;
  }
}

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

    // --- Domain age ---
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
      score += 20; // assume mature if not returned (GDPR masking)
    }

    // --- Registrar ---
    const registrarName = whoisData.registrar?.name || whoisData.registrar_name;
    if (registrarName) {
      summary.push(`Registrar: ${registrarName}`);
      if (/corporate|markmonitor|csc|com laude|safenames/i.test(registrarName)) score += 5;
    }

    // --- Nameservers ---
    if (whoisData.nameservers?.length) {
      const nsList = whoisData.nameservers.slice(0, 2).join(', ');
      summary.push(`Nameservers: ${nsList}`);
      const nsText = whoisData.nameservers.join(' ').toLowerCase();
      if (nsText.includes('cloudflare') || nsText.includes('google') || nsText.includes('aws') || nsText.includes('nsone')) {
        score += 3;
      }
    }

    // === 2) HTTPS Check (robust) ===
    let httpsOk = website.toLowerCase().startsWith('https://');
    if (!httpsOk) {
      httpsOk = await checkHttpsAvailable(cleanDomain);
    }

    if (httpsOk) {
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
        threatEntries: [{ url: website }]   // <-- use full URL exactly as sent in request
      }
    };
    const gsbResp = await axios.post(gsbUrl, gsbBody, { timeout: 10000 });
    if (gsbResp.data && gsbResp.data.matches && gsbResp.data.matches.length > 0) {
      summary.push('⚠️ Flagged by Google Safe Browsing for malware/phishing');
      score -= 60;
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
