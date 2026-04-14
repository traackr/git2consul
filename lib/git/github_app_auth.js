var crypto = require('crypto');
var https = require('https');
var fs = require('fs');
var os = require('os');
var path = require('path');

var logger = require('../logging.js');

var cachedToken = null;
var cachedExpiresAt = null;

function isConfigured() {
  return !!(process.env.GITHUB_APP_ID &&
    process.env.GITHUB_INSTALLATION_ID &&
    process.env.GITHUB_APP_PRIVATE_KEY);
}

function generateJWT() {
  var now = Math.floor(Date.now() / 1000);
  var header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  var payload = Buffer.from(JSON.stringify({
    iat: now - 60,
    exp: now + 600,
    iss: process.env.GITHUB_APP_ID
  })).toString('base64url');

  var unsigned = header + '.' + payload;
  var signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  var signature = signer.sign(process.env.GITHUB_APP_PRIVATE_KEY, 'base64url');

  return unsigned + '.' + signature;
}

function requestInstallationToken(jwt, cb) {
  var installationId = process.env.GITHUB_INSTALLATION_ID;
  var options = {
    hostname: 'api.github.com',
    path: '/app/installations/' + installationId + '/access_tokens',
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + jwt,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'git2consul'
    }
  };

  var req = https.request(options, function(res) {
    var body = '';
    res.on('data', function(chunk) { body += chunk; });
    res.on('end', function() {
      if (res.statusCode !== 201) {
        return cb(new Error('GitHub API returned ' + res.statusCode + ': ' + body));
      }
      try {
        var data = JSON.parse(body);
        cb(null, data.token, data.expires_at);
      } catch (e) {
        cb(new Error('Failed to parse GitHub API response: ' + e.message));
      }
    });
  });

  req.on('error', function(err) { cb(err); });
  req.end();
}

function writeGitCredentials(token) {
  var credDir = path.join(os.homedir(), '.git-credentials');
  var credFile = path.join(credDir, 'credentials');
  var configFile = path.join(credDir, 'gitconfig');

  if (!fs.existsSync(credDir)) {
    fs.mkdirSync(credDir, { recursive: true, mode: 0o700 });
  }

  fs.writeFileSync(credFile, 'https://x-access-token:' + token + '@github.com\n', { mode: 0o600 });
  fs.writeFileSync(configFile, '[credential]\n\thelper = store --file=' + credFile + '\n', { mode: 0o644 });

  process.env.GIT_CONFIG_GLOBAL = configFile;
}

/**
 * Refresh the GitHub App installation token if needed.
 * Calls back immediately if no refresh is required or if not configured.
 */
exports.refreshIfNeeded = function(cb) {
  if (!isConfigured()) return cb();

  // Check if cached token is still valid (with 5 min buffer)
  if (cachedToken && cachedExpiresAt) {
    var bufferMs = 5 * 60 * 1000;
    if (new Date(cachedExpiresAt).getTime() - bufferMs > Date.now()) {
      return cb();
    }
  }

  logger.info('Refreshing GitHub App installation token...');

  try {
    var jwt = generateJWT();
  } catch (e) {
    return cb(new Error('Failed to generate JWT: ' + e.message));
  }

  requestInstallationToken(jwt, function(err, token, expiresAt) {
    if (err) return cb(err);

    cachedToken = token;
    cachedExpiresAt = expiresAt;

    writeGitCredentials(token);
    logger.info('GitHub App token refreshed, expires at %s', expiresAt);
    cb();
  });
};
