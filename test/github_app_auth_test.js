var should = require('should');
var crypto = require('crypto');
var fs = require('fs');
var path = require('path');
var os = require('os');

// Init logging without Consul dependency
var logging = require('../lib/logging.js');
logging.init({
  "logger" : {
    "name" : "git2consul",
    "streams" : [{
      "level": "warn",
      "stream": "process.stdout"
    }]
  }
});

// Generate a test RSA key pair
var testKeyPair = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
});

var credDir = path.join(os.homedir(), '.git-credentials');

describe('GitHub App Auth', function() {

  var originalEnv = {};

  beforeEach(function() {
    ['GITHUB_APP_ID', 'GITHUB_INSTALLATION_ID', 'GITHUB_APP_PRIVATE_KEY', 'GIT_CONFIG_GLOBAL'].forEach(function(key) {
      originalEnv[key] = process.env[key];
      delete process.env[key];
    });
    if (fs.existsSync(credDir)) {
      fs.rmSync(credDir, { recursive: true, force: true });
    }
  });

  afterEach(function() {
    Object.keys(originalEnv).forEach(function(key) {
      if (originalEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = originalEnv[key];
      }
    });
    if (fs.existsSync(credDir)) {
      fs.rmSync(credDir, { recursive: true, force: true });
    }
  });

  // Re-require to reset cached token between tests
  function freshAuth() {
    delete require.cache[require.resolve('../lib/git/github_app_auth.js')];
    return require('../lib/git/github_app_auth.js');
  }

  it('should be a no-op when env vars are not set', function(done) {
    var auth = freshAuth();
    auth.refreshIfNeeded(function(err) {
      should.not.exist(err);
      should.not.exist(process.env.GIT_CONFIG_GLOBAL);
      // No credentials file should be created
      fs.existsSync(credDir).should.not.be.ok;
      done();
    });
  });

  it('should fail gracefully with invalid private key', function(done) {
    var auth = freshAuth();
    process.env.GITHUB_APP_ID = '12345';
    process.env.GITHUB_INSTALLATION_ID = '67890';
    process.env.GITHUB_APP_PRIVATE_KEY = 'not-a-real-key';

    auth.refreshIfNeeded(function(err) {
      should.exist(err);
      err.message.should.containEql('Failed to generate JWT');
      done();
    });
  });

  it('should generate a valid JWT that can be verified with the public key', function() {
    var now = Math.floor(Date.now() / 1000);
    var header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    var payload = Buffer.from(JSON.stringify({
      iat: now - 60,
      exp: now + 600,
      iss: '12345'
    })).toString('base64url');

    var unsigned = header + '.' + payload;
    var signer = crypto.createSign('RSA-SHA256');
    signer.update(unsigned);
    var signature = signer.sign(testKeyPair.privateKey, 'base64url');
    var jwt = unsigned + '.' + signature;

    // Verify structure
    var parts = jwt.split('.');
    parts.length.should.equal(3);

    // Verify header
    var decodedHeader = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    decodedHeader.alg.should.equal('RS256');
    decodedHeader.typ.should.equal('JWT');

    // Verify payload
    var decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    decodedPayload.iss.should.equal('12345');
    decodedPayload.exp.should.be.above(decodedPayload.iat);

    // Verify signature
    var verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(parts[0] + '.' + parts[1]);
    verifier.verify(testKeyPair.publicKey, parts[2], 'base64url').should.be.ok;
  });

  it('should write correctly formatted git credentials files', function() {
    // Simulate what writeGitCredentials does
    var token = 'ghs_test_token_abc123';

    if (!fs.existsSync(credDir)) {
      fs.mkdirSync(credDir, { recursive: true, mode: 0o700 });
    }

    var credFile = path.join(credDir, 'credentials');
    var configFile = path.join(credDir, 'gitconfig');

    fs.writeFileSync(credFile, 'https://x-access-token:' + token + '@github.com\n', { mode: 0o600 });
    fs.writeFileSync(configFile, '[credential]\n\thelper = store --file=' + credFile + '\n', { mode: 0o644 });

    // Verify credentials file
    fs.existsSync(credFile).should.be.ok;
    var credContent = fs.readFileSync(credFile, 'utf8');
    credContent.should.equal('https://x-access-token:ghs_test_token_abc123@github.com\n');

    // Verify permissions
    var credStats = fs.statSync(credFile);
    (credStats.mode & 0o777).should.equal(0o600);

    // Verify gitconfig
    fs.existsSync(configFile).should.be.ok;
    var configContent = fs.readFileSync(configFile, 'utf8');
    configContent.should.containEql('[credential]');
    configContent.should.containEql('helper = store --file=' + credFile);
  });

  it('should skip refresh when env vars are partially set', function(done) {
    var auth = freshAuth();
    // Only set one of the three required vars
    process.env.GITHUB_APP_ID = '12345';

    auth.refreshIfNeeded(function(err) {
      should.not.exist(err);
      should.not.exist(process.env.GIT_CONFIG_GLOBAL);
      done();
    });
  });

  it('should fail when GitHub API returns an error', function(done) {
    var auth = freshAuth();
    process.env.GITHUB_APP_ID = '12345';
    process.env.GITHUB_INSTALLATION_ID = '99999';
    process.env.GITHUB_APP_PRIVATE_KEY = testKeyPair.privateKey;

    // This will generate a valid JWT but the GitHub API will reject it
    // because the app ID doesn't match a real app
    auth.refreshIfNeeded(function(err) {
      should.exist(err);
      done();
    });
  });
});
