function computeHttpSignature(config, headerHash) {
  var template = 'Signature keyId="${keyId}",algorithm="${algorithm}",headers="${headers}",signature="${signature}"',
      sig = template;

  // compute sig here
  var signingBase = '';
  config.headers.forEach(function(h){
    if (signingBase !== '') { signingBase += '\n'; }
    signingBase += h.toLowerCase() + ": " + headerHash[h];
  });

  var hashf = (function() {
      switch (config.algorithm) {
        case 'hmac-sha1': return CryptoJS.HmacSHA1;
        case 'hmac-sha256': return CryptoJS.HmacSHA256;
        case 'hmac-sha512': return CryptoJS.HmacSHA512;
        default : return null;
      }
    }());

  var hash = hashf(signingBase, config.secretkey);
  var signatureOptions = {
        keyId : config.keyId,
        algorithm: config.algorithm,
        headers: config.headers,
        signature : CryptoJS.enc.Base64.stringify(hash)
      };

  // build sig string here
  Object.keys(signatureOptions).forEach(function(key) {
    var pattern = "${" + key + "}",
        value = (typeof signatureOptions[key] != 'string') ? signatureOptions[key].join(' ') : signatureOptions[key];
    sig = sig.replace(pattern, value);
  });

  return sig;
}


var curDate = new Date().toGMTString();
var targetUrl = request.url.trim(); // there may be surrounding ws
targetUrl = targetUrl.replace(new RegExp('^https?://[^/]+/'),'/'); // strip hostname
var method = request.method.toLowerCase();
var sha256digest = CryptoJS.SHA256(request.data);
var base64sha256 = CryptoJS.enc.Base64.stringify(sha256digest);
var computedDigest = 'sha-256=' + base64sha256;

var headerHash = {
      date : curDate,
      host : '',
      '(request-target)' : method + ' ' + targetUrl ,
      'accept' : 'application/json'
    };

var config = {
      algorithm : 'hmac-sha256',
      keyId : '',
      secretkey : '',
      headers : ['(request-target)', 'accept', 'date', 'host']
    };

var sig = computeHttpSignature(config, headerHash);

postman.setEnvironmentVariable('httpsig', sig);
postman.setEnvironmentVariable("current-date", curDate);
postman.setEnvironmentVariable("target-url", targetUrl);
