/* exported PasscodeHelper */
/* globals crypto, TextEncoder */
(function(exports) {
  'use strict';

  const SET_DIGEST_VALUE = 'lockscreen.passcode-lock.digest.value';
  const SET_DIGEST_SALT = 'lockscreen.passcode-lock.digest.salt';
  const SET_DIGEST_ITERATIONS = 'lockscreen.passcode-lock.digest.iterations';
  const SET_DIGEST_ALGORITHM = 'lockscreen.passcode-lock.digest.algorithm';
  const DEFAULT_ALGORITHM = 'SHA-1'; //XXX Update to SHA-256 after bug 554827?
  const DEFAULT_ITERATIONS = 1000;


  var PasscodeHelper = function() {
    /* Usage:
     *      var ph = new PasscodeHelper();
     *      ph.setPassccode(string) -> Promise => digest (or false)
     *      ph.checkPasscode(string) -> Promise resolves to a boolean
     * */


    var _salt;
    var _iterations;
    var _algorithm;
    var _testPass;

    this._encode = function(str) {
      return new TextEncoder('utf-8').encode(str);
    };
    this._toTypedArray = function(obj) {
      // SettingsAPI doesnt like arrays and gives us an Object { 1: .., 2: .. }
      var a = [];
      for (var key in obj) {
        a.push(obj[key]);
      }
      return new Uint8Array(a);
    };
    this._deriveBits = function(pwKey, salt, iterations, algorithm) {
      var length = 256;
      var params = {
        name: 'PBKDF2',
        hash: algorithm,
        salt: salt,
        iterations: iterations
      };
      return crypto.subtle.deriveBits(params, pwKey, length);
    };

    this._makeDigest = function(pass, salt, iterations, algorithm) {
      var bytes = this._encode(pass);
      return crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, [
        'deriveBits'
      ]).then((pwKey) => {
        return this._deriveBits(pwKey, salt, iterations, algorithm);
      }).catch((error) => {
        console.error('PasscodeHelper: _derive_bits() failed!', error);
        throw error;
      });
    };

    this.setPasscode = function(newPass) {
      var lock = navigator.mozSettings.createLock();
      var getFromSettings = Promise.all([
        lock.get(SET_DIGEST_ITERATIONS),
        lock.get(SET_DIGEST_ALGORITHM)
      ]);
      var digest = getFromSettings.then((values) => {
        // Always generate a new salt.
        _salt = crypto.getRandomValues(new Uint8Array(8));
        /* the combined lock.get() makes it quite ugly. we get
         an Array of objects, each with just one key/value,
         which is the requested setting. let's destruct as follows:
         */
        var [digestIteration, digestAlgorithm] = values;
        _iterations = parseInt(digestIteration[SET_DIGEST_ITERATIONS]) ||
          DEFAULT_ITERATIONS;
        _algorithm = typeof(digestAlgorithm[SET_DIGEST_ALGORITHM]) == 'string' ?
                     values[1][SET_DIGEST_ALGORITHM] : DEFAULT_ALGORITHM;

        return this._makeDigest(newPass, _salt,
          _iterations, _algorithm)
          .then(this._storeNewDigest).catch((error) => {
            console.error('PasscodeHelper: Could not make digest:', error);
            throw error;
          });
      }).catch((error) => {
        console.error('PasscodeHelper: No Settings?', error);
        throw error;
      });
      return digest;
    };
    this._storeNewDigest = function (digest) {
      // Note: We can now store the salt, since digest was generated!
      var digestUint8 = new Uint8Array(digest);
      var newSettings = {};
      newSettings[SET_DIGEST_SALT] = _salt;
      newSettings[SET_DIGEST_VALUE] = digestUint8;
      newSettings[SET_DIGEST_ITERATIONS] = _iterations;
      newSettings[SET_DIGEST_ALGORITHM] = _algorithm;
      var lock = navigator.mozSettings.createLock();
      return lock.set(newSettings).then(() => {
        return digestUint8;
      }, (error) => {
        console.error('PasscodeHelper: Couldnt store new digest');
        throw error;
      });
    };
    this.checkPasscode = function (testPass) {
      _testPass = testPass;
      //get salt & digest out of settings
      var lock = navigator.mozSettings.createLock();
      var storedParams = Promise.all([
        lock.get(SET_DIGEST_SALT),
        lock.get(SET_DIGEST_ITERATIONS),
        lock.get(SET_DIGEST_ALGORITHM),
        lock.get(SET_DIGEST_VALUE)
      ]);
      return storedParams.then((values) => {
        return this._makeAndCompare(values[0], values[1], values[2], values[3]);
      })
        .catch((error) => {
          console.error('PasscodeHelper: Couldnt get digest Settings:', error);
          throw error;
        });
    };
    this._makeAndCompare = function(salt, iterations, algorithm, storedDigest) {
      /* the combined lock.get() makes it quite ugly. we get
       an Array of objects, each with just one key/value,
       which is the requested setting. let's destruct as follows:
       */
      var _salt = this._toTypedArray(salt[SET_DIGEST_SALT]);
      var _iterations = iterations[SET_DIGEST_ITERATIONS];
      var _algorithm = algorithm[SET_DIGEST_ALGORITHM];
      var _storedDigest = this._toTypedArray(storedDigest[SET_DIGEST_VALUE]);

      return this._makeDigest(_testPass, _salt, _iterations, _algorithm)
        .then(function (digest) {

          var typedDigest = new Uint8Array(digest);

          return this._compareDigests(_storedDigest, typedDigest);
        }.bind(this)).catch((error) => {
          console.error('PasscodeHelper: Couldnt create digest', error);
          throw error;
        });
    };
    this._compareDigests = function compareDigests(buf1, buf2) {
      if (buf1.byteLength !== buf2.byteLength) {
        return false;
      }
      for (var i = 0; i < buf1.byteLength; i++) {
        if (buf1[i] !== buf2[i]) {
          return false;
        }
      }
      return true;
    };
  };

  exports.PasscodeHelper = PasscodeHelper;
})(this);