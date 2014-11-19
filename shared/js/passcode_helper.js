/* exported PasscodeHelper */
/* globals crypto, TextEncoder */

'use strict';

const SET_DIGEST_VALUE = 'lockscreen.passcode-lock.digest.value';
const SET_DIGEST_SALT = 'lockscreen.passcode-lock.digest.salt';
const SET_DIGEST_ITERATIONS = 'lockscreen.passcode-lock.digest.iterations';
const SET_DIGEST_ALGORITHM = 'lockscreen.passcode-lock.digest.algorithm';
const DEFAULT_ALGORITHM = 'SHA-1';//XXX Update to SHA-256 when bug 554827 lands.
const DEFAULT_ITERATIONS = 5000;

var PasscodeHelper = {
  /*
   * PasscodeHelper.setPassccode(string) -> Promise that resolves to a digest
   * PasscodeHelper.checkPasscode(string) -> Promise that resolves to a boolean
   * */

  _encode: function (str) {
    return new TextEncoder('utf-8').encode(str);
  },
  _toTypedArray: function (obj) {
    // SettingsAPI doesnt like arrays and gives us an Object { 1: .., 2: .. }
    var a = [];
    for (var key in obj) {
      a.push(obj[key]);
    }
    return new Uint8Array(a);
  },
  _deriveBits: function (pwKey, salt, iterations, algorithm) {
    var length = 256;
    var params = {
      name: 'PBKDF2',
      hash: algorithm,
      salt: salt,
      iterations: iterations
    };
    return crypto.subtle.deriveBits(params, pwKey, length);
  },
  _make_digest: function (pass, salt, iterations, algorithm) {
    var bytes = this._encode(pass);
    return crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, [
      'deriveBits'
    ]).then((pwKey) => {
      return this._deriveBits(pwKey, salt, iterations, algorithm);
    }, (error) => {
      console.log('PasscodeHelper._derive_bits() failed!', error);
      return false;
    });
  },
  setPasscode: function (newPass) {
    // Always generate a new salt.
    var salt = crypto.getRandomValues(new Uint8Array(8));
    var lock = navigator.mozSettings.createLock();
    var storedPromise = Promise.all([
      lock.get(SET_DIGEST_ITERATIONS),
      lock.get(SET_DIGEST_ALGORITHM)
    ]);
    return storedPromise.then((values) => {

        var iterations = parseInt(values[0]) || DEFAULT_ITERATIONS;
        var algorithm = (typeof(values[1]) == 'string') ?
          values[1] : DEFAULT_ALGORITHM;
        return this._make_digest(newPass, salt, iterations, algorithm)
          .then((digest) => {
            // Note: We can only store the salt, once digest was generated!
            var digestUint8 = new Uint8Array(digest);
            var lock = navigator.mozSettings.createLock();
            var newSettings = {};
            newSettings[SET_DIGEST_SALT] = salt;
            newSettings[SET_DIGEST_VALUE] = digestUint8;
            newSettings[SET_DIGEST_ITERATIONS] = iterations;
            newSettings[SET_DIGEST_ALGORITHM] = algorithm;
            return lock.set(newSettings).then(() => {
              return digestUint8;
            });

          }, (error) => {
            console.log('Pass_make_digest() failed!', error);
            return false;
          });
      }
    );
  },
  checkPasscode: function (testPass) {
    //get salt & digest out of settings
    var lock = navigator.mozSettings.createLock();
    var storedParams = Promise.all([
      lock.get(SET_DIGEST_SALT),
      lock.get(SET_DIGEST_ITERATIONS),
      lock.get(SET_DIGEST_ALGORITHM),
      lock.get(SET_DIGEST_VALUE)
    ]);
    return storedParams.then((values) => {
      var salt = this._toTypedArray(values[0][SET_DIGEST_SALT]);
      var storedDigest = this._toTypedArray(values[3][SET_DIGEST_VALUE]);
      return this._make_digest(testPass, salt,
        /*iterations*/ values[1][SET_DIGEST_ITERATIONS],
        /*algorithm*/  values[2][SET_DIGEST_ALGORITHM]).then(function (digest) {
          var typedDigest = new Uint8Array(digest);
          function compareDigests(buf1, buf2) {
            if (buf1.byteLength != buf2.byteLength) { return false; }
            for (var i=0; i < buf1.byteLength; i++) {
              if (buf1[i] != buf2[i]) { return false; }
            }
            return true;
          }
          return compareDigests(storedDigest, typedDigest);
        });
    });
  }
};
