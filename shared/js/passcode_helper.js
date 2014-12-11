/* exported PasscodeHelper */
/* globals crypto, TextEncoder */
(function(exports) {
  'use strict';

  const SET_DIGEST_VALUE = 'lockscreen.passcode-lock.digest.value';
  const SET_DIGEST_SALT = 'lockscreen.passcode-lock.digest.salt';
  const SET_DIGEST_ITERATIONS = 'lockscreen.passcode-lock.digest.iterations';
  const SET_DIGEST_ALGORITHM = 'lockscreen.passcode-lock.digest.algorithm';
  const DEFAULT_ALGORITHM = 'SHA-1';//XXX Update to SHA-256 after bug 554827
  const DEFAULT_ITERATIONS = 1000;

  var PasscodeHelper = {
    /*
     * PasscodeHelper.setPassccode(string) -> Promise => digest (or false)
     * PasscodeHelper.checkPasscode(string) -> Promise resolves to a boolean
     * */

    _encode: function(str) {
      return new TextEncoder('utf-8').encode(str);
    },
    _toTypedArray: function(obj) {
      // SettingsAPI doesnt like arrays and gives us an Object { 1: .., 2: .. }
      var a = [];
      for (var key in obj) {
        a.push(obj[key]);
      }
      return new Uint8Array(a);
    },
    _deriveBits: function(pwKey, salt, iterations, algorithm) {
      var length = 256;
      var params = {
        name: 'PBKDF2',
        hash: algorithm,
        salt: salt,
        iterations: iterations
      };
      return crypto.subtle.deriveBits(params, pwKey, length);
    },
    _makeDigest: function(pass, salt, iterations, algorithm) {
      var bytes = this._encode(pass);
      return crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, [
        'deriveBits'
      ]).then((pwKey) => {
        return this._deriveBits(pwKey, salt, iterations, algorithm);
      }).catch((error) => {
        console.error('PasscodeHelper: _derive_bits() failed!', error);
        return Promise.resolve(false);
      });
    },
    setPasscode: function(newPass) {
      var lock = navigator.mozSettings.createLock();
      var getFromSettings = Promise.all([
        lock.get(SET_DIGEST_ITERATIONS),
        lock.get(SET_DIGEST_ALGORITHM)
      ]);
      var digest = getFromSettings.then((values) => {
        // Always generate a new salt.
        this.salt = crypto.getRandomValues(new Uint8Array(8));
        /* the combined lock.get() makes it quite ugly. we get
         an Array of objects, each with just one key/value,
         which is the requested setting. let's destruct as follows:
         */
        this.iterations = parseInt(values[0][SET_DIGEST_ITERATIONS]) ||
          DEFAULT_ITERATIONS;
        this.algorithm = (typeof(values[1][SET_DIGEST_ALGORITHM]) == 'string') ?
          values[1][SET_DIGEST_ALGORITHM] : DEFAULT_ALGORITHM;
        var self = this;
        return this._makeDigest(newPass, this.salt,
                        this.iterations, this.algorithm)
          .then(self._storeNewDigest.bind(self)).catch((error) => {
            console.error('PasscodeHelper: Could not make digest:', error);
            return Promise.resolve(false);
          });
      }).catch((error) => {
        console.error('PasscodeHelper: No Settings?', error);
        return Promise.resolve(false);
        });
      return digest;
    },
    _storeNewDigest: function (digest) {
    // Note: We can now store the salt, since digest was generated!
    var digestUint8 = new Uint8Array(digest);
    var newSettings = {};
    newSettings[SET_DIGEST_SALT] = this.salt;
    newSettings[SET_DIGEST_VALUE] = digestUint8;
    newSettings[SET_DIGEST_ITERATIONS] = this.iterations;
    newSettings[SET_DIGEST_ALGORITHM] = this.algorithm;
    var lock = navigator.mozSettings.createLock();
    return lock.set(newSettings).then(() => {
      return digestUint8;
    }).catch((error) => {
      console.error('PasscodeHelper: Couldnt store new digest');
      return Promise.resolve(false);
    });
  },
    checkPasscode: function (testPass) {
      this.testPass = testPass;
      //get salt & digest out of settings
      var lock = navigator.mozSettings.createLock();
      var storedParams = Promise.all([
        lock.get(SET_DIGEST_SALT),
        lock.get(SET_DIGEST_ITERATIONS),
        lock.get(SET_DIGEST_ALGORITHM),
        lock.get(SET_DIGEST_VALUE)
      ]);
      return storedParams.then(this._makeAndCompare.bind(this))
      .catch((error) => {
        console.error('PasscodeHelper: Couldnt get digest Settings:', error);
        return Promise.resolve(false);
      });
    },
    _makeAndCompare: function(values) {
      /* the combined lock.get() makes it quite ugly. we get
       an Array of objects, each with just one key/value,
       which is the requested setting. let's destruct as follows:
       */
      var salt = this._toTypedArray(values[0][SET_DIGEST_SALT]);
      var iterations = values[1][SET_DIGEST_ITERATIONS];
      var algorithm = values[2][SET_DIGEST_ALGORITHM];
      var storedDigest = this._toTypedArray(values[3][SET_DIGEST_VALUE]);

      return this._makeDigest(this.testPass, salt, iterations, algorithm)
        .then(function (digest) {

          var typedDigest = new Uint8Array(digest);

          return this._compareDigests(storedDigest, typedDigest);
        }.bind(this)).catch((error) => {
          console.error('PasscodeHelper: Couldnt create digest', error);
          return Promise.resolve(false);
        });
    },
    _compareDigests: function compareDigests(buf1, buf2) {
      if (buf1.byteLength !== buf2.byteLength) {
        return false;
      }
      for (var i = 0; i < buf1.byteLength; i++) {
        if (buf1[i] !== buf2[i]) {
          return false;
        }
      }
      return true;
    }
  };
  exports.PasscodeHelper = PasscodeHelper;
})(this);
