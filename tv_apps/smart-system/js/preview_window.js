/* -*- Mode: Java; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- /
/* vim: set shiftwidth=2 tabstop=2 autoindent cindent expandtab: */
'use strict';
/* global applications */
/* global AppWindow */
/* global AppInstallManager */
/* global AppInstallDialogs */
/* global BookmarkManager */
/* global InteractiveNotifications */
/* global SystemBanner */

(function(exports) {
  const PREVIEW_OPENED_TIMES_KEY = 'preview-opened-times';
  const PREVIEW_OPENED_TIMES_TO_HINT = 3;

  /**
   * This window is inherit the AppWindow, and modifies some properties
   * different from the later.
   *
   * @constructor PreviewWindow
   * @augments AppWindow
   */
  var PreviewWindow = function(configs) {
    if (configs && configs.rearWindow) {
      // Render inside its opener.
      this.container = configs.rearWindow;
    }

    this.isWebsite = !configs.manifestURL;
    this.identity = configs.manifestURL || configs.url;
    this.features = configs.features || {};

    this.systemBanner = new SystemBanner();

    configs.chrome = {
      scrollable: false
    };

    AppWindow.call(this, configs);

    if (this.features.name) {
      this.name = this.features.name;
    }

    this.iframe.focus();

    this.container.element.addEventListener('_closed', this);
    this.element.addEventListener('_opened', this);
    this.element.addEventListener('_willdestroy', this);
  };

  /**
   * @borrows AppWindow.prototype as PreviewWindow.prototype
   * @memberof PreviewWindow
   */
  PreviewWindow.prototype = Object.create(AppWindow.prototype);

  PreviewWindow.REGISTERED_EVENTS =
    ['mozbrowserclose', 'mozbrowsererror', 'mozbrowservisibilitychange',
     'mozbrowserloadend', 'mozbrowseractivitydone', 'mozbrowserloadstart',
     'mozbrowsertitlechange', 'mozbrowserlocationchange',
     'mozbrowsericonchange'];

  PreviewWindow.SUB_COMPONENTS = {
    'transitionController': window.AppTransitionController,
    'modalDialog': window.AppModalDialog,
    'valueSelector': window.ValueSelector,
    'authDialog': window.AppAuthenticationDialog,
    'contextmenu': window.BrowserContextMenu,
    'childWindowFactory': window.ChildWindowFactory
  };

  /**
   * We would maintain our own events by other components.
   *
   * @type String
   * @memberof PreviewWindow
   */
  PreviewWindow.prototype.eventPrefix = 'preview';

  PreviewWindow.prototype._DEBUG = false;

  PreviewWindow.prototype.CLASS_NAME = 'PreviewWindow';

  PreviewWindow.prototype.CLASS_LIST = 'appWindow previewWindow';

  PreviewWindow.prototype.openAnimation = 'fade-in';

  PreviewWindow.prototype.closeAnimation = 'fade-out';

  PreviewWindow.prototype.requestOpen = function() {
    this.open();
  };

  PreviewWindow.prototype.requestClose = function() {
    this.close();
  };

  PreviewWindow.prototype.isFocusable = function() {
    return this.isVisible();
  };

  PreviewWindow.prototype._handle_mozbrowserafterkeyup = function(evt) {
    if (document.activeElement !== this.iframe) {
      return;
    }
    if ((evt.keyCode === 27 || evt.key === 'Escape') &&
        !evt.embeddedCancelled) {
      if (this.config.url.startsWith('app://')) {
        this.kill();
      } else {
        var goBackReq = this.iframe.getCanGoBack();
        goBackReq.onsuccess = () => {
          if (goBackReq.result) {
            this.iframe.goBack();
          } else {
            this.kill();
          }
        };
        goBackReq.onerror = () => {
          this.kill();
        };
      }
    }
  };

  PreviewWindow.prototype._handle__opened = function(evt) {
    var previewOpenedTimes =
      JSON.parse(localStorage.getItem(PREVIEW_OPENED_TIMES_KEY) || '{}');

    if (!previewOpenedTimes[this.identity]) {
      previewOpenedTimes[this.identity] = 0;
    }
    previewOpenedTimes[this.identity]++;

    localStorage.setItem(PREVIEW_OPENED_TIMES_KEY,
      JSON.stringify(previewOpenedTimes));

    window.interactiveNotifications.showNotification(
      InteractiveNotifications.TYPE.NORMAL, {
        title: {
          id: 'press-option-hint'
        },
        text: {
          id: 'add-to-apps'
        },
        icon: AppInstallManager.ADD_TO_APPS_ICON_PATH
      }
    );
  };

  PreviewWindow.prototype._handle__willdestroy = function(evt) {
    this.container.element.removeEventListener('_closed', this);

    var previewOpenedTimes =
      JSON.parse(localStorage.getItem(PREVIEW_OPENED_TIMES_KEY) || '{}');
    var needPrompt =
      previewOpenedTimes[this.identity] == PREVIEW_OPENED_TIMES_TO_HINT;
    var options;

    if (this.isWebsite) {
      if (needPrompt) {
        BookmarkManager.get(this.identity).then((bookmark) => {
          var name = this.features.name;
          if (!bookmark) {
            options = {
              manifest: {
                name: name
              }
            };
            AppInstallManager.appInstallDialogs
              .show(AppInstallDialogs.TYPES.AddAppDialog, options)
              .then(() => {
                return BookmarkManager.add({
                  name: name,
                  url: this.identity,
                  iconUrl: this.features.iconUrl
                });
              })
              .then(() => {
                this.systemBanner.show({
                  title: name,
                  text: {
                    id: 'added-to-apps'
                  },
                  icon: AppInstallManager.ADD_TO_APPS_ICON_PATH
                });
              });
          }
        });
      }
    } else {
      if (needPrompt && !AppInstallManager.getAppAddedState(this.manifestURL)) {
        var app = applications.getByManifestURL(this.manifestURL);

        options = {
          manifest: app.manifest
        };

        var onFulfilled = AppInstallManager.handleAddAppToApps
          .bind(AppInstallManager, app);
        var onRejected = AppInstallManager.uninstallPreviewApp
          .bind(AppInstallManager);

        AppInstallManager.appInstallDialogs
          .show(AppInstallDialogs.TYPES.AddAppDialog, options)
          .then(onFulfilled, onRejected);
      } else {
        AppInstallManager.uninstallPreviewApp();
      }
    }
  };

  // This handler is triggered by "this.container.element".
  PreviewWindow.prototype._handle__closed = function(evt) {
    // kill itself when the parent app intends to close.
    this.kill();
  };

  /**
   * @exports PreviewWindow
   */
  exports.PreviewWindow = PreviewWindow;
})(window);