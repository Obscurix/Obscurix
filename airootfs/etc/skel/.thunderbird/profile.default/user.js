// User.js file for Thunderbird hardening.

// Explanation of most settings can be found here https://theprivacyguide1.github.io/about_config.html.
// Explanations for other settings are at the link at the bottom.

// General privacy settings
user_pref("media.peerconnection.enabled", false);
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("browser.sessionstore.max_tabs_undo", 0);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("geo.enabled", false);
user_pref("media.eme.enabled", false);
user_pref("media.gmp-widevinecdm.enabled", false);
user_pref("media.navigator.enabled", false);
user_pref("webgl.disabled", true);
user_pref("browser.browser.sessionstore.privacy_level", 2); 
user_pref("network.IDN_show_punycode", true);
user_pref("extensions.blocklist.url", "https://blocklists.settings.services.mozilla.com/v1/blocklist/3/%20/%20/");
user_pref("dom.event.contextmenu.enabled", false);
user_pref("network.http.referer.spoofSource", true);
user_pref("privacy.trackingprotection.enabled", false); // (Tracking protection is useless with UBO)

// Always use private browsing
user_pref("browser.privatebrowsing.autostart", true);

// Cookie settings
user_pref("network.cookie.cookieBehavior", 1); // (Block third-party cookies. Set to "0" to block all cookies.)
user_pref("network.cookie.lifetimePolicy", 2);

// HTTP referer settings
user_pref("network.http.referer.trimmingPolicy", 2);
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

// Disable location related settings
user_pref("geo.wifi.uri", "");
user_pref("browser.search.geoip.url", "");

// Disable caching
user_pref("browser.cache.offline.enable", false);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.disk_cache_ssl", false);
user_pref("browser.cache.memory.enable", false);
user_pref("browser.cache.offline.enable", false);

// Disable prefetch
user_pref("network.predictor.enabled", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("network.http.speculative-parallel-limit", 0);

// Disable pocket
user_pref("extensions.pocket.enabled", false);
user_pref("extensions.pocket.site", "");
user_pref("extensions.pocket.oAuthConsumerKey", "");
user_pref("extensions.pocket.api", "");

// Disable telemetry
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.hybridContent.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("toolkit.telemetry.server", "");
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("network.allow-experiments", false);
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);
user_pref("toolkit.crashreporter.infoURL", "");
user_pref("datareporting.healthreport.infoURL", "");
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.firstRunURL", ""); 
user_pref("toolkit.telemetry.cachedClientID", "");
user_pref("toolkit.telemetry.infoURL", "");
pref("toolkit.telemetry.prompted", 2);
pref("toolkit.telemetry.rejected", true);

// Disable possible telemetry
user_pref("browser.aboutHomeSnippets.updateUrL", "");
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.startup.homepage_override.buildID", "");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("startup.homepage_override_url", "");
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);

// Disable Google safebrowsing
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.provider.google4.dataSharing.enabled", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.reportURL", "");
user_pref("browser.safebrowsing.provider.google4.reportPhishMistakeURL", "");
user_pref("browser.safebrowsing.provider.google4.reportMalwareMistakeURL", "");
user_pref("browser.safebrowsing.provider.google4.lists", "");
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.dataSharingURL", "");
user_pref("browser.safebrowsing.provider.google4.dataSharing.enabled", false);
user_pref("browser.safebrowsing.provider.google4.advisoryURL", "");
user_pref("browser.safebrowsing.provider.google4.advisoryName", "");
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google.reportURL", "");
user_pref("browser.safebrowsing.provider.google.reportPhishMistakeURL", "");
user_pref("browser.safebrowsing.provider.google.reportMalwareMistakeURL", "");
user_pref("browser.safebrowsing.provider.google.pver", "");
user_pref("browser.safebrowsing.provider.google.lists", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google.advisoryURL", "");
user_pref("browser.safebrowsing.downloads.remote.url", "");

// Set default language to en-US (most common).
user_pref("intl.accept_languages", "en-US");

// Prevent accessibility services from accessing the browser
user_pref("accessibility.force_disabled", 1);

// Request English versions of web pages for enhanced privacy
user_pref("privacy.spoof_english", 2);

// Disable captive portal
user_pref("network.captive-portal-service.enabled", false);
user_pref("captivedetect.canonicalURL", "");

// Other
user_pref("browser.send_pings.require_same_host", true);
user_pref("network.dnsCacheEntries", 100);
user_pref("places.history.enabled", false);
user_pref("browser.formfill.enable", false);

// Disable JavaScript.
user_pref("javascript.enabled", false);

// Settings for enhanced security. See https://2019.www.torproject.org/projects/torbrowser/design/#other-security.
user_pref("gfx.font_rendering.graphite.enabled", false);
user_pref("javascript.options.ion", false);
user_pref("javascript.options.native_regexp", false);
user_pref("javascript.options.baselinejit", false);
user_pref("mathml.disabled", true);
user_pref("gfx.font_rendering.opentype_svg.enabled", false);
user_pref("svg.disabled", true);

// Tor Stream Isolation.
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 9050);
user_pref("network.proxy.socks_remote_dns", true);

// Disable mail indexing
user_pref("mailnews.database.global.indexer.enabled", false);

// Disable chat
user_pref("mail.chat.enabled", false);

// Hide the "Know your rights" message
user_pref("mail.rights.version", 1);

