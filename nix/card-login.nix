# Card login: pam_pkcs11 (OpenSC project) over the RefineID PKCS#11
# module, for console login, the display managers that stack on
# `login`, sudo, the KDE lock screen and GDM's smartcard flow.
#
#   programs.refineid.cardLogin = {
#     enable = true;
#     users.alice = [ "sha256: <fingerprint from refineid card>" ];
#   };
{ pamPkcs11Package }:
{
  config,
  lib,
  pkgs,
  utils,
  ...
}:
let
  cfg = config.programs.refineid;
  login = cfg.cardLogin;
  pamPkcs11 = pamPkcs11Package pkgs;
  pamPkcs11Module = "${pamPkcs11}/lib/security/pam_pkcs11.so";
  # The map from certificate digest to login name pam_pkcs11 reads.
  digestMapping = "pam_pkcs11/digest_mapping";
  # A SHA-256 digest: 32 bytes, two hex digits each.
  fingerprintBytes = 32;
  hexDigitsPerByte = 2;
  fingerprintDigits = fingerprintBytes * hexDigitsPerByte;
  # The prefix `refineid card` prints before the fingerprint.
  fingerprintLabel = "sha256:";
  # The fingerprint's hex digits, uppercase, with the label, colons and
  # white space removed.
  fingerprintHex =
    fingerprint:
    lib.toUpper (
      builtins.replaceStrings [ ":" " " "\t" ] [ "" "" "" ] (
        lib.removePrefix fingerprintLabel (lib.toLower (lib.trim fingerprint))
      )
    );
  validFingerprint =
    fingerprint:
    builtins.match "[0-9A-F]{${toString fingerprintDigits}}" (fingerprintHex fingerprint) != null;
  # The colon form pam_pkcs11's digest mapper compares: AA:BB:...:FF.
  colonFingerprint =
    fingerprint:
    let
      hex = fingerprintHex fingerprint;
    in
    lib.concatMapStringsSep ":" (
      index: builtins.substring (index * hexDigitsPerByte) hexDigitsPerByte hex
    ) (lib.range 0 (fingerprintBytes - 1));
  # A login name pam_pkcs11 can carry on a map line.
  validLogin = name: builtins.match "[A-Za-z0-9._][A-Za-z0-9._-]*[$]?" name != null;
  invalidFingerprints = lib.concatLists (
    lib.mapAttrsToList (
      name: fingerprints:
      map (fingerprint: "${name}: ${fingerprint}") (lib.filter (f: !validFingerprint f) fingerprints)
    ) login.users
  );
  invalidLogins = lib.filter (name: !validLogin name) (lib.attrNames login.users);
  pamConfig = pkgs.writeText "pam_pkcs11.conf" ''
    pam_pkcs11 {
      use_pkcs11_module = refineid;
      pkcs11_module refineid {
        module = ${cfg.package}/lib/librefineid_pkcs11.so;
        # The card's signature over a random challenge is checked against
        # the certificate; no chain, validity or revocation check.
        cert_policy = signature;
      }
      use_mappers = digest;
      mapper digest {
        module = internal;
        algorithm = "sha256";
        mapfile = file:///etc/${digestMapping};
      }
    }
  '';
  pamConfigArgument = "config_file=${pamConfig}";
  # The card rule's place after the slot nixpkgs keeps for its own
  # token rule (pam_p11), which stays disabled; nixpkgs spaces its rules
  # 100 apart.
  cardRuleOffset = 10;
  # The lowest uid gdm-autologin admits, as nixpkgs sets it.
  firstNormalUid = 1000;
  # The PAM services that authenticate a local user by password and take
  # the card first: `login` (console, SDDM and gdm-password substack
  # it), sudo, and the KDE lock screen, which answers prompts only on
  # `kde` (its `kde-smartcard` service gets no PIN entry).
  cardServices = [
    "login"
  ]
  ++ lib.optional (config.security.sudo.enable || config.security.sudo-rs.enable) "sudo"
  ++ lib.optional config.security.sudo-rs.enable "sudo-i"
  ++ lib.optional config.services.desktopManager.plasma6.enable "kde";
in
{
  options.programs.refineid.cardLogin = {
    enable = lib.mkEnableOption ''
      login with the card through pam_pkcs11 for console login, SDDM,
      GDM, sudo and the KDE lock screen. A card in the reader asks for
      PIN 1; without a card the password is asked as before. The
      certificate's chain, validity period and revocation are not
      checked: the map line in {option}`programs.refineid.cardLogin.users`
      is the authorization
    '';

    users = lib.mkOption {
      type = lib.types.attrsOf (lib.types.listOf lib.types.str);
      default = { };
      example = lib.literalExpression ''
        {
          alice = [ "sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ];
        }
      '';
      description = ''
        Login names, each with the SHA-256 fingerprints of the
        authentication certificates that log in as it. A fingerprint is
        64 hex digits in either case, as `refineid card` prints it
        (`sha256: ...`) or with colons between bytes.
      '';
    };
  };

  config = lib.mkIf (cfg.enable && login.enable) {
    assertions = [
      {
        assertion = login.users != { };
        message = "programs.refineid.cardLogin.users names no login.";
      }
      {
        assertion = invalidFingerprints == [ ];
        message = "programs.refineid.cardLogin.users: not ${toString fingerprintDigits} hex digits: ${lib.concatStringsSep ", " invalidFingerprints}";
      }
      {
        assertion = invalidLogins == [ ];
        message = "programs.refineid.cardLogin.users: not a login name: ${lib.concatStringsSep ", " invalidLogins}";
      }
    ];

    environment.etc.${digestMapping} = {
      mode = "0644";
      user = "root";
      group = "root";
      text = lib.concatStrings (
        lib.mapAttrsToList (
          name: fingerprints:
          lib.concatMapStrings (fingerprint: "${colonFingerprint fingerprint} -> ${name}\n") fingerprints
        ) login.users
      );
    };

    # The card rule sits in the token slot of each stack, before every
    # password rule: a card in the reader asks for PIN 1, no card falls
    # through to the password.
    #
    # WARNING (security.pam.services.<name>.rules, nixpkgs): This option and
    # its suboptions are experimental and subject to breaking changes
    # without notice. If you use this option in your system configuration,
    # you will need to manually monitor this module for any changes.
    # Otherwise, failure to adjust your configuration properly could lead
    # to you being locked out of your system, or worse, your system could
    # be left wide open to attackers.
    security.pam.services = lib.mkMerge [
      (lib.genAttrs cardServices (service: {
        rules.auth.refineid_card = {
          control = "sufficient";
          modulePath = pamPkcs11Module;
          args = [ pamConfigArgument ];
          order = config.security.pam.services.${service}.rules.auth.p11.order + cardRuleOffset;
        };
      }))

      # GDM's smartcard flow authenticates through its own service, which
      # waits for a card and accepts nothing else; account, password and
      # session are gdm-password's.
      (lib.mkIf config.services.displayManager.gdm.enable {
        gdm-smartcard = {
          useDefaultRules = false;
          rules = {
            auth = utils.pam.autoOrderRules [
              {
                name = "nologin";
                control = "requisite";
                modulePath = "${config.security.pam.package}/lib/security/pam_nologin.so";
              }
              {
                name = "env";
                control = "required";
                modulePath = "${config.security.pam.package}/lib/security/pam_env.so";
                settings.conffile = "/etc/pam/environment";
                settings.readenv = 0;
              }
              {
                name = "gdm-normal-user";
                control = "required";
                modulePath = "${config.security.pam.package}/lib/security/pam_succeed_if.so";
                settings.quiet = true;
                args = lib.mkBefore [
                  "uid"
                  ">="
                  (toString firstNormalUid)
                ];
              }
              {
                name = "refineid_card";
                control = "required";
                modulePath = pamPkcs11Module;
                args = [
                  pamConfigArgument
                  "wait_for_card"
                  "card_only"
                ];
              }
            ];
            account = utils.pam.autoOrderRules [
              {
                name = "login";
                control = "include";
                modulePath = "login";
              }
            ];
            password = utils.pam.autoOrderRules [
              {
                name = "login";
                control = "substack";
                modulePath = "login";
              }
            ];
            session = utils.pam.autoOrderRules [
              {
                name = "login";
                control = "include";
                modulePath = "login";
              }
            ];
          };
        };
      })
    ];
  };
}
