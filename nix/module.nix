# NixOS module: everything a FINEID card user needs, in one option.
#
#   programs.refineid.enable = true;
#
# gives you the refineid CLI, the RefineID GUI, the PKCS#11
# module registered system-wide for p11-kit consumers, the pcscd
# smart-card daemon, Chromium card login through the user's NSS
# database, and (when Firefox is managed by NixOS) Firefox card login
# via the SecurityDevices policy.
{ refineidPackage }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.refineid;
  modulePath = "/run/current-system/sw/lib/librefineid_pkcs11.so";
  # The login-time NSS registration shared with the Debian package,
  # with the NSS tools it calls put on its PATH.
  browserToken = pkgs.writeShellScript "refineid-browser-token" ''
    export PATH=${
      lib.makeBinPath [
        pkgs.nss.tools
        pkgs.gnugrep
        pkgs.coreutils
      ]
    }:$PATH
    ${builtins.replaceStrings [ "@MODULE@" ] [ modulePath ] (
      builtins.readFile ../packaging/refineid-browser-token
    )}
  '';
in
{
  options.programs.refineid = {
    enable = lib.mkEnableOption "RefineID Finnish identity card middleware";

    package = lib.mkOption {
      type = lib.types.package;
      default = refineidPackage pkgs;
      defaultText = lib.literalExpression "refineid packaged from this flake";
      description = "The RefineID package to install.";
    };

    firefoxIntegration = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Register the RefineID PKCS#11 module in Firefox through the
        SecurityDevices enterprise policy, so card login works with no
        per-user setup. Takes effect when Firefox is enabled through
        {option}`programs.firefox.enable`; a Firefox installed some
        other way needs the manual registration described in
        doc/install-nixos.md.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # The PC/SC smart-card daemon (with the CCID reader driver).
    services.pcscd.enable = true;

    # Allow local users to access the PC/SC daemon without polkit authentication prompts,
    # enabling browser PKCS#11 modules (Firefox, Chrome) and CLI tools to access card readers.
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        if (action.id == "org.debian.pcsc-lite.access_pcsc" ||
            action.id == "org.debian.pcsc-lite.access_card") {
          return polkit.Result.YES;
        }
      });
    '';

    # System-wide p11-kit registration: OpenSSL (pkcs11-provider),
    # GnuTLS, and OpenSSH discover the card through p11-kit.
    environment.etc."pkcs11/modules/refineid.module".source =
      "${cfg.package}/share/p11-kit/modules/refineid.module";

    # Firefox does not consult p11-kit on NixOS; the enterprise
    # policy loads the module directly. Use the stable system-profile
    # path so existing registrations survive updates and garbage collection.
    programs.firefox.policies = lib.mkIf cfg.firefoxIntegration {
      SecurityDevices.Add = {
        "RefineID" = modulePath;
      };
    };

    # Chromium and every other NSS program read ~/.pki/nssdb, which no
    # system policy reaches: a desktop autostart entry gives the
    # signed-in user's database the module at each login.
    environment.etc."xdg/autostart/refineid-browser-token.desktop".text =
      builtins.replaceStrings [ "@EXEC@" ] [ "${browserToken}" ] (
        builtins.readFile ../packaging/refineid-browser-token.desktop
      );

    # Reload running desktop environments' application caches upon system activation,
    # so newly installed or upgraded RefineID appears immediately in menus without
    # requiring user logout or manual panel restarts.
    system.activationScripts.refineid-desktop = lib.stringAfter [ "etc" ] ''
      # Update desktop database for the system profile
      if [ -d /run/current-system/sw/share/applications ]; then
        ${pkgs.desktop-file-utils}/bin/update-desktop-database -q /run/current-system/sw/share/applications 2>/dev/null || true
      fi

      # Migrate any existing Firefox profile pkcs11 registrations pointing to
      # transient /nix/store paths to the stable system-wide path.
      for p11_file in /home/*/.config/mozilla/firefox/*/pkcs11.txt /home/*/.mozilla/firefox/*/pkcs11.txt; do
        if [ -f "$p11_file" ]; then
          ${pkgs.gnused}/bin/sed -i 's|library=/nix/store/[^/]*-refineid-[^/]*/lib/librefineid_pkcs11.so|library=/run/current-system/sw/lib/librefineid_pkcs11.so|g' "$p11_file" 2>/dev/null || true
        fi
      done

      # Refresh running XFCE panels for active user sessions so in-memory menu caches
      # pick up the new or updated .desktop entries immediately.
      for session_pid in $( ${pkgs.procps}/bin/pgrep -f '[x]fce4-session' 2>/dev/null || true ); do
        if [ -r "/proc/$session_pid/environ" ]; then
          uid=$(stat -c '%u' "/proc/$session_pid" 2>/dev/null || continue)
          user=$(id -nu "$uid" 2>/dev/null || continue)
          display=$(tr '\0' '\n' < "/proc/$session_pid/environ" 2>/dev/null | grep '^DISPLAY=' | cut -d= -f2-)
          bus="/run/user/$uid/bus"
          if [ -n "$display" ] && [ -e "$bus" ]; then
            su - "$user" -c "DISPLAY='$display' DBUS_SESSION_BUS_ADDRESS='unix:path=$bus' ${pkgs.procps}/bin/pkill -u '$user' -x xfce4-panel 2>/dev/null || true; sleep 1; nohup xfce4-panel >/dev/null 2>&1 &" 2>/dev/null || true
          fi
        fi
      done
    '';
  };
}
