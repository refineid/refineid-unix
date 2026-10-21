# NixOS module: everything a FINEID card user needs, in one option.
#
#   programs.refineid.enable = true;
#
# gives you the refineid CLI, the RefineID GUI, the PKCS#11
# module registered system-wide for p11-kit consumers, the pcscd
# smart-card daemon, and (when Firefox is managed by NixOS) automatic
# Firefox card-login integration via the SecurityDevices policy.
{ refineidPackage }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.refineid;
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

    # System-wide p11-kit registration: OpenSSL (pkcs11-provider),
    # GnuTLS, and OpenSSH discover the card through p11-kit.
    environment.etc."pkcs11/modules/refineid.module".source =
      "${cfg.package}/share/p11-kit/modules/refineid.module";

    # Firefox does not consult p11-kit on NixOS; the enterprise
    # policy loads the module directly.
    programs.firefox.policies = lib.mkIf cfg.firefoxIntegration {
      SecurityDevices.Add = {
        "RefineID" = "${cfg.package}/lib/librefineid_pkcs11.so";
      };
    };

    # Reload running desktop environments' application caches upon system activation,
    # so newly installed or upgraded RefineID appears immediately in menus without
    # requiring user logout or manual panel restarts.
    system.activationScripts.refineid-desktop = lib.stringAfter [ "etc" ] ''
      # Update desktop database for the system profile
      if [ -d /run/current-system/sw/share/applications ]; then
        ${pkgs.desktop-file-utils}/bin/update-desktop-database -q /run/current-system/sw/share/applications 2>/dev/null || true
      fi

      # Refresh running XFCE panels for active user sessions so in-memory menu caches
      # pick up the new or updated .desktop entries immediately.
      for session_pid in $( ${pkgs.procps}/bin/pgrep -f '[x]fce4-session' 2>/dev/null || true ); do
        if [ -r "/proc/$session_pid/environ" ]; then
          uid=$(stat -c '%u' "/proc/$session_pid" 2>/dev/null || continue)
          user=$(id -nu "$uid" 2>/dev/null || continue)
          display=$(tr '\0' '\n' < "/proc/$session_pid/environ" 2>/dev/null | grep '^DISPLAY=' | cut -d= -f2-)
          bus="/run/user/$uid/bus"
          if [ -n "$display" ] && [ -e "$bus" ]; then
            if ${pkgs.procps}/bin/pgrep -u "$user" -f '[x]fce4-panel' >/dev/null 2>&1; then
              su - "$user" -c "DISPLAY='$display' DBUS_SESSION_BUS_ADDRESS='unix:path=$bus' xfce4-panel -r" 2>/dev/null || true
            else
              su - "$user" -c "DISPLAY='$display' DBUS_SESSION_BUS_ADDRESS='unix:path=$bus' nohup xfce4-panel >/dev/null 2>&1 &" 2>/dev/null || true
            fi
          fi
        fi
      done
    '';
  };
}
