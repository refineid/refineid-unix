# pam_pkcs11 from the OpenSC project: the PAM module that logs a user in
# with a certificate and key on a PKCS#11 token. Built against OpenSSL,
# without debug code, LDAP, cURL, PC/SC event tools or HTML
# documentation; the card is reached only through the PKCS#11 module its
# configuration names.
{
  lib,
  stdenv,
  fetchFromGitHub,
  autoreconfHook,
  pkg-config,
  gettext,
  flex,
  openssl,
  pam,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "pam_pkcs11";
  version = "0.6.14";

  src = fetchFromGitHub {
    owner = "OpenSC";
    repo = "pam_pkcs11";
    tag = "pam_pkcs11-${finalAttrs.version}";
    hash = "sha256-Y0dhYjQTPi63GJWjFOASqfYuVaMaaiPMwvul6UzL9S0=";
  };

  # Without DEBUG, debug.h declares neither set_debug_level nor
  # get_debug_level, which debug.c defines and the mappers call either
  # way; the declarations take the place of the header's warning.
  postPatch = ''
    substituteInPlace src/common/debug.h \
      --replace-fail '#warning "Debugging is completely disabled!"' \
        'void set_debug_level(int level); int get_debug_level(void);'
  '';

  nativeBuildInputs = [
    autoreconfHook
    pkg-config
    gettext
    flex
  ];

  buildInputs = [
    openssl
    pam
  ];

  configureFlags = [
    "--disable-debug"
    "--without-ldap"
    "--without-curl"
    "--without-nss"
    "--without-pcsclite"
    "--without-docbook"
  ];

  meta = {
    description = "PAM module for login with a certificate on a PKCS#11 token";
    homepage = "https://github.com/OpenSC/pam_pkcs11";
    license = lib.licenses.lgpl21Plus;
    platforms = lib.platforms.linux;
  };
})
