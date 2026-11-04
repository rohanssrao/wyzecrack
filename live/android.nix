let
  pkgs = import <nixpkgs> { config = { android_sdk.accept_license = true; allowUnfree = true; }; };
  sdk = pkgs.androidenv.composeAndroidPackages {
    platformVersions = [ "34" ];
    includeEmulator = true;
    includeSystemImages = true;
    systemImageTypes = [ "google_apis" ];
    abiVersions = [ "x86_64" ];
    includeNDK = false;
  };
in sdk.androidsdk
