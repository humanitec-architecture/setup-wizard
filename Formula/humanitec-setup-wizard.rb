# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class HumanitecSetupWizard < Formula
  desc ""
  homepage "https://github.com/humanitec-architecture/setup-wizard"
  version "0.13.4"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/humanitec-architecture/setup-wizard/releases/download/v0.13.4/setup-wizard_0.13.4_darwin_amd64.tar.gz"
      sha256 "0f7c281db1e84710be32410a6398b5f90e75db74f18fff225634a7c6b7b68cc0"

      def install
        bin.install "humanitec-setup-wizard"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/humanitec-architecture/setup-wizard/releases/download/v0.13.4/setup-wizard_0.13.4_darwin_arm64.tar.gz"
      sha256 "980de2605f7e511a18cd0620af52da61553d549ccd32f30835543be606d9d637"

      def install
        bin.install "humanitec-setup-wizard"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? and Hardware::CPU.is_64_bit?
      url "https://github.com/humanitec-architecture/setup-wizard/releases/download/v0.13.4/setup-wizard_0.13.4_linux_amd64.tar.gz"
      sha256 "58686030e09636706a4c484d6eff818ad3adda4d5d0fbda84b1c94221efb2667"
      def install
        bin.install "humanitec-setup-wizard"
      end
    end
    if Hardware::CPU.arm? and Hardware::CPU.is_64_bit?
      url "https://github.com/humanitec-architecture/setup-wizard/releases/download/v0.13.4/setup-wizard_0.13.4_linux_arm64.tar.gz"
      sha256 "43efc0916076df67cb66d4423da6affcfe98a7b03630760ebe22e75503c3857a"
      def install
        bin.install "humanitec-setup-wizard"
      end
    end
  end
end
