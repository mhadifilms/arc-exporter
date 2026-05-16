# Homebrew formula. Lives in the dedicated tap repo `mhadifilms/homebrew-tap`.
# The hashes are placeholders; release.yml updates them automatically on each tag.
class ArcExporter < Formula
  include Language::Python::Virtualenv

  desc "Safely migrate Arc Browser profiles into other browsers"
  homepage "https://github.com/mhadifilms/arc-exporter"
  url "https://files.pythonhosted.org/packages/source/a/arc-exporter/arc_exporter-0.2.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  depends_on "python@3.12"

  resource "cryptography" do
    url "https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-42.0.5.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  resource "psutil" do
    url "https://files.pythonhosted.org/packages/source/p/psutil/psutil-5.9.8.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  resource "typer" do
    url "https://files.pythonhosted.org/packages/source/t/typer/typer-0.12.3.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/source/r/rich/rich-13.7.1.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  resource "keyring" do
    url "https://files.pythonhosted.org/packages/source/k/keyring/keyring-24.3.1.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  resource "platformdirs" do
    url "https://files.pythonhosted.org/packages/source/p/platformdirs/platformdirs-4.2.0.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  resource "httpx" do
    url "https://files.pythonhosted.org/packages/source/h/httpx/httpx-0.27.0.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  resource "pydantic" do
    url "https://files.pythonhosted.org/packages/source/p/pydantic/pydantic-2.6.4.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/arc-exporter --version")
  end
end
