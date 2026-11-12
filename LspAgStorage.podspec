Pod::Spec.new do |s|
  s.name             = 'LspAgStorage'
  s.version          = '0.1.0'
  s.summary          = 'S3-compatible object storage uploads for iOS.'
  s.homepage         = 'https://github.com/ZMsQRT/LspAgStorage'
  s.license          = { :type => 'Proprietary', :text => 'Copyright Moven. All rights reserved.' }
  s.author           = 'Moven'
  s.source           = { :git => 'https://github.com/ZMsQRT/LspAgStorage.git', :tag => s.version.to_s }
  s.platform         = :ios, '17.0'
  s.swift_version    = '6.0'
  s.source_files     = 'MovenS3Uploader.swift'
  s.frameworks       = 'Foundation', 'CryptoKit'
  s.static_framework = true

  s.test_spec 'Tests' do |tests|
    tests.source_files = 'LspAgStorageTests.swift'
  end
end
