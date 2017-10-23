Pod::Spec.new do |s|
  s.name         = "TweetNacl"
  s.version      = "1.0.1"
  s.summary      = "TweetNacl wrapper library written in Swift."
  s.description  = <<-DESC
    A Swift wrapper for TweetNacl C library
  DESC
  s.homepage     = "https://github.com/bitmark-inc/tweetnacl-swiftwrap"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Bitmark Inc" => "support@bitmark.com" }
  s.social_media_url   = "https://twitter.com/bitmarkinc"
  s.ios.deployment_target = "8.0"
  s.osx.deployment_target = "10.9"
  s.watchos.deployment_target = "2.0"
  s.tvos.deployment_target = "9.0"
  s.source       = { :git => "https://github.com/bitmark-inc/tweetnacl-swiftwrap.git", :tag => s.version }
  s.source_files  = "Sources/**/*"
  s.frameworks  = "Foundation"
  s.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/TweetNacl/Sources' }
end
