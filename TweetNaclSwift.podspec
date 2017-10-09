Pod::Spec.new do |spec|
  spec.name = "TweetNaclSwift"
  spec.version = "1.0.0"
  spec.summary = "TweetNacl wrapper library written on Swift."
  spec.homepage = "https://github.com/bitmark-inc/tweetnacl-swiftwrap"
  spec.license = { type: 'MIT', file: 'LICENSE' }
  spec.authors = { "Bitmark Inc" => 'support@bitmark.com' }
  spec.social_media_url = "https://twitter.com/bitmarkinc"

  spec.platform = :ios, "10.0"
  spec.requires_arc = true
  spec.source = { git: "https://github.com/bitmark-inc/tweetnacl-swiftwrap.git", tag: "v#{spec.version}", submodules: true }
  spec.source_files = "TweetnaclSwift/**/*.{h,swift,c}"
  spec.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/TweetNaclSwift/TweetnaclSwift/Dependencies' }
  spec.preserve_paths = 'TweetnaclSwift/Dependencies/module.map'
end
