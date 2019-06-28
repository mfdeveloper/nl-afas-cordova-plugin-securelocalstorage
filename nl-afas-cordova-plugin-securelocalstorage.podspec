#
# Be sure to run `pod lib lint cordova-plugin-ionic-webview.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'nl-afas-cordova-plugin-securelocalstorage'
  s.version          = '0.1.44'
  s.summary          = 'This plugin will store local data encrypted using the IOS keychain from original repo version tag 0.1.14'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
This plugin will store local data encrypted using the IOS keychain
                       DESC

  s.homepage         = 'https://github.com/adelmojunnior/nl-afas-cordova-plugin-securelocalstorage'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Adelmo Júnior' => 'adelmojunnior@gmail.com', 'Michel Felipe' => 'mfelipeof@gmail.com' }
  s.source           = { :git => 'https://github.com/adelmojunnior/nl-afas-cordova-plugin-securelocalstorage.git', :tag => "v#{s.version.to_s}" }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '8.0'

  # s.source_files = 'cordova-plugin-ionic-webview/Classes/**/*'
  s.source_files = 'src/ios/*'

  # s.exclude_files = 'src/www'

  s.platform = :ios, '8.0'

  s.requires_arc = true

  # s.resource_bundles = {
  #   'cordova-plugin-ionic-webview' => ['cordova-plugin-ionic-webview/Assets/*.png']
  # }

  s.public_header_files = 'src/ios/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  s.dependency 'Cordova', '>= 4.3.0'
end
