Pod::Spec.new do |s|
    s.name                       = 'Crypto-Swift'
    s.homepage                   = 'https://github.com/liujunliuhong/Crypto-Swift.git'
    s.summary                    = 'Cryptography in Swift.'
    s.description                = 'Cryptography functions and helpers for Swift implemented in Swift.'
    s.author                     = { 'liujunliuhong' => '1035841713@qq.com' }
    s.version                    = '1.0.0'
    s.source                     = { :git => 'https://github.com/liujunliuhong/Crypto-Swift.git', :tag => s.version.to_s }
    s.platform                   = :ios, '10.0'
    s.license                    = { :type => 'MIT', :file => 'LICENSE' }
    s.module_name                = 'Crypto.Swift'
    s.swift_version              = '5.0'
    s.ios.deployment_target      = '10.0'
    s.requires_arc               = true
    s.static_framework           = true
    
    s.source_files               = 'Sources/*.swift'
    s.dependency 'CryptoSwift'
    s.dependency 'libsecp256k1.ios'
    s.dependency 'libed25519.ios'
    
  end