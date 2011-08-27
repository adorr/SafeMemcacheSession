require 'rubygems'
require 'rake'
require 'spec/rake/spectask'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "safe_memcache_session_store"
    gem.summary = %Q{Rails session store class}
    gem.email = "drewdorr@gmail.com"
    gem.homepage = "http://example.com"
    gem.authors = ["Andrew Dorr"]
    gem.files = Dir["README.md", "lib/**/*"]
    
    gem.add_dependency 'actionpack',  '~> 3.0'
  end
  
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end