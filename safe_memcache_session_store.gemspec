# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{safe_memcache_session_store}
  s.version = "2.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Andrew Dorr"]
  s.date = %q{2011-08-27}
  s.email = %q{drewdorr@gmail.com}
  s.extra_rdoc_files = [
    "README.md"
  ]
  s.files = [
    "README.md",
     "lib/memcache_session_store.rb",
     "lib/memcache_session_store/memcache.rb"
  ]
  s.homepage = %q{http://www.andrewdorr.com}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.summary = %q{Rails safe session store class implemented for Memcache}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<actionpack>, ["~> 3.0"])
    else
      s.add_dependency(%q<actionpack>, ["~> 3.0"])
    end
  else
    s.add_dependency(%q<actionpack>, ["~> 3.0"])
  end
end

