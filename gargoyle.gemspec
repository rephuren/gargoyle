# frozen_string_literal: true

require_relative "lib/gargoyle/version"

Gem::Specification.new do |s|
  s.name = "gargoyle"
  s.version = Gargoyle::VERSION
  s.summary = "Rack middleware that watches a web app for scanners and injection attempts and can serve decoy pages"
  s.authors = ["misxnthropy"]
  s.license = "MIT"
  s.required_ruby_version = ">= 3.1"
  s.files = Dir["lib/**/*.rb", "bin/*", "README.md", "LICENSE"]
  s.bindir = "bin"
  s.executables = ["gargoyle"]
  s.add_dependency "rack", ">= 2.2"
end
