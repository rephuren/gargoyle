# frozen_string_literal: true

require "uri"

module Gargoyle
  Finding = Struct.new(:rule, :where, :sample, keyword_init: true)

  # Runs the rules over a request description: {path:, query:, body:, headers:, ua:}.
  class Detector
    MAX_SCAN = 8192
    MAX_FINDINGS = 20

    def initialize(rules = RULES)
      @rules = rules
    end

    def inspect_request(parts)
      views = views_for(parts)
      found = []
      @rules.each do |rule|
        rule.targets.each do |t|
          (views[t] || []).each do |text|
            m = text.match(rule.pattern)
            next unless m

            found << Finding.new(rule: rule, where: t, sample: m[0].to_s[0, 80])
            break
          end
        end
        break if found.size >= MAX_FINDINGS
      end
      found.first(MAX_FINDINGS)
    end

    # Decodes percent-escapes up to twice (double encoding is a common evasion) and keeps the raw form too.
    def self.variants(str)
      s = str.to_s.dup.force_encoding(Encoding::UTF_8).scrub("?")[0, MAX_SCAN]
      once = decode(s)
      twice = decode(once)
      [s, once, twice].uniq
    end

    def self.decode(str)
      URI.decode_www_form_component(str)
    rescue ArgumentError
      str
    end

    private

    def views_for(parts)
      {
        path: self.class.variants(parts[:path]),
        query: self.class.variants(parts[:query]),
        body: self.class.variants(parts[:body]),
        ua: self.class.variants(parts[:ua]),
        headers: (parts[:headers] || {}).values.flat_map { |v| self.class.variants(v) }
      }
    end
  end
end
