# frozen_string_literal: true

require "json"
require "cgi"

module Gargoyle
  # Summary of a JSON Lines log written by the middleware.
  class Report
    attr_reader :events, :bad_lines

    def self.from_file(path)
      lines = File.readlines(path, chomp: true)
      events = []
      bad = []
      lines.each_with_index do |l, i|
        next if l.strip.empty?

        ev = JSON.parse(l)
        ev.is_a?(Hash) ? events << ev : bad << i + 1
      rescue JSON::ParserError
        bad << i + 1
      end
      new(events, bad)
    end

    def initialize(events, bad_lines = [])
      @events = events
      @bad_lines = bad_lines
    end

    SEVERITY_RANK = { "info" => 0, "low" => 1, "medium" => 2, "high" => 3 }.freeze

    # A report with only the events at or above the given severity. Events with an unknown severity count as info.
    def at_least(severity)
      min = SEVERITY_RANK.fetch(severity.to_s) { raise ArgumentError, "unknown severity #{severity.inspect}, use #{SEVERITY_RANK.keys.join('/')}" }
      self.class.new(@events.select { |e| SEVERITY_RANK.fetch(e["severity"].to_s, 0) >= min }, @bad_lines)
    end

    def tally(key)
      @events.flat_map { |e| Array(e[key]) }.tally.sort_by { |k, v| [-v, k.to_s] }.to_h
    end

    def summary
      {
        events: @events.size,
        unparsable_lines: @bad_lines,
        by_severity: tally("severity"),
        by_rule: tally("rules"),
        by_action: tally("action"),
        owasp: tally("owasp"),
        attack: tally("attack"),
        top_ips: tally("ip").first(10).to_h,
        top_paths: tally("path").first(10).to_h,
        honeytoken_uses: @events.count { |e| Array(e["rules"]).include?("honeytoken-used") }
      }
    end

    def to_text
      s = summary
      out = ["events #{s[:events]} · honeytoken uses #{s[:honeytoken_uses]}"]
      out << "  #{s[:unparsable_lines].size} unparsable line(s), first: line #{s[:unparsable_lines].first}" unless s[:unparsable_lines].empty?
      { "severity" => :by_severity, "rules" => :by_rule, "actions" => :by_action, "OWASP" => :owasp, "ATT&CK (as tagged by rules)" => :attack, "top IPs" => :top_ips, "top paths" => :top_paths }.each do |title, key|
        next if s[key].empty?

        out << "#{title}: " + s[key].map { |k, v| "#{k} x#{v}" }.join(", ")
      end
      out.join("\n")
    end

    def to_html
      s = summary
      rows = s.reject { |k, _| %i[events unparsable_lines honeytoken_uses].include?(k) }.map do |k, h|
        "<h2>#{CGI.escapeHTML(k.to_s)}</h2><table>" + h.map { |a, b| "<tr><td>#{CGI.escapeHTML(a.to_s)}</td><td>#{b}</td></tr>" }.join + "</table>"
      end
      "<!doctype html><meta charset=utf-8><title>gargoyle</title><style>body{background:#000;color:#e8e8e8;font:14px Menlo,monospace;margin:2em}td{padding:.2em 1em}h2{color:#b3000f}</style>" \
        "<h1>gargoyle</h1><p>events #{s[:events]} · honeytoken uses #{s[:honeytoken_uses]}</p>#{rows.join}"
    end
  end
end
