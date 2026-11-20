# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "minitest/autorun"
require "stringio"
require "gargoyle"

module Helpers
  def app
    ->(env) { [200, { "content-type" => "text/plain" }, [env["rack.input"] ? env["rack.input"].read.to_s : "ok"]] }
  end

  def build(**opts)
    @log = StringIO.new
    Gargoyle::Middleware.new(app, log: @log, **opts)
  end

  def events
    @log.string.lines.map { |l| JSON.parse(l) }
  end

  def detect(**parts)
    Gargoyle::Detector.new.inspect_request({ path: "/", query: "", body: "", ua: "Mozilla/5.0", headers: {} }.merge(parts)).map { |f| f.rule.id }
  end
end
