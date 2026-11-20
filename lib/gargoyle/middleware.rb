# frozen_string_literal: true

require "json"
require "time"
require "rack"

module Gargoyle
  # Rack middleware. Modes:
  #   :monitor (default) only logs, the request always reaches the app;
  #   :trap    also answers a few decoy paths (/.env, /.git/config, /wp-login.php) itself;
  #   :block   also answers 403 to requests whose worst finding is at or above `block_at`.
  class Middleware
    HEADER_SKIP = %w[HTTP_AUTHORIZATION HTTP_COOKIE HTTP_PROXY_AUTHORIZATION].freeze

    def initialize(app, mode: :monitor, log: nil, block_at: :high, max_body: 8192, trusted_proxies: [], honeytokens: Honeytokens.new, detector: Detector.new, on_event: nil)
      raise ArgumentError, "mode must be :monitor, :trap or :block" unless %i[monitor trap block].include?(mode)
      raise ArgumentError, "block_at must be :low, :medium or :high" unless SEVERITY.key?(block_at)

      @app = app
      @mode = mode
      @log = log
      @block_at = block_at
      @max_body = max_body
      @trusted = trusted_proxies
      @tokens = honeytokens
      @detector = detector
      @decoys = Decoys.new(honeytokens)
      @on_event = on_event
      @mutex = Mutex.new
    end

    def honeytokens
      @tokens
    end

    def call(env)
      parts = describe(env)
      findings = safely { @detector.inspect_request(parts) } || []
      token_used = safely { @tokens.used_in?([parts[:path], parts[:query], parts[:body], parts[:ua], *parts[:headers].values]) }
      worst = worst_severity(findings, token_used)

      response = nil
      action = :logged
      if @mode != :monitor && (decoy = @decoys.respond(parts[:path])) && @mode == :trap
        response = decoy
        action = :decoy
      elsif @mode == :block && worst && SEVERITY[worst] >= SEVERITY[@block_at]
        response = [403, { "content-type" => "text/plain" }, ["forbidden\n"]]
        action = :blocked
      end
      record(env, parts, findings, token_used, worst, action) if worst || action == :decoy
      response || @app.call(env)
    end

    private

    def describe(env)
      headers = env.select { |k, v| k.start_with?("HTTP_") && !HEADER_SKIP.include?(k) && v.is_a?(String) }
      {
        method: env["REQUEST_METHOD"].to_s,
        path: env["PATH_INFO"].to_s,
        query: env["QUERY_STRING"].to_s,
        ua: env["HTTP_USER_AGENT"].to_s,
        headers: headers,
        body: read_body(env)
      }
    end

    # Reads at most max_body bytes and rewinds, so the application still sees the whole body.
    def read_body(env)
      input = env["rack.input"]
      return "" unless input && %w[POST PUT PATCH].include?(env["REQUEST_METHOD"])
      return "" unless input.respond_to?(:rewind)

      text = input.read(@max_body).to_s
      input.rewind
      text
    rescue StandardError
      ""
    end

    def client_ip(env)
      remote = env["REMOTE_ADDR"].to_s
      xff = env["HTTP_X_FORWARDED_FOR"].to_s
      return remote unless @trusted.include?(remote) && !xff.empty?

      hops = xff.split(",").map(&:strip).reject(&:empty?)
      hops.reverse.find { |h| !@trusted.include?(h) } || remote
    end

    def worst_severity(findings, token_used)
      return :high if token_used

      findings.map { |f| f.rule.severity }.max_by { |s| SEVERITY[s] }
    end

    def record(env, parts, findings, token_used, worst, action)
      rule_ids = findings.map { |f| f.rule.id }
      rule_ids << "honeytoken-used" if token_used
      event = {
        ts: Time.now.utc.iso8601(3),
        ip: client_ip(env),
        method: parts[:method],
        path: parts[:path][0, 300],
        query: parts[:query][0, 300],
        ua: parts[:ua][0, 200],
        severity: worst&.to_s || "info",
        action: action.to_s,
        rules: rule_ids.uniq,
        owasp: findings.map { |f| f.rule.owasp }.uniq,
        attack: (findings.map { |f| f.rule.attack } + (token_used ? ["T1078"] : [])).uniq,
        samples: findings.map { |f| { rule: f.rule.id, where: f.where.to_s, sample: f.sample } }.first(5)
      }
      write(event)
      safely { @on_event&.call(event) }
    end

    def write(event)
      return unless @log

      @mutex.synchronize do
        if @log.respond_to?(:puts)
          @log.puts(JSON.generate(event))
          @log.flush if @log.respond_to?(:flush)
        else
          File.open(@log.to_s, "a") { |f| f.puts(JSON.generate(event)) }
        end
      end
    rescue StandardError
      nil # a full disk or a closed log must never take the application down
    end

    def safely
      yield
    rescue StandardError
      nil
    end
  end
end
