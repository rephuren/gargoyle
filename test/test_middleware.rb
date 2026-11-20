# frozen_string_literal: true

require_relative "test_helper"
require "rack/mock"

class TestMiddleware < Minitest::Test
  include Helpers

  def request(mw, method, path, **env)
    Rack::MockRequest.new(mw).request(method, path, { "REMOTE_ADDR" => "203.0.113.5" }.merge(env))
  end

  def test_monitor_mode_never_changes_the_response
    mw = build
    r = request(mw, "GET", "/.env")
    assert_equal 200, r.status
    assert_equal "ok", r.body
    assert_equal ["sensitive-path"], events.first["rules"]
    assert_equal "logged", events.first["action"]
  end

  def test_clean_requests_are_not_logged
    mw = build
    request(mw, "GET", "/products?page=2")
    assert_empty events
  end

  def test_trap_mode_serves_decoys_that_hold_honeytokens
    mw = build(mode: :trap)
    r = request(mw, "GET", "/.env")
    assert_equal 200, r.status
    assert_includes r.body, mw.honeytokens.tokens.first
    assert_equal "decoy", events.first["action"]
    login = request(mw, "GET", "/wp-login.php?x=%3Cb%3E")
    assert_includes login.body, "<form"
    refute_includes login.body, "<b>"
  end

  def test_trap_mode_does_not_decoy_other_paths
    mw = build(mode: :trap)
    assert_equal "ok", request(mw, "GET", "/about").body
  end

  def test_block_mode_blocks_only_at_or_above_threshold
    mw = build(mode: :block)
    assert_equal 403, request(mw, "GET", "/f?x=../../etc/passwd").status
    assert_equal 200, request(mw, "GET", "/.env").status # medium, below the default :high
    assert_equal ["blocked", "logged"], events.map { |e| e["action"] }
    assert_equal 403, request(build(mode: :block, block_at: :medium), "GET", "/.env").status
  end

  def test_honeytoken_use_is_a_high_finding
    mw = build
    tok = mw.honeytokens.tokens.last
    request(mw, "POST", "/login", input: "user=app&key=#{tok}")
    ev = events.first
    assert_includes ev["rules"], "honeytoken-used"
    assert_equal "high", ev["severity"]
    assert_includes ev["attack"], "T1078"
  end

  def test_application_still_reads_the_full_body
    mw = build
    assert_equal "name=a<script>", request(mw, "POST", "/x", input: "name=a<script>").body
  end

  def test_only_the_first_max_body_bytes_are_scanned_but_the_app_gets_everything
    mw = build(max_body: 10)
    body = "a" * 20 + "<script>"
    assert_equal body, request(mw, "POST", "/x", input: body).body
    assert_empty events
  end

  def test_secrets_in_headers_never_reach_the_log
    mw = build
    request(mw, "GET", "/.env", "HTTP_AUTHORIZATION" => "Bearer topsecret", "HTTP_COOKIE" => "sid=topsecret")
    refute_includes @log.string, "topsecret"
  end

  def test_forwarded_for_is_trusted_only_from_trusted_proxies
    mw = build(trusted_proxies: ["10.0.0.1"])
    request(mw, "GET", "/.env", "REMOTE_ADDR" => "10.0.0.1", "HTTP_X_FORWARDED_FOR" => "198.51.100.9, 10.0.0.1")
    request(mw, "GET", "/.env", "REMOTE_ADDR" => "203.0.113.5", "HTTP_X_FORWARDED_FOR" => "1.2.3.4")
    assert_equal ["198.51.100.9", "203.0.113.5"], events.map { |e| e["ip"] }
  end

  def test_a_broken_log_does_not_break_the_app
    bad = Object.new
    def bad.puts(*)
      raise IOError, "closed"
    end
    mw = Gargoyle::Middleware.new(app, log: bad)
    assert_equal 200, request(mw, "GET", "/.env").status
  end

  def test_a_failing_callback_does_not_break_the_app
    mw = build(on_event: ->(_e) { raise "boom" })
    assert_equal 200, request(mw, "GET", "/.env").status
  end

  def test_bad_options_are_rejected
    assert_raises(ArgumentError) { build(mode: :nope) }
    assert_raises(ArgumentError) { build(block_at: :nope) }
  end

  def test_log_lines_are_valid_json_with_expected_fields
    mw = build
    request(mw, "GET", "/f?x=../../etc/passwd", "HTTP_USER_AGENT" => "sqlmap/1.7")
    ev = events.first
    %w[ts ip method path query ua severity action rules owasp attack samples].each { |k| assert ev.key?(k), k }
    assert_equal "high", ev["severity"]
  end
end
