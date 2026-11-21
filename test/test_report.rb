# frozen_string_literal: true

require_relative "test_helper"
require "tmpdir"
require "open3"
require "rbconfig"

class TestReport < Minitest::Test
  def demo_log
    dir = Dir.mktmpdir
    path = File.join(dir, "demo.jsonl")
    File.write(path, "")
    Gargoyle::Demo.run(path)
    path
  end

  def test_demo_traffic_produces_the_expected_summary
    s = Gargoyle::Report.from_file(demo_log).summary
    assert_equal 9, s[:events] # 7 invented attacks + the second decoy fetch + the request that uses the planted token; benign requests are not logged
    assert_equal 1, s[:honeytoken_uses]
    assert_equal "203.0.113.7", s[:top_ips].keys.first
    assert_includes s[:attack].keys, "T1190"
    assert_includes s[:owasp].keys, "LLM01"
    assert_equal 3, s[:by_action]["decoy"]
  end

  def test_unparsable_lines_are_counted_not_hidden
    dir = Dir.mktmpdir
    path = File.join(dir, "x.jsonl")
    File.write(path, "{\"rules\":[\"xss\"]}\nnot json\n[1,2]\n\n")
    r = Gargoyle::Report.from_file(path)
    assert_equal 1, r.events.size
    assert_equal [2, 3], r.bad_lines
  end

  def test_html_is_escaped
    r = Gargoyle::Report.new([{ "path" => "/<img src=x onerror=alert(1)>", "rules" => ["xss"] }])
    html = r.to_html
    assert_includes html, "&lt;img"
    refute_includes html, "<img src=x"
  end

  def test_cli_exit_codes
    bin = File.expand_path("../bin/gargoyle", __dir__)
    ruby = RbConfig.ruby
    log = demo_log
    _, st = Open3.capture2(ruby, bin, "report", log)
    assert_equal 1, st.exitstatus
    empty = File.join(File.dirname(log), "empty.jsonl")
    File.write(empty, "")
    _, st = Open3.capture2(ruby, bin, "report", empty)
    assert_equal 0, st.exitstatus
    _, _, st = Open3.capture3(ruby, bin, "report", "/nonexistent/file")
    assert_equal 2, st.exitstatus
    out, st = Open3.capture2(ruby, bin, "rules")
    assert_equal 0, st.exitstatus
    assert_includes out, "log4shell"
  end

  def test_min_severity_keeps_only_events_at_or_above_the_level
    rep = Gargoyle::Report.new([{ "severity" => "low" }, { "severity" => "high" }, { "severity" => "info" }, { "severity" => "weird" }])
    assert_equal 1, rep.at_least("high").events.size
    assert_equal 2, rep.at_least(:low).events.size
    assert_equal 4, rep.at_least("info").events.size
    assert_raises(ArgumentError) { rep.at_least("urgent") }
  end

  def test_cli_min_severity_filters_and_rejects_bad_values
    log = demo_log
    bin = File.expand_path("../bin/gargoyle", __dir__)
    out, = Open3.capture2(RbConfig.ruby, bin, "report", log, "--json", "--min-severity", "high")
    assert JSON.parse(out)["by_severity"].keys.all? { |k| k == "high" }
    _, err, st = Open3.capture3(RbConfig.ruby, bin, "report", log, "--min-severity", "urgent")
    assert_equal 2, st.exitstatus
    assert_match(/unknown severity/, err)
  end
end
