# frozen_string_literal: true
# rackup examples/config.ru   (needs the rackup and webrick gems for rack 3)
require_relative "../lib/gargoyle"

use Gargoyle::Middleware, mode: :monitor, log: "gargoyle.jsonl"
run ->(_env) { [200, { "content-type" => "text/plain" }, ["hello\n"]] }
