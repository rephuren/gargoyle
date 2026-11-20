# frozen_string_literal: true

module Gargoyle
  # Fake pages served in :trap mode. They contain no scripts and never echo anything from the request.
  class Decoys
    LOGIN = <<~HTML
      <!doctype html><meta charset="utf-8"><title>Log In</title>
      <form method="post" action="/wp-login.php"><p><label>Username <input name="log"></label></p>
      <p><label>Password <input type="password" name="pwd"></label></p><p><button>Log In</button></p></form>
    HTML

    GIT_CONFIG = <<~CFG
      [core]
      \trepositoryformatversion = 0
      [remote "origin"]
      \turl = https://git.example.invalid/internal/app.git
    CFG

    def initialize(honeytokens)
      @honeytokens = honeytokens
    end

    # Returns a Rack response triple or nil.
    def respond(path)
      case path
      when %r{\A/\.env\z} then [200, { "content-type" => "text/plain" }, [@honeytokens.decoy_env]]
      when %r{\A/\.git/config\z} then [200, { "content-type" => "text/plain" }, [GIT_CONFIG]]
      when %r{\A/wp-login\.php\z} then [200, { "content-type" => "text/html; charset=utf-8" }, [LOGIN]]
      end
    end
  end
end
