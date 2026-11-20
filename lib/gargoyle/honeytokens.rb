# frozen_string_literal: true

require "securerandom"

module Gargoyle
  # Fake credentials planted in decoy files. If one ever shows up in a later request, someone harvested the decoy and is trying it.
  # Tokens are generated at start-up, never stored in the repository, and look like nothing that works anywhere.
  class Honeytokens
    attr_reader :tokens

    def initialize(count: 3)
      @tokens = Array.new(count) { "gg-#{SecureRandom.hex(8)}" }.freeze
    end

    def decoy_env
      <<~ENV
        APP_ENV=production
        DB_HOST=db.internal.invalid
        DB_USER=app
        DB_PASSWORD=#{tokens[0]}
        SECRET_KEY_BASE=#{tokens[1]}
        API_TOKEN=#{tokens[2]}
      ENV
    end

    def used_in?(texts)
      texts.any? { |t| tokens.any? { |k| t.to_s.include?(k) } }
    end
  end
end
