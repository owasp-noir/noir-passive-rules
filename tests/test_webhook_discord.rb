require 'minitest/autorun'
require 'yaml'

class TestWebhookDiscord < Minitest::Test
  def setup
    @yaml = YAML.load_file('secrets/webhook-discord.yaml')
    @regex_patterns = @yaml['matchers'].select { |m| m['type'] == 'regex' }.flat_map { |m| m['patterns'] }
  end

  def test_regex_patterns_presence
    refute_empty @regex_patterns, "No regex patterns found in webhook-discord.yaml"
  end

  def test_positive_matches
    # Valid Discord Webhook URLs
    # ID: 17-19 digits
    # Token: 60-68 characters [A-Za-z0-9_-]

    valid_ids = [
      '12345678901234567',   # 17 digits
      '123456789012345678',  # 18 digits
      '1234567890123456789'  # 19 digits
    ]

    valid_tokens = [
      'a' * 60,
      'a' * 68,
      'A' * 60 + '-' + '_',
      # 64 chars mixed
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
    ]

    valid_ids.each do |id|
      valid_tokens.each do |token|
        url_discord = "https://discord.com/api/webhooks/#{id}/#{token}"
        url_discordapp = "https://discordapp.com/api/webhooks/#{id}/#{token}"

        assert_match_any_pattern(url_discord)
        assert_match_any_pattern(url_discordapp)
      end
    end
  end

  def test_negative_matches
    invalid_examples = [
      "https://google.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-", # Wrong domain
      "http://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-",  # http instead of https
      "https://discord.com/api/webhook/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-",  # webhook instead of webhooks
      "https://discord.com/api/webhooks/1234567890123456/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-",   # ID too short (16)
      "https://discord.com/api/webhooks/12345678901234567890/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-", # ID too long (20)
      "https://discord.com/api/webhooks/123456789012345678/" + "a" * 59, # Token too short (59)
      # "https://discord.com/api/webhooks/123456789012345678/" + "a" * 69, # Token too long (69) - Matches prefix, which is expected for unanchored regex
      "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDE!FGHIJKLMNOPQRSTUVWXYZ1234567890_-", # Token contains invalid char in middle
    ]

    invalid_examples.each_with_index do |example, index|
      refute_match_any_pattern(example, "Failed on invalid example index #{index}: #{example}")
    end
  end

  private

  def assert_match_any_pattern(text, msg = nil)
    matched = @regex_patterns.any? { |pattern| text.match?(Regexp.new(pattern)) }
    assert matched, msg || "Expected '#{text}' to match at least one regex pattern"
  end

  def refute_match_any_pattern(text, msg = nil)
    matched = @regex_patterns.any? { |pattern| text.match?(Regexp.new(pattern)) }
    refute matched, msg || "Expected '#{text}' NOT to match any regex pattern"
  end
end
