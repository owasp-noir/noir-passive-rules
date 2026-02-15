require 'yaml'
require 'minitest/autorun'

class TestXaiApiKey < Minitest::Test
  def setup
    @yaml_data = YAML.load_file('secrets/xai-api-key.yaml')
    @regex_pattern = @yaml_data['matchers'].find { |m| m['type'] == 'regex' }['patterns'].first
    @regex = Regexp.new(@regex_pattern)
  end

  def test_valid_xai_api_key
    # Generate a valid key: 'xai-' followed by 88 alphanumeric characters
    valid_key = 'xai-' + 'a' * 88
    assert_match @regex, valid_key

    valid_key_2 = 'xai-' + 'A' * 88
    assert_match @regex, valid_key_2

    valid_key_3 = 'xai-' + '0' * 88
    assert_match @regex, valid_key_3

    # Fix random generation
    charset = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
    valid_key_mixed = 'xai-' + (0...88).map { charset.sample }.join
    assert_match @regex, valid_key_mixed
  end

  def test_invalid_prefix
    invalid_key = 'yai-' + 'a' * 88
    refute_match @regex, invalid_key
  end

  def test_invalid_length
    # Too short
    invalid_key_short = 'xai-' + 'a' * 87
    refute_match @regex, invalid_key_short

    # Too long - The regex is unanchored, so it will match the first 88 chars of a longer string.
    # So we don't test for "too long" failing to match, because it SHOULD match.
  end

  def test_invalid_characters
    # Contains symbol
    invalid_key_symbol = 'xai-' + 'a' * 87 + '!'
    refute_match @regex, invalid_key_symbol
  end
end
