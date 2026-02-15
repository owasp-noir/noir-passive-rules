# validation_test.rb
require 'minitest/autorun'
require 'yaml'

class TestSshRsaKeyVerification < Minitest::Test
  def setup
    # Load the YAML file
    @yaml_data = YAML.load_file('secrets/ssh-rsa-key.yaml')

    # Extract the regex pattern
    # The structure is matchers -> list of matchers -> find type regex -> patterns -> first pattern
    matcher = @yaml_data['matchers'].find { |m| m['type'] == 'regex' }
    @regex_pattern = matcher['patterns'][0]
    @regex = Regexp.new(@regex_pattern)
  end

  def test_regex_pattern_validity
    # Ensure the regex pattern was successfully extracted
    refute_nil @regex_pattern, "Regex pattern should be present in the YAML file"
  end

  def test_positive_match_exact_100_chars
    # Valid ssh-rsa key with exactly 100 characters of base64 data
    base64_data = "A" * 100
    valid_key = "ssh-rsa #{base64_data}"
    assert_match @regex, valid_key, "Should match ssh-rsa followed by exactly 100 base64 characters"
  end

  def test_positive_match_more_than_100_chars
    # Valid ssh-rsa key with more than 100 characters
    base64_data = "B" * 150
    valid_key = "ssh-rsa #{base64_data}"
    assert_match @regex, valid_key, "Should match ssh-rsa followed by more than 100 base64 characters"
  end

  def test_positive_match_multiple_spaces
    # Key with multiple spaces between ssh-rsa and data
    base64_data = "C" * 100
    valid_key = "ssh-rsa   #{base64_data}"
    assert_match @regex, valid_key, "Should match with multiple spaces"
  end

  def test_positive_match_tabs
    # Key with tabs between ssh-rsa and data
    base64_data = "D" * 100
    valid_key = "ssh-rsa\t\t#{base64_data}"
    assert_match @regex, valid_key, "Should match with tabs"
  end

  def test_positive_match_valid_base64_chars
    # Key with mixed valid base64 characters
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    base64_data = (base64_chars * 2)[0...100] # Ensure at least 100 chars
    valid_key = "ssh-rsa #{base64_data}"
    assert_match @regex, valid_key, "Should match with valid base64 characters"
  end

  def test_negative_match_less_than_100_chars
    # Key with less than 100 characters of base64 data
    base64_data = "E" * 99
    invalid_key = "ssh-rsa #{base64_data}"
    refute_match @regex, invalid_key, "Should not match with less than 100 base64 characters"
  end

  def test_negative_match_invalid_characters
    # Key with invalid characters in the base64 part
    base64_data = "F" * 90 + "!@#$%^&*()"
    invalid_key = "ssh-rsa #{base64_data}"
    refute_match @regex, invalid_key, "Should not match with invalid characters in base64 part"
  end

  def test_negative_match_missing_prefix
    # String without ssh-rsa prefix
    base64_data = "G" * 100
    invalid_key = "ssh-dsa #{base64_data}"
    refute_match @regex, invalid_key, "Should not match without ssh-rsa prefix"
  end

  def test_negative_match_prefix_only
    # ssh-rsa prefix without following data
    invalid_key = "ssh-rsa "
    refute_match @regex, invalid_key, "Should not match ssh-rsa prefix only"
  end
end
