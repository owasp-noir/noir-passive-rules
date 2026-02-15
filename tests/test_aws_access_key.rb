require 'minitest/autorun'
require 'yaml'

class TestAwsAccessKey < Minitest::Test
  def setup
    @yaml_data = YAML.load_file('secrets/aws-access-key.yaml')
    @matchers = @yaml_data['matchers']
    @regex_patterns = @matchers.find { |m| m['type'] == 'regex' }['patterns']

    # regex[0] is for AWS_ACCESS_KEY_ID
    # regex[1] is for AWS_SECRET_ACCESS_KEY
    @access_key_regex = Regexp.new(@regex_patterns[0])
    @secret_key_regex = Regexp.new(@regex_patterns[1])
  end

  def test_valid_access_key_id
    valid_keys = [
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE',
      'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"',
      "AWS_ACCESS_KEY_ID='AKIAIOSFODNN7EXAMPLE'",
      'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
    ]

    valid_keys.each do |key|
      assert_match(@access_key_regex, key, "Should match valid key: #{key}")
    end
  end

  def test_invalid_access_key_id
    invalid_keys = [
      'AWS_ACCESS_KEY_ID=BKIAIOSFODNN7EXAMPLE', # Wrong prefix
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMP',   # Too short
      'AWS_ACCESS_KEY_ID=AKIBIOSFODNN7EXAMPLE', # Second char not K
      'AWS_ACCESS_KEY_ID=1KIAIOSFODNN7EXAMPLE', # First char digit
    ]

    invalid_keys.each do |key|
      refute_match(@access_key_regex, key, "Should not match invalid key: #{key}")
    end
  end

  def test_valid_secret_access_key
    valid_keys = [
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
      "AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI+K7MDENG/bPxRfiCYEXAMPLEKEY', # With +
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY=', # With = (padding)
    ]

    valid_keys.each do |key|
      assert_match(@secret_key_regex, key, "Should match valid secret key: #{key}")
    end
  end

  def test_invalid_secret_access_key
    invalid_keys = [
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE', # Too short (39)
    ]

    invalid_keys.each do |key|
      refute_match(@secret_key_regex, key, "Should not match invalid secret key: #{key}")
    end
  end
end
