require 'minitest/autorun'
require 'yaml'

class TestAwsS3Key < Minitest::Test
  def setup
    @yaml_data = YAML.load_file('secrets/aws-s3-key.yaml')
    @matchers = @yaml_data['matchers'].find { |m| m['type'] == 'regex' }
    @patterns = @matchers['patterns']
    # The patterns in YAML are strings. When loaded by YAML.load_file, they are just strings.
    # We need to convert them to Regexp objects.
    @aws_access_key_id_pattern = Regexp.new(@patterns[0])
    @aws_secret_access_key_pattern = Regexp.new(@patterns[1])
  end

  def test_aws_access_key_id_positive
    # Standard format with double quotes
    assert_match(@aws_access_key_id_pattern, 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')
    # Standard format with single quotes
    assert_match(@aws_access_key_id_pattern, "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'")
    # With spaces around equals
    assert_match(@aws_access_key_id_pattern, 'AWS_ACCESS_KEY_ID   =   "AKIAIOSFODNN7EXAMPLE"')
    # With no spaces around equals
    assert_match(@aws_access_key_id_pattern, 'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"')
  end

  def test_aws_access_key_id_negative
    # Too short
    refute_match(@aws_access_key_id_pattern, 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPL"')
    # Too long
    refute_match(@aws_access_key_id_pattern, 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLEE"')
    # Lowercase letters (should be uppercase only for ID)
    refute_match(@aws_access_key_id_pattern, 'AWS_ACCESS_KEY_ID = "akiaiosfodnn7example"')
    # Wrong prefix (variable name mismatch)
    refute_match(@aws_access_key_id_pattern, 'OTHER_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')
  end

  def test_aws_secret_access_key_positive
    # Standard format with double quotes (40 chars)
    assert_match(@aws_secret_access_key_pattern, 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
    # Standard format with single quotes
    assert_match(@aws_secret_access_key_pattern, "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
    # With spaces
    assert_match(@aws_secret_access_key_pattern, 'AWS_SECRET_ACCESS_KEY   =   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
  end

  def test_aws_secret_access_key_negative
    # Too short
    refute_match(@aws_secret_access_key_pattern, 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE"')
    # Too long
    refute_match(@aws_secret_access_key_pattern, 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYY"')
    # Invalid characters (e.g., spaces inside key)
    refute_match(@aws_secret_access_key_pattern, 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY EXAMPLEKEY"')
    # Wrong variable name
    refute_match(@aws_secret_access_key_pattern, 'OTHER_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
  end
end
