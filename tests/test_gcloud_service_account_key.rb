require 'yaml'
require 'minitest/autorun'

class TestGcloudServiceAccountKey < Minitest::Test
  def setup
    @yaml_data = YAML.load_file(File.join(__dir__, '../secrets/gcloud-service-account-key.yaml'))
    @regex_matcher = @yaml_data['matchers'].find { |m| m['type'] == 'regex' }
    @patterns = @regex_matcher['patterns']
  end

  def test_service_account_type
    pattern = @patterns.find { |p| p.include?('type') }
    regex = Regexp.new(pattern)

    # Positive cases
    assert_match(regex, '"type": "service_account"')
    assert_match(regex, '"type" : "service_account"')
    assert_match(regex, '"type"  :  "service_account"')

    # Negative cases
    refute_match(regex, '"type": "user"')
    refute_match(regex, '"kind": "service_account"')
  end

  def test_project_id
    pattern = @patterns.find { |p| p.include?('project_id') }
    regex = Regexp.new(pattern)

    # Positive cases
    assert_match(regex, '"project_id": "my-project-123"')
    assert_match(regex, '"project_id" : "test_project"')

    # Negative cases
    refute_match(regex, '"project_id": ""') # Empty string shouldn't match due to +
    refute_match(regex, '"id": "my-project"')
  end

  def test_private_key_id
    pattern = @patterns.find { |p| p.include?('private_key_id') }
    regex = Regexp.new(pattern)

    # Positive cases
    assert_match(regex, '"private_key_id": "abcdef1234567890"')
    assert_match(regex, '"private_key_id" : "key_id_value"')

    # Negative cases
    refute_match(regex, '"private_key_id": ""')
    refute_match(regex, '"key_id": "abcdef"')
  end

  def test_private_key
    pattern = @patterns.find { |p| p.include?('private_key') && !p.include?('private_key_id') }
    regex = Regexp.new(pattern)

    # Positive cases
    assert_match(regex, '"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ..."')
    assert_match(regex, '"private_key" : "some_private_key_content"')

    # Negative cases
    refute_match(regex, '"private_key": ""')
    refute_match(regex, '"public_key": "content"')
  end
end
