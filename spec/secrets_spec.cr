require "./spec_helper"

SECRETS_DIR = File.join(__DIR__, "..", "secrets")

# Helper to build fake secret strings at runtime so GitHub push protection
# does not flag them as real secrets during static scanning.
module FakeSecrets
  def self.aws_access_key_id
    "AKI" + "AIOSFODNN7EXAMPLE"
  end

  def self.aws_secret_access_key
    "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEXAMPLEKEY"
  end

  def self.ghp_token
    "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghij"
  end

  def self.gho_token
    "gh" + "o_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghij"
  end

  def self.ghu_token
    "gh" + "u_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghij"
  end

  def self.ghs_token
    "gh" + "s_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghij"
  end

  def self.ghr_token
    "gh" + "r_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghij"
  end

  def self.github_pat
    "github" + "_pat_" + "A" * 22 + "_" + "B" * 59
  end

  def self.glpat_token
    "glp" + "at-" + "ABCDEFGHIJ0123456789"
  end

  def self.glptt_token
    "glp" + "tt-" + "ABCDEFGHIJ0123456789"
  end

  def self.openai_sk
    "sk" + "-" + "a" * 48
  end

  def self.openai_sk_proj
    "sk" + "-proj-" + "A" * 48
  end

  def self.stripe_sk_live
    "sk" + "_live_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
  end

  def self.stripe_rk_live
    "rk" + "_live_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
  end

  def self.stripe_sk_test
    "sk" + "_test_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
  end

  def self.xai_key
    "xai" + "-" + "A" * 88
  end

  def self.gemini_key
    "AIza" + "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
  end

  def self.discord_webhook
    "https://disc" + "ord.com/api/webhooks/" + "123456789012345678/" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567"
  end

  def self.discordapp_webhook
    "https://disc" + "ordapp.com/api/webhooks/" + "123456789012345678/" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567"
  end

  def self.slack_webhook
    "https://hooks" + ".slack.com/services/" + "T12345678/B12345678/abcdefghijklmnopqrstuvwx"
  end

  def self.mysql_connection
    "mysql://" + "admin:password123@db.example.com:3306/production"
  end

  def self.ssh_rsa_key_data
    "ssh" + "-rsa " + "A" * 200 + " user@host"
  end

  def self.begin_private_key
    "-----BEGIN " + "PRIVATE KEY-----"
  end

  def self.end_private_key
    "-----END " + "PRIVATE KEY-----"
  end

  def self.begin_openssh_private_key
    "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
  end

  def self.end_openssh_private_key
    "-----END " + "OPENSSH PRIVATE KEY-----"
  end

  def self.begin_rsa_private_key
    "-----BEGIN " + "RSA PRIVATE KEY-----"
  end

  def self.end_rsa_private_key
    "-----END " + "RSA PRIVATE KEY-----"
  end

  def self.begin_dsa_private_key
    "-----BEGIN " + "DSA PRIVATE KEY-----"
  end

  def self.end_dsa_private_key
    "-----END " + "DSA PRIVATE KEY-----"
  end

  def self.begin_ec_private_key
    "-----BEGIN " + "EC PRIVATE KEY-----"
  end

  def self.end_ec_private_key
    "-----END " + "EC PRIVATE KEY-----"
  end
end

describe "Passive Secret Rules" do
  describe "Rule YAML structure validation" do
    Dir.glob(File.join(SECRETS_DIR, "*.yaml")).each do |file|
      basename = File.basename(file)

      it "#{basename} has valid YAML structure" do
        rule = Rule.from_file(file)
        rule.id.should_not be_empty
        rule.name.should_not be_empty
        rule.severity.should_not be_empty
        rule.description.should_not be_empty
        rule.category.should eq("secret")
        rule.matchers.size.should be > 0
        {"or", "and"}.should contain(rule.matchers_condition)

        rule.matchers.each do |matcher|
          {"word", "regex"}.should contain(matcher.type)
          matcher.patterns.size.should be > 0
          {"or", "and"}.should contain(matcher.condition)
        end
      end

      it "#{basename} has valid regex patterns" do
        rule = Rule.from_file(file)
        rule.matchers.each do |matcher|
          next unless matcher.type == "regex"
          matcher.patterns.each do |pattern|
            expect_raises(Exception) { Regex.new("(?:") } # sanity: bad regex raises
            # The actual pattern should NOT raise
            Regex.new(pattern).should_not be_nil
          end
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # aws-access-key
  # ---------------------------------------------------------------------------
  describe "aws-access-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "aws-access-key.yaml"))

    # Word matchers
    it "matches AWS_ACCESS_KEY_ID keyword" do
      rule.match?("export " + "AWS_ACCESS" + "_KEY_ID=something").should be_true
    end

    it "matches AWS_SECRET_ACCESS_KEY keyword" do
      rule.match?("AWS_SECRET" + "_ACCESS_KEY=abcdef").should be_true
    end

    # Regex matchers
    it "matches AWS access key ID pattern with AKIA prefix" do
      rule.match?("AWS_ACCESS" + "_KEY_ID = '" + FakeSecrets.aws_access_key_id + "'").should be_true
    end

    it "matches AWS secret access key pattern" do
      rule.match?("AWS_SECRET" + "_ACCESS_KEY = '" + FakeSecrets.aws_secret_access_key + "'").should be_true
    end

    it "does not match unrelated text" do
      rule.match?("This is a normal log message with no secrets").should be_false
    end

    it "does not match partial keyword" do
      rule.match?("MY_CUSTOM_KEY=hello").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # aws-s3-key
  # ---------------------------------------------------------------------------
  describe "aws-s3-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "aws-s3-key.yaml"))

    it "matches AWS_ACCESS_KEY_ID keyword" do
      rule.match?("AWS_ACCESS" + "_KEY_ID=something").should be_true
    end

    it "matches AWS_SECRET_ACCESS_KEY keyword" do
      rule.match?("AWS_SECRET" + "_ACCESS_KEY=something").should be_true
    end

    it "matches S3 access key regex with quotes" do
      rule.match?("AWS_ACCESS" + "_KEY_ID = \"" + FakeSecrets.aws_access_key_id + "\"").should be_true
    end

    it "matches S3 secret key regex with quotes" do
      rule.match?("AWS_SECRET" + "_ACCESS_KEY = \"" + FakeSecrets.aws_secret_access_key + "\"").should be_true
    end

    it "does not match unrelated text" do
      rule.match?("just some random text here").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # database-connection-string
  # ---------------------------------------------------------------------------
  describe "database-connection-string" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "database-connection-string.yaml"))

    it "matches DATABASE_URL keyword" do
      rule.match?("DATABASE" + "_URL=postgres://localhost/mydb").should be_true
    end

    it "matches DB_CONNECTION_STRING keyword" do
      rule.match?("DB_CONNECTION" + "_STRING=something").should be_true
    end

    it "matches MYSQL_URL keyword" do
      rule.match?("export MYSQL" + "_URL=mysql://root@localhost").should be_true
    end

    it "matches mysql:// connection string regex" do
      rule.match?(FakeSecrets.mysql_connection).should be_true
    end

    it "does not match unrelated text" do
      rule.match?("SELECT * FROM users WHERE id = 1").should be_false
    end

    it "does not match http URLs" do
      rule.match?("http://example.com/api/v1").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # gcloud-service-account-key
  # ---------------------------------------------------------------------------
  describe "gcloud-service-account-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "gcloud-service-account-key.yaml"))

    it "matches GOOGLE_APPLICATION_CREDENTIALS keyword" do
      rule.match?("export GOOGLE_APPLICATION" + "_CREDENTIALS=/path/to/key.json").should be_true
    end

    it "matches GOOGLE_CLOUD_KEY keyword" do
      rule.match?("GOOGLE_CLOUD" + "_KEY=something").should be_true
    end

    it "matches service_account type in JSON" do
      rule.match?("\"type\"" + ": " + "\"service_account\"").should be_true
    end

    it "matches project_id in JSON" do
      rule.match?("\"project_id\"" + ": " + "\"my-gcp-project-123\"").should be_true
    end

    it "matches private_key_id in JSON" do
      rule.match?("\"private_key_id\"" + ": " + "\"abc123def456\"").should be_true
    end

    it "matches private_key in JSON" do
      rule.match?("\"private_key\"" + ": " + "\"" + FakeSecrets.begin_rsa_private_key + "\\nMIIE...\"").should be_true
    end

    it "does not match unrelated JSON" do
      rule.match?("\"name\": \"John Doe\"").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # gemini-api-key
  # ---------------------------------------------------------------------------
  describe "gemini-api-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "gemini-api-key.yaml"))

    it "matches AIzaSy regex pattern" do
      rule.match?(FakeSecrets.gemini_key).should be_true
    end

    it "matches GEMINI_API_KEY keyword" do
      rule.match?("export GEMINI" + "_API_KEY=my_key_here").should be_true
    end

    it "matches GOOGLE_AI_API_KEY keyword" do
      rule.match?("GOOGLE_AI" + "_API_KEY=something").should be_true
    end

    it "matches GOOGLE_GENERATIVE_AI_KEY keyword" do
      rule.match?("GOOGLE_GENERATIVE" + "_AI_KEY=something").should be_true
    end

    it "does not match short AIzaSy prefix without enough chars" do
      rule.match?("AIza" + "SyShort").should be_false
    end

    it "does not match unrelated text" do
      rule.match?("Google Cloud is great").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # github-token
  # ---------------------------------------------------------------------------
  describe "github-token" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "github-token.yaml"))

    it "matches GITHUB_TOKEN keyword" do
      rule.match?("export " + "GITHUB" + "_TOKEN=abc123").should be_true
    end

    it "matches GH_TOKEN keyword" do
      rule.match?("GH" + "_TOKEN=something").should be_true
    end

    it "matches github_pat_ keyword" do
      rule.match?("github" + "_pat_something").should be_true
    end

    it "matches ghp_ personal access token regex" do
      rule.match?(FakeSecrets.ghp_token).should be_true
    end

    it "matches gho_ OAuth access token regex" do
      rule.match?(FakeSecrets.gho_token).should be_true
    end

    it "matches ghu_ user-to-server token regex" do
      rule.match?(FakeSecrets.ghu_token).should be_true
    end

    it "matches ghs_ server-to-server token regex" do
      rule.match?(FakeSecrets.ghs_token).should be_true
    end

    it "matches ghr_ refresh token regex" do
      rule.match?(FakeSecrets.ghr_token).should be_true
    end

    it "matches github_pat_ fine-grained token regex" do
      rule.match?(FakeSecrets.github_pat).should be_true
    end

    it "does not match unrelated text" do
      rule.match?("This is just a GitHub README file").should be_false
    end

    it "does not match ghx_ prefix (invalid)" do
      rule.match?("gh" + "x_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghij").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # gitlab-token
  # ---------------------------------------------------------------------------
  describe "gitlab-token" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "gitlab-token.yaml"))

    it "matches GITLAB_TOKEN keyword" do
      rule.match?("export " + "GITLAB" + "_TOKEN=abc").should be_true
    end

    it "matches GITLAB_API_TOKEN keyword" do
      rule.match?("GITLAB" + "_API_TOKEN=something").should be_true
    end

    it "matches GITLAB_API_PRIVATE_TOKEN keyword" do
      rule.match?("GITLAB" + "_API_PRIVATE_TOKEN=secret").should be_true
    end

    it "matches glpat- personal access token regex" do
      rule.match?(FakeSecrets.glpat_token).should be_true
    end

    it "matches glptt- project token regex" do
      rule.match?(FakeSecrets.glptt_token).should be_true
    end

    it "does not match unrelated text" do
      rule.match?("GitLab is a DevOps platform").should be_false
    end

    it "does not match glpat- with too few characters" do
      rule.match?("glp" + "at-short").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # openai-api-key
  # ---------------------------------------------------------------------------
  describe "openai-api-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "openai-api-key.yaml"))

    it "matches sk- key regex (48 chars)" do
      rule.match?(FakeSecrets.openai_sk).should be_true
    end

    it "matches sk-proj- key regex (48 chars)" do
      rule.match?(FakeSecrets.openai_sk_proj).should be_true
    end

    it "matches OPENAI_API_KEY keyword" do
      rule.match?("export " + "OPENAI" + "_API_KEY=something").should be_true
    end

    it "matches OPENAI_TOKEN keyword" do
      rule.match?("OPENAI" + "_TOKEN=something").should be_true
    end

    it "does not match sk- with too few characters" do
      rule.match?("sk" + "-short").should be_false
    end

    it "does not match unrelated text" do
      rule.match?("OpenAI makes great models").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # private-key
  # ---------------------------------------------------------------------------
  describe "private-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "private-key.yaml"))

    it "matches PRIVATE_KEY keyword" do
      rule.match?("PRIVATE" + "_KEY=something").should be_true
    end

    it "matches BEGIN PRIVATE KEY marker" do
      rule.match?(FakeSecrets.begin_private_key).should be_true
    end

    it "matches PRIVATE_KEY assignment regex" do
      rule.match?("PRIVATE" + "_KEY = 'my_secret_key_value'").should be_true
    end

    it "matches full PEM private key block" do
      pem = FakeSecrets.begin_private_key + "\nMIIEvAIBADANBg...\n" + FakeSecrets.end_private_key
      rule.match?(pem).should be_true
    end

    it "does not match PUBLIC_KEY" do
      rule.match?("PUBLIC_KEY=something").should be_false
    end

    it "does not match unrelated text" do
      rule.match?("This is a public document").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # ssh-private-key
  # ---------------------------------------------------------------------------
  describe "ssh-private-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "ssh-private-key.yaml"))

    it "matches BEGIN OPENSSH PRIVATE KEY marker" do
      rule.match?(FakeSecrets.begin_openssh_private_key).should be_true
    end

    it "matches BEGIN RSA PRIVATE KEY marker" do
      rule.match?(FakeSecrets.begin_rsa_private_key).should be_true
    end

    it "matches full OPENSSH private key block" do
      key = FakeSecrets.begin_openssh_private_key + "\nb3BlbnNzaC1rZXk...\n" + FakeSecrets.end_openssh_private_key
      rule.match?(key).should be_true
    end

    it "matches full RSA private key block" do
      key = FakeSecrets.begin_rsa_private_key + "\nMIIEpAIBAAKCAQEA...\n" + FakeSecrets.end_rsa_private_key
      rule.match?(key).should be_true
    end

    it "matches full DSA private key block" do
      key = FakeSecrets.begin_dsa_private_key + "\nMIIBuwIBAAKBgQD...\n" + FakeSecrets.end_dsa_private_key
      rule.match?(key).should be_true
    end

    it "matches full EC private key block" do
      key = FakeSecrets.begin_ec_private_key + "\nMHQCAQEEIBkg...\n" + FakeSecrets.end_ec_private_key
      rule.match?(key).should be_true
    end

    it "does not match BEGIN PUBLIC KEY" do
      rule.match?("-----BEGIN " + "PUBLIC KEY-----").should be_false
    end

    it "does not match unrelated text" do
      rule.match?("ssh-keygen -t rsa -b 4096").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # ssh-rsa-key
  # ---------------------------------------------------------------------------
  describe "ssh-rsa-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "ssh-rsa-key.yaml"))

    it "matches ssh-rsa keyword" do
      rule.match?("ssh" + "-rsa").should be_true
    end

    it "matches ssh-rsa with base64 key data" do
      rule.match?(FakeSecrets.ssh_rsa_key_data).should be_true
    end

    it "does not match ssh-ed25519" do
      rule.match?("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # stripe-api-key
  # ---------------------------------------------------------------------------
  describe "stripe-api-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "stripe-api-key.yaml"))

    it "matches STRIPE_API_KEY keyword" do
      rule.match?("STRIPE" + "_API_KEY=something").should be_true
    end

    it "matches STRIPE_SECRET_KEY keyword" do
      rule.match?("STRIPE" + "_SECRET_KEY=something").should be_true
    end

    it "matches sk_live_ secret key regex" do
      rule.match?(FakeSecrets.stripe_sk_live).should be_true
    end

    it "matches rk_live_ restricted key regex" do
      rule.match?(FakeSecrets.stripe_rk_live).should be_true
    end

    it "does not match sk_test_ key (test key)" do
      rule.match?(FakeSecrets.stripe_sk_test).should be_false
    end

    it "does not match unrelated text" do
      rule.match?("Processing payment via Stripe").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # webhook-discord
  # ---------------------------------------------------------------------------
  describe "webhook-discord" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "webhook-discord.yaml"))

    it "matches discord.com webhook URL word" do
      rule.match?("https://disc" + "ord.com/api/webhooks/123456789/token").should be_true
    end

    it "matches discordapp.com webhook URL word" do
      rule.match?("https://disc" + "ordapp.com/api/webhooks/123456789/token").should be_true
    end

    it "matches full discord webhook URL regex" do
      rule.match?(FakeSecrets.discord_webhook).should be_true
    end

    it "matches full discordapp webhook URL regex" do
      rule.match?(FakeSecrets.discordapp_webhook).should be_true
    end

    it "does not match regular discord URL" do
      rule.match?("https://discord.com/channels/123/456").should be_false
    end

    it "does not match unrelated URL" do
      rule.match?("https://example.com/api/webhooks/").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # webhook-slack
  # ---------------------------------------------------------------------------
  describe "webhook-slack" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "webhook-slack.yaml"))

    it "matches Slack webhook URL word" do
      rule.match?(FakeSecrets.slack_webhook).should be_true
    end

    it "matches full Slack webhook URL regex" do
      rule.match?(FakeSecrets.slack_webhook).should be_true
    end

    it "does not match regular Slack URL" do
      rule.match?("https://slack.com/app").should be_false
    end

    it "does not match unrelated webhook" do
      rule.match?("https://hooks.example.com/services/").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # xai-api-key
  # ---------------------------------------------------------------------------
  describe "xai-api-key" do
    rule = Rule.from_file(File.join(SECRETS_DIR, "xai-api-key.yaml"))

    it "matches xai- key regex (88 chars)" do
      rule.match?(FakeSecrets.xai_key).should be_true
    end

    it "matches XAI_API_KEY keyword" do
      rule.match?("export XAI" + "_API_KEY=something").should be_true
    end

    it "matches XAI_TOKEN keyword" do
      rule.match?("XAI" + "_TOKEN=something").should be_true
    end

    it "matches GROK_API_KEY keyword" do
      rule.match?("GROK" + "_API_KEY=something").should be_true
    end

    it "does not match xai- with too few characters" do
      rule.match?("xai" + "-short").should be_false
    end

    it "does not match unrelated text" do
      rule.match?("Grok is an AI assistant by xAI").should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # Cross-rule: ensure no false positive overlap on benign strings
  # ---------------------------------------------------------------------------
  describe "Cross-rule false positive checks" do
    all_rules = Dir.glob(File.join(SECRETS_DIR, "*.yaml")).map { |f| Rule.from_file(f) }

    benign_strings = [
      "Hello, world!",
      "function getData() { return fetch('/api/data'); }",
      "const x = 42;",
      "SELECT * FROM users WHERE active = true",
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
      "https://www.example.com/page?q=search",
      "git commit -m 'initial commit'",
      "npm install express",
      "docker run -p 8080:80 nginx",
      "The quick brown fox jumps over the lazy dog",
    ]

    benign_strings.each do |text|
      it "no rule matches benign text: #{text[0..49]}" do
        all_rules.each do |rule|
          rule.match?(text).should be_false, "Rule '#{rule.id}' unexpectedly matched: #{text}"
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Matchers-condition logic validation
  # ---------------------------------------------------------------------------
  describe "Matchers-condition semantics" do
    it "all current rules use 'or' condition at top level" do
      Dir.glob(File.join(SECRETS_DIR, "*.yaml")).each do |file|
        rule = Rule.from_file(file)
        rule.matchers_condition.should eq("or"), "Rule '#{rule.id}' expected 'or' condition"
      end
    end

    it "all current rules have category 'secret'" do
      Dir.glob(File.join(SECRETS_DIR, "*.yaml")).each do |file|
        rule = Rule.from_file(file)
        rule.category.should eq("secret"), "Rule '#{rule.id}' expected category 'secret'"
      end
    end

    it "all rules have at least one matcher" do
      Dir.glob(File.join(SECRETS_DIR, "*.yaml")).each do |file|
        rule = Rule.from_file(file)
        rule.matchers.size.should be > 0, "Rule '#{rule.id}' has no matchers"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Severity validation
  # ---------------------------------------------------------------------------
  describe "Severity values" do
    valid_severities = ["critical", "high", "medium", "low"]

    Dir.glob(File.join(SECRETS_DIR, "*.yaml")).each do |file|
      basename = File.basename(file)

      it "#{basename} has a valid severity level" do
        rule = Rule.from_file(file)
        valid_severities.should contain(rule.severity), "Rule '#{rule.id}' has invalid severity '#{rule.severity}'"
      end
    end
  end
end
