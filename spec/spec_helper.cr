require "spec"
require "yaml"

# Represents a single matcher block from the YAML rule
struct Matcher
  getter type : String
  getter patterns : Array(String)
  getter condition : String

  def initialize(@type : String, @patterns : Array(String), @condition : String)
  end

  # Check if the given text matches this matcher block
  def match?(text : String) : Bool
    results = patterns.map do |pattern|
      case type
      when "word"
        text.includes?(pattern)
      when "regex"
        !!(Regex.new(pattern).match(text))
      else
        false
      end
    end

    case condition
    when "and"
      results.all?
    else # "or"
      results.any?
    end
  end
end

# Represents a parsed YAML rule file
struct Rule
  getter id : String
  getter name : String
  getter severity : String
  getter description : String
  getter matchers_condition : String
  getter matchers : Array(Matcher)
  getter category : String

  def initialize(
    @id : String,
    @name : String,
    @severity : String,
    @description : String,
    @matchers_condition : String,
    @matchers : Array(Matcher),
    @category : String
  )
  end

  # Check if the given text matches the rule (evaluates all matchers with the top-level condition)
  def match?(text : String) : Bool
    results = matchers.map { |m| m.match?(text) }

    case matchers_condition
    when "and"
      results.all?
    else # "or"
      results.any?
    end
  end

  # Parse a rule from a YAML file path
  def self.from_file(path : String) : Rule
    content = File.read(path)
    yaml = YAML.parse(content)

    id = yaml["id"].as_s
    info = yaml["info"]
    name = info["name"].as_s
    severity = info["severity"].as_s
    description = info["description"].as_s
    matchers_condition = yaml["matchers-condition"].as_s
    category = yaml["category"].as_s

    matchers = [] of Matcher
    yaml["matchers"].as_a.each do |m|
      type = m["type"].as_s
      patterns = m["patterns"].as_a.map(&.as_s)
      condition = m["condition"].as_s
      matchers << Matcher.new(type, patterns, condition)
    end

    Rule.new(
      id: id,
      name: name,
      severity: severity,
      description: description,
      matchers_condition: matchers_condition,
      matchers: matchers,
      category: category,
    )
  end
end

# Helper to resolve rule file path relative to project root
def rule_path(filename : String) : String
  base = File.join(__DIR__, "..", "secrets")
  File.join(base, filename)
end
