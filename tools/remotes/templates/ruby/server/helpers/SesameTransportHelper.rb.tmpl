require "json"
require "net/http"
require "uri"

#[Helper]
class SesameTransportHelper
  SNAPSHOT_VARIABLE = "YON_APPLICATION_JSON"
  SECURE_SCHEME = "https"
  PLAIN_SCHEME = "http"
  LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "::1"].freeze
  ROOT_PATHS = ["", "/"].freeze
  SECURE_PROXY_VARIABLES = ["HTTPS_PROXY", "https_proxy"].freeze
  PLAIN_PROXY_VARIABLES = ["http_proxy"].freeze
  JSON_TYPE = "application/json"
  BODY = "body"
  DEADLINE = "deadline"
  REDIRECT_STATUSES = (300..399)
  MILLISECONDS_PER_SECOND = 1000.0
  ORIGIN_RULE = "sesame.origin must be an https origin without a path, or http on a loopback address"
  REDIRECT_RULE = "SESAME answered with a redirect, which this transport never follows"
  SIZE_RULE = "SESAME's answer is larger than the response limit"
  DEADLINE_RULE = "SESAME did not answer before the deadline"

  # @param request [Hash]
  # @param execution [Object]
  # @return [Hash]
  def exchange(request, execution)
    address = address(origin, request)
    status, content = sent(address, outgoing(address, request), request)
    { "status" => status, BODY => json_or_nothing(content) }
  end

  private

  def origin
    snapshot = JSON.parse(ENV.fetch(SNAPSHOT_VARIABLE, "{}"))
    configured = snapshot.dig("yon", "sesame", "origin")
    parsed = configured.is_a?(String) ? URI.parse(configured) : nil
    raise ArgumentError, ORIGIN_RULE unless parsed && usable?(parsed)
    parsed
  rescue URI::InvalidURIError, JSON::ParserError
    raise ArgumentError, ORIGIN_RULE
  end

  def usable?(origin)
    checks = [
      allowed_scheme?(origin),
      origin.userinfo.nil?,
      ROOT_PATHS.include?(origin.path),
      origin.query.nil?,
      origin.fragment.nil?,
    ]
    checks.all?
  end

  def allowed_scheme?(origin)
    secure = origin.scheme == SECURE_SCHEME && !origin.host.to_s.empty?
    local = origin.scheme == PLAIN_SCHEME && LOOPBACK_HOSTS.include?(origin.hostname)
    secure || local
  end

  def address(origin, request)
    address = origin.dup
    address.path = request["path"]
    address.query = request["query"].empty? ? nil : URI.encode_www_form(request["query"].transform_values(&:to_s))
    address
  end

  def outgoing(address, request)
    outgoing = Net::HTTPGenericRequest.new(request["method"], request.key?(BODY), true, address.request_uri)
    outgoing["Accept"] = JSON_TYPE
    outgoing["Content-Type"] = JSON_TYPE
    request["headers"].each { |name, value| outgoing[name] = value }
    outgoing.body = JSON.generate(request[BODY]) if request.key?(BODY)
    outgoing
  end

  def sent(address, outgoing, request)
    seconds = remaining_seconds(request[DEADLINE])
    options = { use_ssl: address.scheme == SECURE_SCHEME, open_timeout: seconds, read_timeout: seconds, write_timeout: seconds }
    answer = nil
    Net::HTTP.start(address.hostname, address.port, *proxy(address), **options) do |connection|
      connection.request(outgoing) { |response| answer = answered(response, request) }
    end
    answer
  end

  def proxy(address)
    variables = address.scheme == SECURE_SCHEME ? SECURE_PROXY_VARIABLES : PLAIN_PROXY_VARIABLES
    configured = variables.map { |variable| ENV.fetch(variable, "") }.find { |value| !value.empty? }
    return [nil, nil] if configured.nil?
    proxy = URI.parse(configured)
    [proxy.hostname, proxy.port]
  end

  def answered(response, request)
    status = response.code.to_i
    raise IOError, REDIRECT_RULE if REDIRECT_STATUSES.cover?(status)
    [status, read(response, request["maxResponseBytes"], request[DEADLINE])]
  end

  def read(response, limit, deadline)
    content = +""
    response.read_body do |chunk|
      content << chunk
      raise IOError, SIZE_RULE if content.bytesize > limit
      raise IOError, DEADLINE_RULE if remaining_seconds(deadline) <= 0
    end
    content
  end

  def remaining_seconds(deadline)
    (deadline - (Time.now.to_f * MILLISECONDS_PER_SECOND)) / MILLISECONDS_PER_SECOND
  end

  def json_or_nothing(content)
    JSON.parse(content)
  rescue JSON::ParserError
    nil
  end
end
