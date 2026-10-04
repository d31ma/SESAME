import 'dart:convert';
import 'dart:io';

@Helper
class SesameTransportHelper {
  static const String _snapshotVariable = 'YON_APPLICATION_JSON';
  static const String _secureScheme = 'https';
  static const String _plainScheme = 'http';
  static const List<String> _loopbackHosts = ['localhost', '127.0.0.1', '::1'];
  static const List<String> _rootPaths = ['', '/'];
  static const String _jsonType = 'application/json';
  static const String _bodyField = 'body';
  static const String _deadlineField = 'deadline';
  static const int _firstRedirectStatus = 300;
  static const int _firstOtherStatus = 400;
  static const String _originRule = 'sesame.origin must be an https origin without a path, or http on a loopback address';
  static const String _redirectRule = 'SESAME answered with a redirect, which this transport never follows';
  static const String _sizeRule = "SESAME's answer is larger than the response limit";

  Future<Object?> exchange(Object? request, BehaviorExecution execution) async {
    final fields = request as Map;
    final address = _address(_origin(), fields);
    final remaining = _remaining(fields[_deadlineField] as int);
    final client = _client(remaining);
    try {
      return await _sent(client, address, fields).timeout(remaining);
    } finally {
      client.close(force: true);
    }
  }

  Uri _origin() {
    final snapshot = jsonDecode(Platform.environment[_snapshotVariable] ?? '{}');
    final configured = (((snapshot as Map)['yon'] as Map?)?['sesame'] as Map?)?['origin'];
    final origin = configured is String ? Uri.tryParse(configured) : null;
    if (origin == null || !_usable(origin)) {
      throw StateError(_originRule);
    }
    return origin;
  }

  bool _usable(Uri origin) {
    final checks = [
      _allowedScheme(origin),
      origin.userInfo.isEmpty,
      _rootPaths.contains(origin.path),
      !origin.hasQuery,
      !origin.hasFragment,
    ];
    return !checks.contains(false);
  }

  bool _allowedScheme(Uri origin) {
    final secure = origin.scheme == _secureScheme && origin.host.isNotEmpty;
    final local = origin.scheme == _plainScheme && _loopbackHosts.contains(origin.host);
    return secure || local;
  }

  Uri _address(Uri origin, Map fields) {
    final query = (fields['query'] as Map).map((name, value) => MapEntry('$name', '$value'));
    return origin.replace(path: fields['path'] as String, queryParameters: query.isEmpty ? null : query);
  }

  Duration _remaining(int deadline) {
    return Duration(milliseconds: deadline - DateTime.now().millisecondsSinceEpoch);
  }

  HttpClient _client(Duration remaining) {
    return HttpClient()
      ..findProxy = HttpClient.findProxyFromEnvironment
      ..connectionTimeout = remaining;
  }

  Future<Object?> _sent(HttpClient client, Uri address, Map fields) async {
    final outgoing = await client.openUrl(fields['method'] as String, address);
    outgoing.followRedirects = false;
    outgoing.headers.set(HttpHeaders.acceptHeader, _jsonType);
    outgoing.headers.set(HttpHeaders.contentTypeHeader, _jsonType);
    (fields['headers'] as Map).forEach((name, value) => outgoing.headers.set('$name', '$value'));
    if (fields.containsKey(_bodyField)) {
      outgoing.add(utf8.encode(jsonEncode(fields[_bodyField])));
    }
    final response = await outgoing.close();
    _requireNoRedirect(response.statusCode);
    final content = await _read(response, fields['maxResponseBytes'] as int);
    return {'status': response.statusCode, _bodyField: _jsonOrNothing(content)};
  }

  void _requireNoRedirect(int status) {
    if (status >= _firstRedirectStatus && status < _firstOtherStatus) {
      throw StateError(_redirectRule);
    }
  }

  Future<String> _read(HttpClientResponse response, int limit) async {
    final content = BytesBuilder(copy: false);
    await for (final chunk in response) {
      content.add(chunk);
      _requireWithin(content.length, limit);
    }
    return utf8.decode(content.takeBytes(), allowMalformed: true);
  }

  void _requireWithin(int size, int limit) {
    if (size > limit) {
      throw StateError(_sizeRule);
    }
  }

  Object? _jsonOrNothing(String content) {
    try {
      return jsonDecode(content);
    } on FormatException {
      return null;
    }
  }
}
