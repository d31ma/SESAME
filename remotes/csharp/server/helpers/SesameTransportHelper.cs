using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

[Helper]
sealed class SesameTransportHelper : BehaviorHTTPAdapter {
    private const string SnapshotVariable = "YON_APPLICATION_JSON";
    private const string SecureScheme = "https";
    private const string PlainScheme = "http";
    private const string RootPath = "/";
    private const string JsonType = "application/json";
    private const string AcceptHeader = "Accept";
    private const string QuoteMark = "\"";
    private const string NothingJson = "null";
    private const string BodyField = "body";
    private const string StatusField = "status";
    private const int FirstRedirectStatus = 300;
    private const int FirstOtherStatus = 400;
    private const int ReadChunkBytes = 81920;
    private const string OriginRule = "sesame.origin must be an https origin without a path, or http on a loopback address";
    private const string RedirectRule = "SESAME answered with a redirect, which this transport never follows";
    private const string SizeRule = "SESAME's answer is larger than the response limit";
    private static readonly string[] LoopbackHosts = { "localhost", "127.0.0.1", "[::1]" };

    public async Task<BehaviorJSON> exchange(BehaviorJSON request, BehaviorExecution execution) {
        var address = Address(Origin(), request);
        using var deadline = Deadline(execution);
        using var client = Client();
        using var outgoing = Outgoing(request, address);
        using var response = await client.SendAsync(outgoing, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        RequireNoRedirect((int)response.StatusCode);
        var content = await Read(response, request.Get("maxResponseBytes").Integer, deadline.Token);
        return Answer((int)response.StatusCode, content);
    }

    private static Uri Origin() {
        var snapshot = BehaviorJSON.Parse(Environment.GetEnvironmentVariable(SnapshotVariable) ?? NothingJson);
        var configured = snapshot.Get("yon").Get("sesame").Get("origin");
        var text = configured.ToString().StartsWith(QuoteMark) ? configured.Text : string.Empty;
        Uri.TryCreate(text, UriKind.Absolute, out var origin);
        RequireUsable(origin);
        return origin;
    }

    private static void RequireUsable(Uri origin) {
        if (origin == null || !Usable(origin)) {
            throw new InvalidOperationException(OriginRule);
        }
    }

    private static bool Usable(Uri origin) {
        bool[] checks = {
            AllowedScheme(origin),
            origin.UserInfo.Length == 0,
            origin.AbsolutePath == RootPath,
            origin.Query.Length == 0,
            origin.Fragment.Length == 0,
        };
        return Array.IndexOf(checks, false) < 0;
    }

    private static bool AllowedScheme(Uri origin) {
        var secure = origin.Scheme == SecureScheme;
        var local = origin.Scheme == PlainScheme && Array.IndexOf(LoopbackHosts, origin.Host) >= 0;
        return secure || local;
    }

    private static Uri Address(Uri origin, BehaviorJSON request) {
        var address = new UriBuilder(origin) { Path = request.Get("path").Text, Query = Query(request.Get("query")) };
        return address.Uri;
    }

    private static string Query(BehaviorJSON values) {
        var pairs = new List<string>();
        foreach (var pair in values.Members) {
            pairs.Add(Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(Plain(pair.Value)));
        }
        return string.Join("&", pairs);
    }

    private static string Plain(BehaviorJSON value) {
        var text = value.ToString();
        return text.StartsWith(QuoteMark) ? value.Text : text;
    }

    private static CancellationTokenSource Deadline(BehaviorExecution execution) {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(execution.Signal.Token);
        deadline.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(0, execution.Deadline - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())));
        return deadline;
    }

    private static HttpClient Client() {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        return new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private static HttpRequestMessage Outgoing(BehaviorJSON request, Uri address) {
        var outgoing = new HttpRequestMessage(new HttpMethod(request.Get("method").Text), address);
        outgoing.Headers.TryAddWithoutValidation(AcceptHeader, JsonType);
        foreach (var pair in request.Get("headers").Members) {
            outgoing.Headers.TryAddWithoutValidation(pair.Key, pair.Value.Text);
        }
        outgoing.Content = Payload(request);
        return outgoing;
    }

    private static HttpContent Payload(BehaviorJSON request) {
        if (!request.Has(BodyField)) {
            return null;
        }
        return new StringContent(request.Get(BodyField).ToString(), Encoding.UTF8, JsonType);
    }

    private static void RequireNoRedirect(int status) {
        if (status >= FirstRedirectStatus && status < FirstOtherStatus) {
            throw new InvalidOperationException(RedirectRule);
        }
    }

    private static async Task<byte[]> Read(HttpResponseMessage response, long limit, CancellationToken token) {
        using var stream = await response.Content.ReadAsStreamAsync(token);
        using var content = new MemoryStream();
        var chunk = new byte[ReadChunkBytes];
        var count = await stream.ReadAsync(chunk, token);
        while (count > 0) {
            content.Write(chunk, 0, count);
            RequireWithin(content.Length, limit);
            count = await stream.ReadAsync(chunk, token);
        }
        return content.ToArray();
    }

    private static void RequireWithin(long size, long limit) {
        if (size > limit) {
            throw new InvalidOperationException(SizeRule);
        }
    }

    private static BehaviorJSON Answer(int status, byte[] content) {
        return BehaviorJSON.Object(new Dictionary<string, BehaviorJSON> {
            [StatusField] = BehaviorJSON.From(status),
            [BodyField] = JsonOrNothing(Encoding.UTF8.GetString(content)),
        });
    }

    private static BehaviorJSON JsonOrNothing(string content) {
        try {
            return BehaviorJSON.Parse(content);
        } catch (BehaviorError) {
            return BehaviorJSON.Parse(NothingJson);
        }
    }
}
