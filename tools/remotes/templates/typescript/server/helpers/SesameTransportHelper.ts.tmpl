@Helper
export default class SesameTransportHelper {
  private static readonly SNAPSHOT_VARIABLE = 'YON_APPLICATION_JSON';
  private static readonly SECURE_SCHEME = 'https:';
  private static readonly PLAIN_SCHEME = 'http:';
  private static readonly LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];
  private static readonly ROOT_PATH = '/';
  private static readonly JSON_TYPE = 'application/json';
  private static readonly ORIGIN_RULE = 'sesame.origin must be an https origin without a path, or http on a loopback address';
  private static readonly SIZE_RULE = "SESAME's answer is larger than the response limit";

  async exchange(request: BehaviorHttpRequest, execution: BehaviorExecution): Promise<BehaviorJsonValue> {
    const response = await fetch(this.address(this.origin(), request), this.options(request));
    const content = await this.read(response, request.maxResponseBytes);
    return { status: response.status, body: this.jsonOrNothing(content) };
  }

  private origin(): URL {
    const snapshot = JSON.parse(process.env[SesameTransportHelper.SNAPSHOT_VARIABLE] ?? '{}');
    const origin = new URL(String(snapshot?.yon?.sesame?.origin ?? ''));
    this.requireUsable(origin);
    return origin;
  }

  private requireUsable(origin: URL): void {
    if (!this.usable(origin)) {
      throw new Error(SesameTransportHelper.ORIGIN_RULE);
    }
  }

  private usable(origin: URL): boolean {
    const checks = [
      this.allowedScheme(origin),
      origin.username === '',
      origin.password === '',
      origin.pathname === SesameTransportHelper.ROOT_PATH,
      origin.search === '',
      origin.hash === '',
    ];
    return !checks.includes(false);
  }

  private allowedScheme(origin: URL): boolean {
    const secure = origin.protocol === SesameTransportHelper.SECURE_SCHEME;
    const local = origin.protocol === SesameTransportHelper.PLAIN_SCHEME && SesameTransportHelper.LOOPBACK_HOSTS.includes(origin.hostname);
    return secure || local;
  }

  private address(origin: URL, request: BehaviorHttpRequest): string {
    const target = new URL(request.path, origin);
    for (const [name, value] of Object.entries(request.query)) {
      target.searchParams.set(name, String(value));
    }
    return target.toString();
  }

  private options(request: BehaviorHttpRequest): RequestInit {
    return {
      method: request.method,
      headers: { 'Content-Type': SesameTransportHelper.JSON_TYPE, Accept: SesameTransportHelper.JSON_TYPE, ...request.headers },
      body: this.payload(request),
      redirect: 'error',
      credentials: 'omit',
      signal: request.signal,
    };
  }

  private payload(request: BehaviorHttpRequest): string | undefined {
    if (request.body === undefined) {
      return undefined;
    }
    return JSON.stringify(request.body);
  }

  private async read(response: Response, limit: number): Promise<string> {
    const decoder = new TextDecoder();
    let text = '';
    let size = 0;
    for await (const chunk of response.body ?? []) {
      size += chunk.byteLength;
      this.requireWithin(size, limit);
      text += decoder.decode(chunk, { stream: true });
    }
    return text + decoder.decode();
  }

  private requireWithin(size: number, limit: number): void {
    if (size > limit) {
      throw new Error(SesameTransportHelper.SIZE_RULE);
    }
  }

  private jsonOrNothing(content: string): BehaviorJsonValue {
    try {
      return JSON.parse(content);
    } catch {
      return null;
    }
  }
}
