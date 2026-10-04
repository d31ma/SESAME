[HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})]
interface SesameGroupClient {
    [PostRequest("/create")]
    System.Threading.Tasks.Task<BehaviorJSON> Create([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/member-add")]
    System.Threading.Tasks.Task<BehaviorJSON> MemberAdd([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/member-remove")]
    System.Threading.Tasks.Task<BehaviorJSON> MemberRemove([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
