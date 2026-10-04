@HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})
interface SesameGroupClient {
    @PostRequest("/create")
    Object create(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/member-add")
    Object memberAdd(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/member-remove")
    Object memberRemove(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
