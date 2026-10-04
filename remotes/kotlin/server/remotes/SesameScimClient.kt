@HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})
interface SesameScimClient {
    @PostRequest("/client-disable")
    fun clientDisable(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/client-register")
    fun clientRegister(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/client-rotate-token")
    fun clientRotateToken(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/group-create")
    fun groupCreate(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/group-deprovision")
    fun groupDeprovision(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/group-get")
    fun groupGet(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/group-list")
    fun groupList(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/group-patch")
    fun groupPatch(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/user-create")
    fun userCreate(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/user-deprovision")
    fun userDeprovision(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/user-get")
    fun userGet(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/user-list")
    fun userList(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?

    @PostRequest("/user-patch")
    fun userPatch(@RequestHeader("Authorization") authorization: String, @RequestBody body: Any?): Any?
}
