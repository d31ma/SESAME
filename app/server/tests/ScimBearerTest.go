import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type ScimBearerTest struct {
	behaviors *BehaviorContext
}

func (test *ScimBearerTest) TestResourceRouteWithoutABearerTokenAnswersUnauthorized() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()

	_, err := controller.PostUserList(setup.Anonymous(), ScimListRequest{})
	response := (&SesameErrorHandler{}).Answer(err)

	Assert.Equals(http.StatusUnauthorized, response.StatusCode)
	Assert.Equals("Bearer", response.Header.Get("WWW-Authenticate"))
	Assert.Equals("provisioning_denied", test.answeredCode(err))
}

func (test *ScimBearerTest) TestResourceRouteRefusesTheTokenUnderAnotherScheme() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := setup.ScimClient(controller, session, false).Token
	request := setup.Anonymous()
	request.Header.Set("Authorization", "Basic "+token)

	_, err := controller.PostUserList(request, ScimListRequest{})

	Assert.Equals(http.StatusUnauthorized, setup.Status(err))
}

func (test *ScimBearerTest) TestBearerSchemeIsCaseInsensitive() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := setup.ScimClient(controller, session, false).Token
	request := setup.Anonymous()
	request.Header.Set("Authorization", "bearer "+token)

	_, err := controller.PostUserList(request, ScimListRequest{})

	Assert.IsTrue(err == nil)
}

func (test *ScimBearerTest) TestRefusedTokenIsNeverEchoed() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()
	guessed := "guessed-provisioning-token-value"

	_, err := controller.PostUserCreate(setup.Bearer(guessed), ScimResourceCreateRequest{Body: setup.ScimUserBody("ada@acme.test")})
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)

	Assert.IsTrue(readErr == nil)
	Assert.IsTrue(!strings.Contains(string(body), guessed))
	Assert.IsTrue(!strings.Contains(err.Error(), guessed))
}

func (test *ScimBearerTest) TestTokenSeesOnlyItsOwnTenantsUsers() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	token := setup.ScimClient(controller, session, false).Token
	otherToken := setup.ScimClient(controller, other, false).Token
	created := setup.ScimUserCreated(controller, token, "ada@acme.test")

	_, err := controller.PostUserGet(setup.Bearer(otherToken), ScimResourceRequest{ResourceID: created.ID})
	list, listErr := controller.PostUserList(setup.Bearer(otherToken), ScimListRequest{})

	Assert.Equals(http.StatusNotFound, setup.Status(err))
	Assert.IsTrue(listErr == nil)
	Assert.Equals(0, list.TotalResults)
}

func (test *ScimBearerTest) TestGroupRoutesNeedTheGroupGrant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := setup.ScimClient(controller, session, false).Token

	_, err := controller.PostGroupCreate(setup.Bearer(token), ScimResourceCreateRequest{Body: setup.ScimGroupBody("engineering")})

	Assert.Equals(http.StatusForbidden, setup.Status(err))
	Assert.Equals("provisioning_forbidden", test.answeredCode(err))
}

func (test *ScimBearerTest) controller() *ScimController {
	return SesameTestSetup{}.Scim(SesameTestSetup{}.Engine(), 0)
}

func (test *ScimBearerTest) answeredCode(err error) string {
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	SesameTestSetup{}.Check(readErr)
	problem := Problem{}
	SesameTestSetup{}.Check(json.Unmarshal(body, &problem))
	return problem.Code
}
