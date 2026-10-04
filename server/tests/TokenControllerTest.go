// @Test(SesameTestSetup, {"partition":"tests"})
type TokenControllerTest struct {
	behaviors *BehaviorContext
}

func (test *TokenControllerTest) TestJwksPublishesOnePublicSigningKey() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	keys, err := test.controller().PostJwks()

	Assert.IsTrue(err == nil)
	Assert.Equals(1, len(keys.Keys))
	Assert.Equals("EC", keys.Keys[0].KeyType)
	Assert.Equals("ES256", keys.Keys[0].Algorithm)
	Assert.Equals("sig", keys.Keys[0].Use)
	Assert.IsTrue(keys.Keys[0].KeyID != "")
	Assert.IsTrue(keys.Keys[0].X != "")
}

func (test *TokenControllerTest) controller() *TokenController {
	return &TokenController{engineService: &EngineService{engineSettingsService: &EngineSettingsService{}}}
}
